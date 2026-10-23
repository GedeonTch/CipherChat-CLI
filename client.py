"""Client exclusivement CLI de CipherChat."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum, auto
from urllib.parse import urlsplit

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, WebSocketException

from encryption import DecryptionError, decrypt_message, derive_key, encrypt_message
from protocol import (
    KDF_NAME,
    MAX_PACKET_BYTES,
    PBKDF2_ITERATIONS,
    PROTOCOL_VERSION,
    ROOM_NAME,
    SALT_MIN_SIZE,
    ProtocolError,
    b64decode,
    decode_packet,
    encode_packet,
    timestamp_ms,
    validate_username,
)

OPEN_TIMEOUT_SECONDS = 10
CLOSE_TIMEOUT_SECONDS = 5
PING_INTERVAL_SECONDS = 20
PING_TIMEOUT_SECONDS = 20

WELCOME_KEYS = {
    "type",
    "version",
    "room",
    "username",
    "session_id",
    "salt",
    "kdf",
    "iterations",
    "timestamp",
}
SYSTEM_KEYS = {"type", "version", "room", "event", "username", "timestamp"}


class ClientError(Exception):
    """Erreur de connexion ou de négociation affichable sans secret."""


class Command(Enum):
    MESSAGE = auto()
    HELP = auto()
    QUIT = auto()
    UNKNOWN = auto()


def parse_command(line: str) -> Command:
    stripped = line.strip()
    if stripped == "/help":
        return Command.HELP
    if stripped == "/quit":
        return Command.QUIT
    if stripped.startswith("/"):
        return Command.UNKNOWN
    return Command.MESSAGE


def print_help() -> None:
    print("Commandes :")
    print("  /quit   Quitter le salon")
    print("  /help   Afficher les commandes", flush=True)


def print_banner(url: str, username: str) -> None:
    print("\n==================================================")
    print("                 CIPHERCHAT")
    print("          Messagerie sécurisée en temps réel")
    print("==================================================\n")
    print("Serveur : Connecté")
    print("Salon   : #general")
    print(f"Pseudo  : {username}")
    print(f"URL     : {url}\n")
    print_help()
    print("--------------------------------------------------")
    print("Écrivez votre message puis appuyez sur Entrée.", flush=True)


def validate_server_url(url: str) -> str:
    """Accepte WS pour le local et WSS avec vérification TLS pour le public."""

    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise ClientError("L'URL du serveur est invalide.") from exc
    if parsed.scheme not in {"ws", "wss"} or not parsed.hostname:
        raise ClientError("L'URL doit commencer par ws:// ou wss:// et contenir un hôte.")
    if parsed.username is not None or parsed.password is not None:
        raise ClientError("Les identifiants dans l'URL ne sont pas acceptés.")
    return url


def validate_welcome(
    packet: dict, expected_username: str, expected_session_id: str
) -> bytes:
    """Valide la négociation et refuse notamment une dégradation du KDF."""

    if packet.get("type") == "error":
        message = packet.get("message")
        code = packet.get("code")
        if isinstance(message, str) and isinstance(code, str):
            raise ClientError(f"Le serveur a refusé la connexion ({code}) : {message}")
        raise ClientError("Le serveur a refusé la connexion.")
    if set(packet) != WELCOME_KEYS or packet.get("type") != "welcome":
        raise ClientError("Réponse de bienvenue du serveur invalide.")
    if packet.get("version") != PROTOCOL_VERSION or packet.get("room") != ROOM_NAME:
        raise ClientError("Le serveur utilise un protocole ou un salon incompatible.")
    if packet.get("username") != expected_username:
        raise ClientError("Le pseudo confirmé par le serveur ne correspond pas.")
    if packet.get("session_id") != expected_session_id:
        raise ClientError("L'identifiant de session confirmé est invalide.")
    if packet.get("kdf") != KDF_NAME or packet.get("iterations") != PBKDF2_ITERATIONS:
        raise ClientError("Les paramètres de dérivation du serveur sont incompatibles.")
    if type(packet.get("timestamp")) is not int:
        raise ClientError("L'horodatage de bienvenue est invalide.")
    try:
        salt = b64decode(packet.get("salt"), "salt")
    except ProtocolError as exc:
        raise ClientError(str(exc)) from exc
    if len(salt) < SALT_MIN_SIZE:
        raise ClientError("Le sel public transmis par le serveur est trop court.")
    return salt


def format_timestamp(value: int) -> str:
    try:
        return (
            datetime.fromtimestamp(value / 1_000, tz=timezone.utc)
            .astimezone()
            .strftime("%H:%M:%S")
        )
    except (ValueError, OverflowError, OSError):
        return "--:--:--"


def safe_display(text: str) -> str:
    """Empêche les contrôles de terminal et conserve un message sur une ligne."""

    result: list[str] = []
    for character in text:
        if character == "\n":
            result.append("\\n")
        elif character == "\r":
            result.append("\\r")
        elif character.isprintable():
            result.append(character)
        else:
            result.append("?")
    return "".join(result)


def format_incoming_message(packet: dict, key: bytes) -> str:
    plaintext = decrypt_message(packet, key)
    time_text = format_timestamp(packet["timestamp"])
    username = safe_display(packet["username"])
    return f"[{time_text}] {username} : {safe_display(plaintext)}"


def format_system_message(packet: dict) -> str:
    if set(packet) != SYSTEM_KEYS or packet.get("type") != "system":
        raise ProtocolError("Événement système invalide.")
    if packet.get("version") != PROTOCOL_VERSION or packet.get("room") != ROOM_NAME:
        raise ProtocolError("Événement système incompatible.")
    if packet.get("event") not in {"joined", "left"}:
        raise ProtocolError("Événement de présence inconnu.")
    username = validate_username(packet.get("username"))
    if type(packet.get("timestamp")) is not int:
        raise ProtocolError("Horodatage de présence invalide.")
    action = "a rejoint le salon" if packet["event"] == "joined" else "a quitté le salon"
    return f"--- {username} {action} ---"


async def close_cleanly(websocket) -> None:
    """Envoie /quit au protocole puis ferme la socket avec le code normal."""

    try:
        await websocket.send(encode_packet({"type": "leave"}))
    except ConnectionClosed:
        pass
    try:
        await websocket.close(code=1000)
    except ConnectionClosed:
        pass


async def handle_command(line: str, websocket) -> Command:
    """Exécute une commande locale ; utilisé aussi par le test de /quit."""

    command = parse_command(line)
    if command is Command.HELP:
        print_help()
    elif command is Command.QUIT:
        await close_cleanly(websocket)
    elif command is Command.UNKNOWN:
        print("Commande inconnue. Utilisez /help.", flush=True)
    return command


class AsyncStdin:
    """Lecture stdin dans un thread daemon pour ne pas bloquer l'arrêt async."""

    def __init__(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._queue: asyncio.Queue[str | None] = asyncio.Queue()
        self._active = True
        self._thread = threading.Thread(
            target=self._read_lines, name="cipherchat-stdin", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def _publish(self, value: str | None) -> None:
        if not self._active:
            return
        try:
            self._loop.call_soon_threadsafe(self._queue.put_nowait, value)
        except RuntimeError:
            # La boucle est déjà fermée pendant l'arrêt du processus.
            pass

    def _read_lines(self) -> None:
        while self._active:
            try:
                line = input()
            except EOFError:
                self._publish(None)
                return
            except (OSError, ValueError):
                self._publish(None)
                return
            self._publish(line)

    async def readline(self) -> str | None:
        return await self._queue.get()

    def close(self) -> None:
        # Un input() bloquant ne peut pas être annulé portablement ; le thread
        # daemon ne retardera toutefois pas la terminaison du programme.
        self._active = False


async def receive_messages(websocket, key: bytes, stopping: asyncio.Event) -> None:
    try:
        async for raw in websocket:
            try:
                packet = decode_packet(raw)
                packet_type = packet.get("type")
                if packet_type == "message":
                    try:
                        print(format_incoming_message(packet, key), flush=True)
                    except (DecryptionError, ProtocolError, ValueError) as exc:
                        print(f"[message illisible] {exc}", flush=True)
                elif packet_type == "system":
                    try:
                        print(format_system_message(packet), flush=True)
                    except ProtocolError as exc:
                        print(f"[événement ignoré] {exc}", flush=True)
                elif packet_type == "error":
                    message = packet.get("message", "Erreur serveur inconnue.")
                    print(f"[serveur] {safe_display(str(message))}", flush=True)
                else:
                    print("[protocole] Paquet inattendu ignoré.", flush=True)
            except ProtocolError as exc:
                print(f"[protocole] {exc}", flush=True)
    except ConnectionClosed as exc:
        if not stopping.is_set():
            print(
                f"[connexion] Connexion fermée (code {exc.code}). "
                "Aucune reconnexion automatique n'est tentée.",
                flush=True,
            )


async def join_server(websocket, username: str, session_id: str) -> bytes:
    await websocket.send(
        encode_packet(
            {
                "type": "join",
                "version": PROTOCOL_VERSION,
                "room": ROOM_NAME,
                "username": username,
                "session_id": session_id,
            }
        )
    )
    raw = await asyncio.wait_for(websocket.recv(), timeout=OPEN_TIMEOUT_SECONDS)
    try:
        packet = decode_packet(raw)
    except ProtocolError as exc:
        raise ClientError(str(exc)) from exc
    return validate_welcome(packet, username, session_id)


async def interactive_chat(websocket, key: bytes, username: str, session_id: str) -> None:
    stopping = asyncio.Event()
    stdin = AsyncStdin()
    stdin.start()
    receiver = asyncio.create_task(receive_messages(websocket, key, stopping))
    sequence = 0

    try:
        while not receiver.done():
            line_task = asyncio.create_task(stdin.readline())
            done, _ = await asyncio.wait(
                {line_task, receiver}, return_when=asyncio.FIRST_COMPLETED
            )
            if receiver in done:
                line_task.cancel()
                await asyncio.gather(line_task, return_exceptions=True)
                break

            line = line_task.result()
            if line is None:
                stopping.set()
                await close_cleanly(websocket)
                return

            command = parse_command(line)
            if command is not Command.MESSAGE:
                if command is Command.QUIT:
                    stopping.set()
                await handle_command(line, websocket)
                if command is Command.QUIT:
                    return
                continue
            if not line.strip():
                continue

            sequence += 1
            try:
                packet = encrypt_message(
                    line,
                    key,
                    {
                        "version": PROTOCOL_VERSION,
                        "room": ROOM_NAME,
                        "username": username,
                        "message_id": str(uuid.uuid4()),
                        "session_id": session_id,
                        "sequence": sequence,
                        "timestamp": timestamp_ms(),
                    },
                )
                await websocket.send(encode_packet(packet))
            except (ValueError, ProtocolError) as exc:
                print(f"[envoi impossible] {exc}", flush=True)
    finally:
        stopping.set()
        stdin.close()
        if not receiver.done():
            try:
                await websocket.close(code=1000)
            except ConnectionClosed:
                pass
        await asyncio.gather(receiver, return_exceptions=True)


async def run_client(url: str, username: str, passphrase: str) -> None:
    validate_server_url(url)
    session_id = str(uuid.uuid4())
    async with connect(
        url,
        open_timeout=OPEN_TIMEOUT_SECONDS,
        close_timeout=CLOSE_TIMEOUT_SECONDS,
        ping_interval=PING_INTERVAL_SECONDS,
        ping_timeout=PING_TIMEOUT_SECONDS,
        max_size=MAX_PACKET_BYTES,
    ) as websocket:
        salt = await join_server(websocket, username, session_id)
        # La dérivation n'a lieu qu'après validation des paramètres annoncés.
        key = derive_key(passphrase, salt, PBKDF2_ITERATIONS)
        print_banner(url, username)
        await interactive_chat(websocket, key, username, session_id)


def prompt_username() -> str:
    while True:
        username = input("Pseudo : ").strip()
        try:
            return validate_username(username)
        except ProtocolError as exc:
            print(f"Pseudo invalide : {exc}")


def prompt_passphrase() -> str:
    while True:
        passphrase = getpass.getpass("Phrase secrète partagée (saisie masquée) : ")
        if passphrase:
            return passphrase
        print("La phrase secrète ne peut pas être vide.")


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Client CLI de messagerie chiffrée CipherChat."
    )
    parser.add_argument(
        "--url",
        default="ws://127.0.0.1:8000/ws",
        help="URL WebSocket du serveur (défaut : ws://127.0.0.1:8000/ws).",
    )
    return parser


def main() -> int:
    args = build_argument_parser().parse_args()
    print("==================================================")
    print("                 CIPHERCHAT")
    print("          Messagerie sécurisée en temps réel")
    print("==================================================")
    try:
        validate_server_url(args.url)
        username = prompt_username()
        passphrase = prompt_passphrase()
        asyncio.run(run_client(args.url, username, passphrase))
        print("Connexion terminée. Au revoir !")
        return 0
    except KeyboardInterrupt:
        print("\nInterruption : connexion terminée. Au revoir !")
        return 0
    except (ClientError, OSError, ValueError, WebSocketException) as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
