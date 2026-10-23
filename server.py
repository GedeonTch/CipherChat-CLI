"""Serveur FastAPI/WebSocket de CipherChat, sans persistance des messages."""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from collections import deque
from contextlib import suppress
from dataclasses import dataclass, field

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from protocol import (
    KDF_NAME,
    MAX_PACKET_BYTES,
    PBKDF2_ITERATIONS,
    PROTOCOL_VERSION,
    ROOM_NAME,
    SALT_MIN_SIZE,
    ProtocolError,
    b64decode,
    b64encode,
    canonical_username,
    decode_packet,
    encode_packet,
    timestamp_ms,
    validate_join_packet,
    validate_leave_packet,
    validate_message_packet,
)

MESSAGES_PER_SECOND = 5
RATE_WINDOW_SECONDS = 1.0
RECENT_MESSAGE_IDS = 256
JOIN_TIMEOUT_SECONDS = 15
WS_PING_INTERVAL_SECONDS = 20
WS_PING_TIMEOUT_SECONDS = 20
DEFAULT_MAX_CONNECTIONS = 100
# Sel public uniquement destiné au développement local. Il n'est jamais régénéré.
DEFAULT_DEVELOPMENT_SALT = b"cipherchat-dev!!"


@dataclass(frozen=True, slots=True)
class ServerConfig:
    salt: bytes
    max_connections: int = DEFAULT_MAX_CONNECTIONS
    port: int = 8000
    environment: str = "development"

    def __post_init__(self) -> None:
        if not isinstance(self.salt, bytes) or len(self.salt) < SALT_MIN_SIZE:
            raise ValueError("Le sel public doit contenir au moins 16 octets.")
        if type(self.max_connections) is not int or self.max_connections < 1:
            raise ValueError("CIPHERCHAT_MAX_CONNECTIONS doit être un entier positif.")
        if type(self.port) is not int or not 1 <= self.port <= 65_535:
            raise ValueError("PORT doit être compris entre 1 et 65535.")
        if self.environment not in {"development", "production"}:
            raise ValueError("CIPHERCHAT_ENV doit valoir 'development' ou 'production'.")


def _positive_int_from_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} doit être un entier.") from exc
    if value < 1:
        raise RuntimeError(f"{name} doit être un entier positif.")
    return value


def load_config() -> ServerConfig:
    """Charge la configuration sans jamais générer de sel de remplacement."""

    environment = os.getenv("CIPHERCHAT_ENV", "development").strip().lower()
    # Render renseigne normalement RENDER=true. La commande de déploiement
    # documentée impose aussi CIPHERCHAT_ENV=production explicitement.
    if os.getenv("RENDER", "").strip().lower() == "true":
        environment = "production"
    if environment not in {"development", "production"}:
        raise RuntimeError("CIPHERCHAT_ENV doit valoir 'development' ou 'production'.")

    configured_salt = os.getenv("CIPHERCHAT_SALT_B64")
    if environment == "production" and not configured_salt:
        raise RuntimeError(
            "CIPHERCHAT_SALT_B64 est obligatoire en production/Render : "
            "aucun sel de développement ne sera utilisé silencieusement."
        )

    if configured_salt is None:
        salt = DEFAULT_DEVELOPMENT_SALT
    else:
        try:
            salt = b64decode(configured_salt, "CIPHERCHAT_SALT_B64")
        except ProtocolError as exc:
            raise RuntimeError("CIPHERCHAT_SALT_B64 doit être du Base64 strict.") from exc
        if len(salt) < SALT_MIN_SIZE:
            raise RuntimeError("CIPHERCHAT_SALT_B64 doit décoder au moins 16 octets.")

    return ServerConfig(
        salt=salt,
        max_connections=_positive_int_from_env(
            "CIPHERCHAT_MAX_CONNECTIONS", DEFAULT_MAX_CONNECTIONS
        ),
        port=_positive_int_from_env("PORT", 8000),
        environment=environment,
    )


@dataclass(slots=True)
class Member:
    websocket: WebSocket
    username: str
    session_id: str
    last_sequence: int = 0
    rate_timestamps: deque[float] = field(default_factory=deque)
    seen_message_ids: set[str] = field(default_factory=set)
    seen_message_order: deque[str] = field(default_factory=deque)

    def allow_message(self) -> bool:
        """Fenêtre glissante : au plus cinq envois, même valides ou non, par seconde."""

        now = time.monotonic()
        while (
            self.rate_timestamps
            and now - self.rate_timestamps[0] >= RATE_WINDOW_SECONDS
        ):
            self.rate_timestamps.popleft()
        if len(self.rate_timestamps) >= MESSAGES_PER_SECOND:
            return False
        self.rate_timestamps.append(now)
        return True

    def has_seen(self, message_id: str) -> bool:
        return message_id in self.seen_message_ids

    def remember(self, message_id: str, sequence: int) -> None:
        self.last_sequence = sequence
        self.seen_message_ids.add(message_id)
        self.seen_message_order.append(message_id)
        if len(self.seen_message_order) > RECENT_MESSAGE_IDS:
            oldest = self.seen_message_order.popleft()
            self.seen_message_ids.discard(oldest)


class ConnectionManager:
    """État volatil du salon, prévu pour un seul processus Uvicorn."""

    def __init__(self, max_connections: int) -> None:
        self.max_connections = max_connections
        self._connections: set[WebSocket] = set()
        self._members: dict[WebSocket, Member] = {}
        self._usernames: dict[str, WebSocket] = {}
        self._lock = asyncio.Lock()

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    @property
    def member_count(self) -> int:
        return len(self._members)

    async def reserve(self, websocket: WebSocket) -> bool:
        """Compte aussi les connexions pas encore identifiées dans la limite."""

        async with self._lock:
            if len(self._connections) >= self.max_connections:
                return False
            self._connections.add(websocket)
            return True

    async def register(
        self, websocket: WebSocket, username: str, session_id: str
    ) -> Member | None:
        """Enregistre atomiquement un pseudo sans jamais écraser un membre."""

        async with self._lock:
            canonical = canonical_username(username)
            if canonical in self._usernames or websocket not in self._connections:
                return None
            member = Member(websocket=websocket, username=username, session_id=session_id)
            self._members[websocket] = member
            self._usernames[canonical] = websocket
            return member

    async def remove(self, websocket: WebSocket) -> Member | None:
        async with self._lock:
            self._connections.discard(websocket)
            member = self._members.pop(websocket, None)
            if member is not None:
                canonical = canonical_username(member.username)
                # Ne supprime jamais une identité qui aurait été réattribuée.
                if self._usernames.get(canonical) is websocket:
                    self._usernames.pop(canonical, None)
            return member

    async def broadcast(
        self, packet: dict, *, exclude: WebSocket | None = None
    ) -> None:
        """Diffuse un paquet déjà validé, sans jamais le déchiffrer."""

        async with self._lock:
            targets = [
                member.websocket
                for member in self._members.values()
                if member.websocket is not exclude
            ]
        if not targets:
            return

        raw = encode_packet(packet)
        results = await asyncio.gather(
            *(websocket.send_text(raw) for websocket in targets),
            return_exceptions=True,
        )
        # Leur boucle de réception et/ou le heartbeat effectuera le nettoyage.
        # Fermer ici évite de conserver volontairement une socket manifestement morte.
        for websocket, result in zip(targets, results, strict=True):
            if isinstance(result, Exception):
                with suppress(Exception):
                    await websocket.close(code=1011)


def system_packet(event: str, username: str) -> dict:
    return {
        "type": "system",
        "version": PROTOCOL_VERSION,
        "room": ROOM_NAME,
        "event": event,
        "username": username,
        "timestamp": timestamp_ms(),
    }


async def send_error(websocket: WebSocket, code: str, message: str) -> None:
    await websocket.send_text(
        encode_packet({"type": "error", "code": code, "message": message})
    )


async def reject_and_close(
    websocket: WebSocket, code: str, message: str, close_code: int = 1008
) -> None:
    try:
        await send_error(websocket, code, message)
    finally:
        with suppress(Exception):
            await websocket.close(code=close_code)


async def receive_text(websocket: WebSocket) -> str:
    """Accepte uniquement des trames texte et conserve la détection de départ."""

    message = await websocket.receive()
    if message["type"] == "websocket.disconnect":
        raise WebSocketDisconnect(code=message.get("code", 1000))
    if message["type"] != "websocket.receive" or message.get("text") is None:
        raise ProtocolError("Les trames WebSocket binaires ne sont pas acceptées.")
    return message["text"]


async def handle_user_message(
    websocket: WebSocket, member: Member, packet: dict, manager: ConnectionManager
) -> None:
    if not member.allow_message():
        await send_error(
            websocket,
            "rate_limited",
            "Limite de 5 messages par seconde atteinte ; le paquet n'a pas été relayé.",
        )
        return

    try:
        validate_message_packet(packet)
    except ProtocolError as exc:
        await send_error(websocket, exc.code, str(exc))
        return

    if packet["username"] != member.username or packet["session_id"] != member.session_id:
        await send_error(
            websocket,
            "identity_mismatch",
            "Le pseudo ou l'identifiant de session ne correspond pas à cette connexion.",
        )
        return

    sequence = packet["sequence"]
    if sequence <= member.last_sequence:
        await send_error(
            websocket,
            "invalid_sequence",
            "Le numéro de séquence doit être strictement croissant.",
        )
        return
    if member.has_seen(packet["message_id"]):
        await send_error(
            websocket,
            "duplicate_message",
            "Cet identifiant de message a déjà été utilisé récemment.",
        )
        return

    member.remember(packet["message_id"], sequence)
    await manager.broadcast(packet, exclude=websocket)


def create_app(config: ServerConfig | None = None) -> FastAPI:
    config = config or load_config()
    app = FastAPI(title="CipherChat", version="1.0.0")
    manager = ConnectionManager(config.max_connections)
    app.state.config = config
    app.state.manager = manager

    @app.get("/health")
    async def health() -> dict[str, str | int]:
        return {
            "status": "ok",
            "room": ROOM_NAME,
            "protocol_version": PROTOCOL_VERSION,
        }

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        await websocket.accept()
        if not await manager.reserve(websocket):
            await reject_and_close(
                websocket,
                "connection_limit",
                "Le salon a atteint sa limite de connexions simultanées.",
                close_code=1013,
            )
            return

        try:
            try:
                raw = await asyncio.wait_for(
                    receive_text(websocket), timeout=JOIN_TIMEOUT_SECONDS
                )
                join_packet = decode_packet(raw)
                username, session_id = validate_join_packet(join_packet)
            except asyncio.TimeoutError:
                await reject_and_close(
                    websocket,
                    "join_timeout",
                    "Délai dépassé pour rejoindre le salon.",
                )
                return
            except ProtocolError as exc:
                await reject_and_close(websocket, exc.code, str(exc))
                return

            member = await manager.register(websocket, username, session_id)
            if member is None:
                await reject_and_close(
                    websocket,
                    "duplicate_username",
                    "Ce pseudo est déjà utilisé dans le salon.",
                )
                return

            await websocket.send_text(
                encode_packet(
                    {
                        "type": "welcome",
                        "version": PROTOCOL_VERSION,
                        "room": ROOM_NAME,
                        "username": username,
                        "session_id": session_id,
                        "salt": b64encode(config.salt),
                        "kdf": KDF_NAME,
                        "iterations": PBKDF2_ITERATIONS,
                        "timestamp": timestamp_ms(),
                    }
                )
            )
            await manager.broadcast(
                system_packet("joined", username), exclude=websocket
            )

            while True:
                try:
                    raw = await receive_text(websocket)
                    packet = decode_packet(raw)
                except ProtocolError as exc:
                    await send_error(websocket, exc.code, str(exc))
                    if exc.code == "packet_too_large":
                        await websocket.close(code=1009)
                        return
                    continue

                packet_type = packet.get("type")
                if packet_type == "leave":
                    try:
                        validate_leave_packet(packet)
                    except ProtocolError as exc:
                        await send_error(websocket, exc.code, str(exc))
                        continue
                    await websocket.close(code=1000)
                    return
                if packet_type == "message":
                    await handle_user_message(websocket, member, packet, manager)
                else:
                    await send_error(
                        websocket,
                        "invalid_packet",
                        "Type de paquet non autorisé après la connexion.",
                    )

        except WebSocketDisconnect:
            pass
        finally:
            departed = await manager.remove(websocket)
            if departed is not None:
                await manager.broadcast(
                    system_packet("left", departed.username), exclude=websocket
                )

    return app


app = create_app()


if __name__ == "__main__":
    config = load_config()
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=config.port,
        ws="auto",
        ws_max_size=MAX_PACKET_BYTES,
        ws_ping_interval=WS_PING_INTERVAL_SECONDS,
        ws_ping_timeout=WS_PING_TIMEOUT_SECONDS,
        # L'état du salon est local au processus : ne pas ajouter de workers.
    )
