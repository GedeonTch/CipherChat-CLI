"""Protocole JSON partagé par le client et le serveur CipherChat."""

from __future__ import annotations

import base64
import binascii
import json
import re
import time
import uuid
from collections.abc import Mapping
from typing import Any

PROTOCOL_VERSION = 1
ROOM_NAME = "general"
KDF_NAME = "PBKDF2-HMAC-SHA256"
PBKDF2_ITERATIONS = 600_000
KEY_SIZE = 32
SALT_MIN_SIZE = 16
NONCE_SIZE = 12
GCM_TAG_SIZE = 16

MAX_USERNAME_CHARS = 24
MAX_PLAINTEXT_CHARS = 2_000
# Limite serveur conservative : AES-GCM produit autant d'octets de ciphertext
# que le texte clair encodé en UTF-8, auxquels s'ajoute le tag.
MAX_PLAINTEXT_BYTES = 2_000
MAX_CIPHERTEXT_BYTES = MAX_PLAINTEXT_BYTES + GCM_TAG_SIZE
MAX_PACKET_BYTES = 8 * 1024
MAX_SEQUENCE = 2**63 - 1
MAX_TIMESTAMP_MS = 2**63 - 1

AAD_FIELDS = (
    "version",
    "room",
    "username",
    "message_id",
    "session_id",
    "sequence",
    "timestamp",
)
MESSAGE_KEYS = frozenset({"type", *AAD_FIELDS, "nonce", "ciphertext"})
JOIN_KEYS = frozenset({"type", "version", "room", "username", "session_id"})
LEAVE_KEYS = frozenset({"type"})
_USERNAME_ALLOWED = re.compile(r"[\w.\-]+", re.UNICODE)


class ProtocolError(ValueError):
    """Erreur de validation d'un paquet, sans donnée sensible dans le message."""

    def __init__(self, message: str, code: str = "invalid_packet") -> None:
        super().__init__(message)
        self.code = code


def timestamp_ms() -> int:
    """Horodatage Unix en millisecondes, inclus dans les métadonnées et l'AAD."""

    return time.time_ns() // 1_000_000


def _reject_json_constant(value: str) -> None:
    raise ProtocolError(f"Valeur JSON non autorisée : {value}.")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("Le paquet JSON contient une clé dupliquée.")
        result[key] = value
    return result


def decode_packet(raw: str) -> dict[str, Any]:
    """Décode un paquet JSON strict et impose la limite de 8 KiB."""

    if not isinstance(raw, str):
        raise ProtocolError("Le paquet doit être une trame WebSocket texte.")
    if len(raw.encode("utf-8")) > MAX_PACKET_BYTES:
        raise ProtocolError("Le paquet dépasse la limite de 8 KiB.", "packet_too_large")
    try:
        packet = json.loads(
            raw,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except ProtocolError:
        raise
    except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
        raise ProtocolError("Le paquet JSON est invalide.") from exc
    if not isinstance(packet, dict):
        raise ProtocolError("Le paquet JSON doit être un objet.")
    return packet


def encode_packet(packet: Mapping[str, Any]) -> str:
    """Sérialise un paquet sans valeurs non finies et vérifie sa taille."""

    try:
        raw = json.dumps(
            packet,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ProtocolError("Le paquet ne peut pas être sérialisé en JSON.") from exc
    if len(raw.encode("utf-8")) > MAX_PACKET_BYTES:
        raise ProtocolError("Le paquet dépasse la limite de 8 KiB.", "packet_too_large")
    return raw


def _require_exact_keys(packet: Mapping[str, Any], expected: frozenset[str]) -> None:
    actual = set(packet)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details: list[str] = []
        if missing:
            details.append("champs manquants : " + ", ".join(missing))
        if extra:
            details.append("champs interdits : " + ", ".join(extra))
        raise ProtocolError("Structure du paquet invalide (" + "; ".join(details) + ").")


def validate_username(username: object) -> str:
    """Valide un pseudo Unicode de 1 à 24 caractères, sans espaces."""

    if not isinstance(username, str):
        raise ProtocolError("Le pseudo doit être une chaîne.", "invalid_username")
    if not 1 <= len(username) <= MAX_USERNAME_CHARS:
        raise ProtocolError(
            f"Le pseudo doit contenir 1 à {MAX_USERNAME_CHARS} caractères.",
            "invalid_username",
        )
    if username != username.strip() or _USERNAME_ALLOWED.fullmatch(username) is None:
        raise ProtocolError(
            "Le pseudo accepte uniquement lettres, chiffres, '_', '-' et '.'.",
            "invalid_username",
        )
    if not any(character.isalnum() for character in username):
        raise ProtocolError(
            "Le pseudo doit contenir au moins une lettre ou un chiffre.",
            "invalid_username",
        )
    return username


def canonical_username(username: str) -> str:
    """Forme utilisée pour empêcher les doublons tels que Alice et alice."""

    return username.casefold()


def _validate_uuid(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ProtocolError(f"Le champ {field} doit être un UUID.")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ProtocolError(f"Le champ {field} doit être un UUID.") from exc
    if str(parsed) != value:
        raise ProtocolError(f"Le champ {field} doit être un UUID canonique en minuscules.")
    return value


def validate_message_metadata(metadata: Mapping[str, Any]) -> None:
    """Valide tous les champs qui seront authentifiés par AES-GCM."""

    if not isinstance(metadata, Mapping):
        raise ProtocolError("Les métadonnées doivent être un objet.")

    version = metadata.get("version")
    if type(version) is not int or version != PROTOCOL_VERSION:
        raise ProtocolError("Version du protocole non prise en charge.", "unsupported_version")
    if metadata.get("room") != ROOM_NAME:
        raise ProtocolError("Le salon doit être 'general'.", "invalid_room")
    validate_username(metadata.get("username"))
    _validate_uuid(metadata.get("message_id"), "message_id")
    _validate_uuid(metadata.get("session_id"), "session_id")

    sequence = metadata.get("sequence")
    if type(sequence) is not int or not 1 <= sequence <= MAX_SEQUENCE:
        raise ProtocolError("Le numéro de séquence est invalide.")
    timestamp = metadata.get("timestamp")
    if type(timestamp) is not int or not 0 <= timestamp <= MAX_TIMESTAMP_MS:
        raise ProtocolError("L'horodatage est invalide.")


def extract_metadata(packet: Mapping[str, Any]) -> dict[str, Any]:
    """Copie uniquement les métadonnées prévues, jamais de champ auxiliaire."""

    validate_message_metadata(packet)
    return {field: packet[field] for field in AAD_FIELDS}


def build_aad(metadata: Mapping[str, Any]) -> bytes:
    """Construit l'AAD canonique, identique chez l'émetteur et les récepteurs."""

    canonical = extract_metadata(metadata)
    return json.dumps(
        canonical,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64decode(value: object, field: str) -> bytes:
    if not isinstance(value, str):
        raise ProtocolError(f"Le champ {field} doit être encodé en Base64.")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise ProtocolError(f"Le champ {field} n'est pas un Base64 valide.") from exc


def validate_join_packet(packet: Mapping[str, Any]) -> tuple[str, str]:
    _require_exact_keys(packet, JOIN_KEYS)
    if packet.get("type") != "join":
        raise ProtocolError("Le premier paquet doit être de type 'join'.")
    if type(packet.get("version")) is not int or packet.get("version") != PROTOCOL_VERSION:
        raise ProtocolError("Version du protocole non prise en charge.", "unsupported_version")
    if packet.get("room") != ROOM_NAME:
        raise ProtocolError("Le salon doit être 'general'.", "invalid_room")
    username = validate_username(packet.get("username"))
    session_id = _validate_uuid(packet.get("session_id"), "session_id")
    return username, session_id


def validate_leave_packet(packet: Mapping[str, Any]) -> None:
    _require_exact_keys(packet, LEAVE_KEYS)
    if packet.get("type") != "leave":
        raise ProtocolError("Paquet de départ invalide.")


def validate_message_packet(packet: Mapping[str, Any]) -> tuple[bytes, bytes]:
    """Valide un message et retourne ``(nonce, ciphertext_avec_tag)``."""

    if not isinstance(packet, Mapping):
        raise ProtocolError("Le message doit être un objet JSON.")
    _require_exact_keys(packet, MESSAGE_KEYS)
    if packet.get("type") != "message":
        raise ProtocolError("Le paquet n'est pas un message utilisateur.")
    validate_message_metadata(packet)

    nonce = b64decode(packet.get("nonce"), "nonce")
    if len(nonce) != NONCE_SIZE:
        raise ProtocolError("Le nonce AES-GCM doit contenir exactement 12 octets.")

    ciphertext = b64decode(packet.get("ciphertext"), "ciphertext")
    if len(ciphertext) <= GCM_TAG_SIZE:
        raise ProtocolError("Le message chiffré est vide ou incomplet.")
    if len(ciphertext) > MAX_CIPHERTEXT_BYTES:
        raise ProtocolError(
            "Les données chiffrées dépassent la limite de 2 000 octets de texte UTF-8.",
            "message_too_large",
        )
    return nonce, ciphertext


def make_message_packet(
    metadata: Mapping[str, Any], nonce: bytes, ciphertext: bytes
) -> dict[str, Any]:
    """Construit un paquet message sans jamais accepter de texte clair annexe."""

    packet: dict[str, Any] = {
        "type": "message",
        **extract_metadata(metadata),
        "nonce": b64encode(nonce),
        "ciphertext": b64encode(ciphertext),
    }
    validate_message_packet(packet)
    return packet
