"""Chiffrement authentifié AES-256-GCM de CipherChat."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from protocol import (
    KEY_SIZE,
    MAX_PLAINTEXT_BYTES,
    MAX_PLAINTEXT_CHARS,
    NONCE_SIZE,
    PBKDF2_ITERATIONS,
    SALT_MIN_SIZE,
    ProtocolError,
    build_aad,
    make_message_packet,
    validate_message_packet,
)


class DecryptionError(ValueError):
    """Échec volontairement générique pour une clé fausse ou des données altérées."""


def derive_key(
    passphrase: str,
    salt: bytes,
    iterations: int = PBKDF2_ITERATIONS,
) -> bytes:
    """Dérive une clé AES-256 à partir de la phrase secrète et du sel public."""

    if not isinstance(passphrase, str) or not passphrase:
        raise ValueError("La phrase secrète ne peut pas être vide.")
    if not isinstance(salt, bytes) or len(salt) < SALT_MIN_SIZE:
        raise ValueError(f"Le sel doit contenir au moins {SALT_MIN_SIZE} octets.")
    if type(iterations) is not int or iterations < 1:
        raise ValueError("Le nombre d'itérations PBKDF2 doit être positif.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != KEY_SIZE:
        raise ValueError("La clé AES-256 doit contenir exactement 32 octets.")


def validate_plaintext(plaintext: str) -> bytes:
    """Applique les limites client en caractères et en octets UTF-8."""

    if not isinstance(plaintext, str) or not plaintext:
        raise ValueError("Le message ne peut pas être vide.")
    if len(plaintext) > MAX_PLAINTEXT_CHARS:
        character_limit = f"{MAX_PLAINTEXT_CHARS:,}".replace(",", " ")
        raise ValueError(
            f"Le message dépasse la limite de {character_limit} caractères."
        )
    encoded = plaintext.encode("utf-8")
    if len(encoded) > MAX_PLAINTEXT_BYTES:
        raise ValueError(
            "Le message dépasse la limite conservative de "
            f"{MAX_PLAINTEXT_BYTES} octets UTF-8 imposée par le protocole."
        )
    return encoded


def encrypt_message(
    plaintext: str,
    key: bytes,
    metadata: Mapping[str, Any],
) -> dict[str, Any]:
    """Chiffre un message avant tout envoi réseau et retourne son paquet JSON."""

    _validate_key(key)
    encoded = validate_plaintext(plaintext)
    # build_aad valide aussi les métadonnées avant le chiffrement.
    aad = build_aad(metadata)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext_with_tag = AESGCM(key).encrypt(nonce, encoded, aad)
    return make_message_packet(metadata, nonce, ciphertext_with_tag)


def decrypt_message(packet: Mapping[str, Any], key: bytes) -> str:
    """Vérifie le protocole et l'AAD, puis déchiffre un message utilisateur."""

    _validate_key(key)
    nonce, ciphertext_with_tag = validate_message_packet(packet)
    aad = build_aad(packet)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext_with_tag, aad)
    except InvalidTag:
        raise DecryptionError(
            "Déchiffrement impossible : phrase secrète différente ou paquet altéré."
        ) from None

    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        raise DecryptionError("Le contenu déchiffré n'est pas un texte UTF-8 valide.") from None
    try:
        validate_plaintext(text)
    except ValueError as exc:
        raise DecryptionError("Le contenu déchiffré ne respecte pas les limites du protocole.") from exc
    return text
