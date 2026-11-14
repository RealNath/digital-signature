from __future__ import annotations

from typing import Any


class CryptoNotReadyError(RuntimeError):
    """Raised until work item 1 supplies the cryptographic implementation."""


def generate_keypair(algorithm: str) -> tuple[bytes, bytes, str]:
    """Return PKCS8 private PEM, SPKI public PEM, and lowercase SPKI fingerprint."""
    raise CryptoNotReadyError("crypto core is not implemented yet (work item 1)")


def load_private_key(pem: bytes) -> Any:
    """Load an unencrypted PKCS8 PEM private key."""
    raise CryptoNotReadyError("crypto core is not implemented yet (work item 1)")


def load_public_key(pem: bytes) -> Any:
    """Load an SPKI PEM public key."""
    raise CryptoNotReadyError("crypto core is not implemented yet (work item 1)")


def get_algorithm(key: Any) -> str:
    """Return the canonical profile name for a loaded key."""
    raise CryptoNotReadyError("crypto core is not implemented yet (work item 1)")


def public_key_from_private(private_key: Any) -> Any:
    """Derive the public key corresponding to a loaded private key."""
    raise CryptoNotReadyError("crypto core is not implemented yet (work item 1)")


def fingerprint(public_key: Any) -> str:
    """Return hex_lower(SHA256(DER SPKI)) for a loaded public key."""
    raise CryptoNotReadyError("crypto core is not implemented yet (work item 1)")
