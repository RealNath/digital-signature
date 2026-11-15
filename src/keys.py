from __future__ import annotations

import hashlib
from typing import Any

import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.ed25519
from cryptography.hazmat.primitives import serialization

def generate_keypair(algorithm: str) -> tuple[bytes, bytes, str]:
    """Return PKCS8 private PEM, SPKI public PEM, and lowercase SPKI fingerprint."""

    algorithms = {
        "RSA-3072": cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072
        ),
        "P-256": cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
            cryptography.hazmat.primitives.asymmetric.ec.SECP256R1()
        ),
        "Ed25519": cryptography.hazmat.primitives.asymmetric.ed25519.generate_private_key()
    }

    if algorithm not in algorithms:
        raise ValueError(f"unsupported algorithm: {algorithm}")

    private_key = algorithms[algorithm]
    public_key = public_key_from_private(private_key)

    if algorithm == "RSA-3072":
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    elif algorithm == "P-256":
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    elif algorithm == "Ed25519":
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    fingerprint_hex = fingerprint(public_key)

    return private_pem, public_pem, fingerprint_hex


def load_private_key(pem: bytes) -> Any:
    """Load an unencrypted PKCS8 PEM private key."""

    private_key = serialization.load_pem_private_key(pem, password=None)

    return private_key


def load_public_key(pem: bytes) -> Any:
    """Load an SPKI PEM public key."""

    public_key = serialization.load_pem_public_key(pem)

    return public_key


def get_algorithm(key: Any) -> str:
    """Return the canonical profile name for a loaded key."""

    algorithms = {
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey: "RSA-3072",
        cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey: "P-256",
        cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey: "Ed25519",
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey: "RSA-3072",
        cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey: "P-256",
        cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey: "Ed25519"
    }

    if type(key) in algorithms:
        return algorithms[type(key)]


def public_key_from_private(private_key: Any) -> Any:
    """Derive the public key corresponding to a loaded private key."""

    public_key = private_key.public_key()

    return public_key


def fingerprint(public_key: Any) -> str:
    """Return hex_lower(SHA256(DER SPKI)) for a loaded public key."""

    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    fingerprint = hashlib.sha256(public_der).hexdigest()
    
    return fingerprint.lower()