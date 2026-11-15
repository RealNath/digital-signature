from __future__ import annotations

import hashlib
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

# Profil Algoritma untuk kunci publik dan privat.
RSA_PSS = "rsa-pss-sha256"
ECDSA_P256 = "ecdsa-p256-sha256"
ED25519 = "ed25519"

RSA_KEY_SIZE = 3072
RSA_PUBLIC_EXPONENT = 65537
P256_CURVE_NAME = "secp256r1"

def _generate_rsa() -> Any:
    return rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_SIZE
    )

def _generate_p256() -> Any:
    return ec.generate_private_key(ec.SECP256R1())

def _generate_ed25519() -> Any:
    return ed25519.Ed25519PrivateKey.generate()

_GENERATORS: dict[str, Callable[[], Any]] = {
    RSA_PSS: _generate_rsa,
    ECDSA_P256: _generate_p256,
    ED25519: _generate_ed25519,
}

def generate_keypair(algorithm: str) -> tuple[bytes, bytes, str]:
    # Mengembalikan PEM privat PKCS8, PEM publik SPKI, dan sidik jari SPKI huruf kecil.

    generator = _GENERATORS.get(algorithm)
    if generator is None:
        raise ValueError(f"unsupported algorithm: {algorithm}")

    private_key = generator()
    public_key = public_key_from_private(private_key)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem, fingerprint(public_key)

def load_private_key(pem: bytes) -> Any:
    # Memuat kunci privat PEM PKCS8 tanpa enkripsi.

    return serialization.load_pem_private_key(pem, password=None)

def load_public_key(pem: bytes) -> Any:
    # Memuat kunci publik PEM SPKI.

    return serialization.load_pem_public_key(pem)

def get_algorithm(key: Any) -> str:
    # Mengembalikan nama profil algoritma untuk kunci publik atau privat.

    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        if isinstance(key, rsa.RSAPrivateKey):
            public_numbers = key.public_key().public_numbers()
        else:
            public_numbers = key.public_numbers()
        if key.key_size != RSA_KEY_SIZE or public_numbers.e != RSA_PUBLIC_EXPONENT:
            raise ValueError("RSA key parameters do not match rsa-pss-sha256")
        return RSA_PSS

    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        if key.curve.name != P256_CURVE_NAME:
            raise ValueError("EC key curve does not match ecdsa-p256-sha256")
        return ECDSA_P256

    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return ED25519

    raise ValueError(f"unsupported key type: {type(key).__name__}")

def public_key_from_private(private_key: Any) -> Any:
    # Mengambil kunci publik yang berpasangan dengan kunci privat.

    return private_key.public_key()

def fingerprint(public_key: Any) -> str:
    # Menerapkan hex_lower(SHA256(DER SPKI)) untuk kunci publik.

    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return hashlib.sha256(public_der).hexdigest().lower()