from __future__ import annotations

from typing import Any

from src.keys import get_algorithm

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

def sign(private_key: Any, message: bytes) -> bytes:
    """Sign the exact message bytes; implementations must not pre-hash twice."""

    algorithm = get_algorithm(private_key)

    if algorithm == "RSA-3072":
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32
            ),
            hashes.SHA256()
        )
    elif algorithm == "P-256":
        der_signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )

        r, s = decode_dss_signature(der_signature)

        r_bytes = r.to_bytes(32, byteorder='big')
        s_bytes = s.to_bytes(32, byteorder='big')

        signature = r_bytes + s_bytes
    elif algorithm == "Ed25519":
        signature = private_key.sign(message)
    return signature

def verify(public_key: Any, message: bytes, signature: bytes) -> bool:
    """Verify the exact message bytes and return False for an invalid signature."""
    try:
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, message)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        else:
            raise TypeError(f"Unsupported public key type: {type(public_key)}")

        return True

    except InvalidSignature:
        return False