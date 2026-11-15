from __future__ import annotations

from typing import Any

try:
    from .keys import ECDSA_P256, ED25519, RSA_PSS, get_algorithm
except ImportError:
    from keys import ECDSA_P256, ED25519, RSA_PSS, get_algorithm

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

RSA_SALT_LENGTH = 32
ECDSA_SCALAR_BYTES = 32

# Ukuran signature, dari tabel 2.1
SIGNATURE_SIZES = {
    RSA_PSS: 384,
    ECDSA_P256: 64,
    ED25519: 64,
}

def sign(private_key: Any, message: bytes) -> bytes:
    """Sign the exact message bytes."""

    algorithm = get_algorithm(private_key)

    if algorithm == RSA_PSS:
        return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=RSA_SALT_LENGTH,
            ),
            hashes.SHA256(),
        )

    if algorithm == ECDSA_P256:
        der_signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_signature)
        return r.to_bytes(ECDSA_SCALAR_BYTES, "big") + s.to_bytes(ECDSA_SCALAR_BYTES, "big")

    if algorithm == ED25519:
        return private_key.sign(message)

    raise ValueError(f"unsupported algorithm: {algorithm}")

def verify(public_key: Any, message: bytes, signature: bytes) -> bool:
    """Verify the exact message bytes (return False for invalid signature)."""

    algorithm = get_algorithm(public_key)
    if len(signature) != SIGNATURE_SIZES[algorithm]:
        return False

    try:
        if algorithm == RSA_PSS:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=RSA_SALT_LENGTH,
                ),
                hashes.SHA256(),
            )
        elif algorithm == ECDSA_P256:
            r = int.from_bytes(signature[:ECDSA_SCALAR_BYTES], "big")
            s = int.from_bytes(signature[ECDSA_SCALAR_BYTES:], "big")
            public_key.verify(
                encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256())
            )
        else:
            public_key.verify(signature, message)
    except (InvalidSignature, ValueError):
        return False

    return True