from __future__ import annotations

from typing import Any

try:
    from .keys import CryptoNotReadyError
except ImportError:
    from keys import CryptoNotReadyError


def sign(private_key: Any, message: bytes) -> bytes:
    """Sign the exact message bytes; implementations must not pre-hash twice."""
    raise CryptoNotReadyError("crypto core is not implemented yet (work item 1)")


def verify(public_key: Any, message: bytes, signature: bytes) -> bool:
    """Verify the exact message bytes and return False for an invalid signature."""
    raise CryptoNotReadyError("crypto core is not implemented yet (work item 1)")
