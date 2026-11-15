from __future__ import annotations

import base64
from typing import Any

try:
    from .formats import FormatError, canonical_json, require_exact_fields, require_string, strict_b64decode, strict_json_loads
except ImportError:
    from formats import FormatError, canonical_json, require_exact_fields, require_string, strict_b64decode, strict_json_loads

MAX_BUNDLE_BYTES = 64 * 1024
SCHEMA = "minisign-bundle/v1"

def build_bundle(manifest_bytes: bytes, signature: bytes) -> bytes:
    if not isinstance(manifest_bytes, bytes) or not isinstance(signature, bytes):
        raise TypeError("manifest and signature must be bytes")
    result = canonical_json({
        "schema": SCHEMA,
        "manifest_b64": base64.b64encode(manifest_bytes).decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    })
    if len(result) > MAX_BUNDLE_BYTES:
        raise FormatError("bundle exceeds the 64 KiB limit")
    return result

def parse_bundle(data: bytes) -> tuple[bytes, bytes]:
    value: Any = strict_json_loads(data, max_bytes=MAX_BUNDLE_BYTES, label="bundle")
    bundle = require_exact_fields(value, ("schema", "manifest_b64", "signature_b64"), "bundle")
    if type(bundle["schema"]) is not str or bundle["schema"] != SCHEMA:
        raise FormatError(f"bundle schema must be {SCHEMA}")
    require_string(bundle["manifest_b64"], "bundle.manifest_b64")
    require_string(bundle["signature_b64"], "bundle.signature_b64")
    return (
        strict_b64decode(bundle["manifest_b64"], "bundle.manifest_b64"),
        strict_b64decode(bundle["signature_b64"], "bundle.signature_b64"),
    )