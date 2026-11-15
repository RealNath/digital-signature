from __future__ import annotations

import json
import re
from typing import Any

class FormatError(ValueError):
    pass

def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FormatError(f"duplicate JSON field: {key}")
        result[key] = value
    return result

def strict_json_loads(data: bytes, *, max_bytes: int, label: str) -> Any:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if len(data) > max_bytes:
        raise FormatError(f"{label} exceeds the {max_bytes}-byte limit")
    if data.startswith(b"\xef\xbb\xbf"):
        raise FormatError(f"{label} must not contain a UTF-8 BOM")
    try:
        source = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise FormatError(f"{label} is not valid UTF-8") from exc
    if re.search(r"\\u[0-9a-fA-F]{4}", source):
        raise FormatError(f"{label} must not use \\uXXXX escapes")
    try:
        return json.loads(
            source,
            object_pairs_hook=_unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                FormatError(f"invalid JSON constant: {value}")
            ),
        )
    except FormatError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise FormatError(f"{label} is not valid JSON") from exc

def require_exact_fields(value: Any, fields: tuple[str, ...], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(fields):
        raise FormatError(f"{label} must contain exactly: {', '.join(fields)}")
    return value

def require_string(value: Any, label: str, pattern: str | None = None) -> str:
    if type(value) is not str:
        raise FormatError(f"{label} must be a string")
    try:
        value.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise FormatError(f"{label} must contain ASCII characters only") from exc
    if pattern is not None and re.fullmatch(pattern, value) is None:
        raise FormatError(f"{label} has an invalid value")
    return value

def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")

def strict_b64decode(value: Any, label: str) -> bytes:
    import base64
    import binascii

    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", value) is None:
        raise FormatError(f"{label} is not standard Base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise FormatError(f"{label} is not valid Base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise FormatError(f"{label} is not canonically encoded Base64")
    return decoded