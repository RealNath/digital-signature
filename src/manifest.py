from __future__ import annotations

import re
from typing import Any

try:
    from .formats import FormatError, canonical_json, require_exact_fields, require_string, strict_json_loads
except ImportError:  # direct execution with src/ on sys.path
    from formats import FormatError, canonical_json, require_exact_fields, require_string, strict_json_loads

MAX_MANIFEST_BYTES = 16 * 1024
SCHEMA = "minisign-manifest/v1"
ALGORITHMS = ("rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519")
PACKAGE_RE = r"[a-z0-9][a-z0-9._-]{0,63}"
VERSION_RE = r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}"
ARTIFACT_NAME_RE = r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
HEX256_RE = r"[0-9a-f]{64}"
MAX_SAFE_INTEGER = 9007199254740991

def validate_manifest(value: Any) -> dict[str, Any]:
    manifest = require_exact_fields(
        value, ("schema", "package", "version", "algorithm", "keyid", "artifact"), "manifest"
    )
    if manifest["schema"] != SCHEMA or type(manifest["schema"]) is not str:
        raise FormatError(f"manifest schema must be {SCHEMA}")
    require_string(manifest["package"], "manifest.package", PACKAGE_RE)
    require_string(manifest["version"], "manifest.version", VERSION_RE)
    require_string(manifest["algorithm"], "manifest.algorithm")
    require_string(manifest["keyid"], "manifest.keyid", HEX256_RE)
    artifact = require_exact_fields(manifest["artifact"], ("name", "size", "sha256"), "manifest.artifact")
    require_string(artifact["name"], "manifest.artifact.name", ARTIFACT_NAME_RE)
    if type(artifact["size"]) is not int or not 0 <= artifact["size"] <= MAX_SAFE_INTEGER:
        raise FormatError("manifest.artifact.size must be an integer in the permitted range")
    require_string(artifact["sha256"], "manifest.artifact.sha256", HEX256_RE)
    return manifest

def serialize_manifest(value: Any) -> bytes:
    manifest = validate_manifest(value)
    ordered = {
        "schema": manifest["schema"],
        "package": manifest["package"],
        "version": manifest["version"],
        "algorithm": manifest["algorithm"],
        "keyid": manifest["keyid"],
        "artifact": {
            "name": manifest["artifact"]["name"],
            "size": manifest["artifact"]["size"],
            "sha256": manifest["artifact"]["sha256"],
        },
    }
    data = canonical_json(ordered)
    if len(data) > MAX_MANIFEST_BYTES:
        raise FormatError("manifest exceeds the 16 KiB limit")
    return data

def parse_manifest(data: bytes) -> dict[str, Any]:
    value = strict_json_loads(data, max_bytes=MAX_MANIFEST_BYTES, label="manifest")
    manifest = validate_manifest(value)
    if serialize_manifest(manifest) != data:
        raise FormatError("manifest is not in canonical serialization")
    if re.search(rb"\\u[0-9a-fA-F]{4}", data):
        raise FormatError("manifest must not use \\uXXXX escapes")
    return manifest

def build_manifest(
    package: str,
    version: str,
    algorithm: str,
    keyid: str,
    artifact_name: str,
    artifact_size: int,
    artifact_sha256: str,
) -> tuple[dict[str, Any], bytes]:
    value = {
        "schema": SCHEMA,
        "package": package,
        "version": version,
        "algorithm": algorithm,
        "keyid": keyid,
        "artifact": {"name": artifact_name, "size": artifact_size, "sha256": artifact_sha256},
    }
    return value, serialize_manifest(value)
