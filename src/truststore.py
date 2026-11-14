from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

try:
    from . import keys
    from .formats import FormatError, require_exact_fields, require_string, strict_json_loads
    from .manifest import ALGORITHMS, HEX256_RE, PACKAGE_RE
except ImportError:
    import keys
    from formats import FormatError, require_exact_fields, require_string, strict_json_loads
    from manifest import ALGORITHMS, HEX256_RE, PACKAGE_RE

SCHEMA = "minisign-trust/v1"
MAX_TRUST_STORE_BYTES = 1024 * 1024


def empty_store() -> dict[str, Any]:
    return {"schema": SCHEMA, "keys": []}


def validate_store(value: Any) -> dict[str, Any]:
    store = require_exact_fields(value, ("schema", "keys"), "trust store")
    if type(store["schema"]) is not str or store["schema"] != SCHEMA:
        raise FormatError(f"trust store schema must be {SCHEMA}")
    if type(store["keys"]) is not list:
        raise FormatError("trust store.keys must be an array")
    seen: set[str] = set()
    for index, raw_entry in enumerate(store["keys"]):
        label = f"trust store.keys[{index}]"
        entry = require_exact_fields(raw_entry, ("keyid", "algorithm", "public_key_pem", "packages"), label)
        keyid = require_string(entry["keyid"], f"{label}.keyid", HEX256_RE)
        if keyid in seen:
            raise FormatError("trust store contains duplicate keyid values")
        seen.add(keyid)
        algorithm = require_string(entry["algorithm"], f"{label}.algorithm")
        if algorithm not in ALGORITHMS:
            raise FormatError(f"{label}.algorithm is unsupported")
        pem = require_string(entry["public_key_pem"], f"{label}.public_key_pem")
        if "-----BEGIN PUBLIC KEY-----" not in pem or "-----END PUBLIC KEY-----" not in pem:
            raise FormatError(f"{label}.public_key_pem is not an SPKI PEM")
        try:
            public_key = keys.load_public_key(pem.encode("ascii"))
            actual_algorithm = keys.get_algorithm(public_key)
            actual_keyid = keys.fingerprint(public_key)
        except keys.CryptoNotReadyError:
            raise
        except Exception as exc:
            raise FormatError(f"{label}.public_key_pem is invalid") from exc
        if actual_algorithm != algorithm:
            raise FormatError(f"{label}.algorithm does not match its public key")
        if actual_keyid != keyid:
            raise FormatError(f"{label}.keyid does not match its public key")
        packages = entry["packages"]
        if type(packages) is not list or not packages:
            raise FormatError(f"{label}.packages must be a non-empty array")
        package_names: set[str] = set()
        for package in packages:
            package_name = require_string(package, f"{label}.packages[]", PACKAGE_RE)
            if package_name in package_names:
                raise FormatError(f"{label}.packages contains duplicates")
            package_names.add(package_name)
    return store


def load_store(path: str | os.PathLike[str]) -> dict[str, Any]:
    data = Path(path).read_bytes()
    return parse_store(data)


def parse_store(data: bytes) -> dict[str, Any]:
    value = strict_json_loads(data, max_bytes=MAX_TRUST_STORE_BYTES, label="trust store")
    return validate_store(value)


def save_store_atomic(path: str | os.PathLike[str], store: dict[str, Any]) -> None:
    validated = validate_store(store)
    target = Path(path)
    parent = target.parent if str(target.parent) else Path(".")
    parent.mkdir(parents=False, exist_ok=True)
    payload = json.dumps(validated, ensure_ascii=False, indent=2, allow_nan=False).encode("utf-8") + b"\n"
    if len(payload) > MAX_TRUST_STORE_BYTES:
        raise FormatError("trust store exceeds the 1 MiB implementation limit")
    fd = -1
    temporary: str | None = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(parent))
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        temporary = None
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def add_key(path: str | os.PathLike[str], public_pem: bytes, package: str) -> dict[str, Any]:
    require_string(package, "package", PACKAGE_RE)
    try:
        public_key = keys.load_public_key(public_pem)
        algorithm = keys.get_algorithm(public_key)
        keyid = keys.fingerprint(public_key)
    except keys.CryptoNotReadyError:
        raise
    except Exception as exc:
        raise FormatError("public key is invalid") from exc
    if algorithm not in ALGORITHMS or type(keyid) is not str or len(keyid) != 64:
        raise FormatError("public key profile or fingerprint is invalid")
    try:
        pem_text = public_pem.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise FormatError("public key PEM must contain ASCII characters only") from exc
    target = Path(path)
    if target.exists():
        store = load_store(target)
    else:
        store = empty_store()
    entries = store["keys"]
    entry = next((item for item in entries if item["keyid"] == keyid), None)
    if entry is None:
        entry = {"keyid": keyid, "algorithm": algorithm, "public_key_pem": pem_text, "packages": [package]}
        entries.append(entry)
    else:
        if entry["algorithm"] != algorithm:
            raise FormatError("existing keyid refers to different key material")
        if package not in entry["packages"]:
            entry["packages"].append(package)
    save_store_atomic(target, store)
    return {"keyid": keyid, "algorithm": algorithm, "package": package}


def remove_key(path: str | os.PathLike[str], keyid: str) -> None:
    require_string(keyid, "keyid", HEX256_RE)
    store = load_store(path)
    remaining = [entry for entry in store["keys"] if entry["keyid"] != keyid]
    if len(remaining) == len(store["keys"]):
        raise FileNotFoundError(f"keyid not found: {keyid}")
    store["keys"] = remaining
    save_store_atomic(path, store)
