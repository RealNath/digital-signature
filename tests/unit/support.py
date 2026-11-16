# Helper untuk skenario U01-U14

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]

PROFILES = ("rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519")
PACKAGE = "demo-app"
VERSION = "1.0.0"

TEXT = b"release payload\n"
BINARY = bytes(range(256)) * 4
EMPTY = b""

def run_tool(*args: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "src.minisign", *(str(arg) for arg in args)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

def keygen(prefix: Path, profile: str) -> str:
    proc = run_tool("keygen", "--algorithm", profile, "--out", prefix)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()

def sign(artifact, key, bundle, package: str = PACKAGE, version: str = VERSION):
    return run_tool(
        "sign",
        "--file", artifact,
        "--package", package,
        "--version", version,
        "--key", key,
        "--out", bundle,
    )

def trust_add(pub, package: str, store):
    return run_tool("trust", "add", "--key", pub, "--package", package, "--store", store)

def verify(
    artifact,
    bundle,
    store,
    package: str = PACKAGE,
    version: str = VERSION,
) -> subprocess.CompletedProcess[str]:
    return run_tool(
        "verify",
        "--file", artifact,
        "--bundle", bundle,
        "--trust-store", store,
        "--package", package,
        "--version", version,
        "--json",
    )

def result(proc: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    return json.loads(proc.stdout)

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def unb64(text: str) -> bytes:
    return base64.b64decode(text)

def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

def read_bundle(path: Path) -> dict[str, str]:
    return json.loads(path.read_bytes())

def write_bundle(path: Path, manifest_b64: str, signature_b64: str, schema: str = "minisign-bundle/v1") -> None:
    payload = {
        "schema": schema,
        "manifest_b64": manifest_b64,
        "signature_b64": signature_b64,
    }
    path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")

def manifest_of(bundle: dict[str, str]) -> bytes:
    return unb64(bundle["manifest_b64"])

def signature_of(bundle: dict[str, str]) -> bytes:
    return unb64(bundle["signature_b64"])

def signed_release(
    tmp_path: Path,
    keyring: dict[str, dict[str, Any]],
    profile: str = "ed25519",
    data: bytes = TEXT,
    name: str = "artifact.txt",
    package: str = PACKAGE,
    version: str = VERSION,
) -> tuple[Path, Path, Path]:
    """Sign an artifact and build a trust store that trusts its key."""
    artifact = tmp_path / name
    artifact.write_bytes(data)
    bundle = tmp_path / "bundle.json"
    store = tmp_path / "trust.json"

    proc = sign(artifact, keyring[profile]["key"], bundle, package, version)
    assert proc.returncode == 0, proc.stderr
    proc = trust_add(keyring[profile]["pub"], package, store)
    assert proc.returncode == 0, proc.stderr

    return artifact, bundle, store