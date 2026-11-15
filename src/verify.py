from __future__ import annotations

import hashlib
import os
from dataclasses import asdict, dataclass
from typing import Any

try:
    from . import keys, signing
    from .bundle import parse_bundle
    from .formats import FormatError
    from .manifest import ALGORITHMS, parse_manifest
    from .truststore import parse_store
except ImportError:
    import keys
    import signing
    from bundle import parse_bundle
    from formats import FormatError
    from manifest import ALGORITHMS, parse_manifest
    from truststore import parse_store

@dataclass(frozen=True)
class VerifyResult:
    valid: bool
    status: str
    message: str
    algorithm: str | None = None
    keyid: str | None = None
    package: str | None = None
    version: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

def _result(status: str, message: str, manifest: dict[str, Any] | None = None) -> VerifyResult:
    artifact = manifest or {}
    return VerifyResult(
        valid=status == "OK",
        status=status,
        message=message,
        algorithm=artifact.get("algorithm"),
        keyid=artifact.get("keyid"),
        package=artifact.get("package"),
        version=artifact.get("version"),
    )

def verify_bytes(
    artifact_bytes: bytes,
    bundle_bytes: bytes,
    trust_bytes: bytes,
    expected_package: str,
    expected_version: str,
    artifact_name: str,
) -> VerifyResult:
    # Memverifikasi mengikuti urutan kontrak.
    manifest: dict[str, Any] | None = None
    try:
        manifest_bytes, signature = parse_bundle(bundle_bytes)
        trust_store = parse_store(trust_bytes)
        manifest = parse_manifest(manifest_bytes)
    except FormatError as exc:
        return _result("FORMAT_ERROR", str(exc), manifest)

    algorithm = manifest["algorithm"]
    if algorithm not in ALGORITHMS:
        return _result("UNSUPPORTED_ALGORITHM", "Manifest uses an unsupported signature profile.", manifest)

    entry = next((item for item in trust_store["keys"] if item["keyid"] == manifest["keyid"]), None)
    if entry is None or entry["algorithm"] != algorithm or expected_package not in entry["packages"]:
        return _result("KEY_NOT_TRUSTED", "The manifest key is not trusted for this package.", manifest)

    try:
        public_key = keys.load_public_key(entry["public_key_pem"].encode("ascii"))
        if keys.get_algorithm(public_key) != algorithm or keys.fingerprint(public_key) != manifest["keyid"]:
            return _result("FORMAT_ERROR", "Trust-store key metadata does not match its public key.", manifest)
        signature_valid = signing.verify(public_key, manifest_bytes, signature)
    except Exception:
        return _result("FORMAT_ERROR", "Trusted public key could not be loaded.", manifest)
    if not signature_valid:
        return _result("INVALID_SIGNATURE", "Signature is invalid for the manifest.", manifest)

    if (
        manifest["package"] != expected_package
        or manifest["version"] != expected_version
        or manifest["artifact"]["name"] != artifact_name
    ):
        return _result("METADATA_MISMATCH", "Manifest metadata does not match the expected release.", manifest)

    artifact = manifest["artifact"]
    if len(artifact_bytes) != artifact["size"] or hashlib.sha256(artifact_bytes).hexdigest() != artifact["sha256"]:
        return _result("ARTIFACT_MISMATCH", "Artifact size or SHA-256 does not match the manifest.", manifest)

    return _result("OK", "Signature and artifact are valid.", manifest)

def read_verify_inputs(
    artifact_path: str | os.PathLike[str],
    bundle_path: str | os.PathLike[str],
    trust_path: str | os.PathLike[str],
    expected_package: str,
    expected_version: str,
) -> VerifyResult:
    # Membaca semua masukan sebelum parsing.
    try:
        with open(artifact_path, "rb") as stream:
            artifact = stream.read()
        with open(bundle_path, "rb") as stream:
            bundle = stream.read()
        with open(trust_path, "rb") as stream:
            trust = stream.read()
    except OSError as exc:
        return _result("INPUT_ERROR", f"Unable to read verification input: {exc}")
    return verify_bytes(
        artifact,
        bundle,
        trust,
        expected_package,
        expected_version,
        os.path.basename(os.fspath(artifact_path)),
    )