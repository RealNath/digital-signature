from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path

try:
    from . import keys, signing, truststore
    from .bundle import build_bundle
    from .formats import FormatError
    from .manifest import ALGORITHMS, PACKAGE_RE, VERSION_RE, build_manifest
    from .verify import VerifyResult, read_verify_inputs
except ImportError:
    import keys
    import signing
    import truststore
    from bundle import build_bundle
    from formats import FormatError
    from manifest import ALGORITHMS, PACKAGE_RE, VERSION_RE, build_manifest
    from verify import VerifyResult, read_verify_inputs

__version__ = "0.0.1"
EXIT_OK = 0
EXIT_REJECTED = 1
EXIT_ERROR = 2

class CliParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self._error_message = message
        super().error(message)


def build_parser() -> argparse.ArgumentParser:
    parser = CliParser(prog="minisign", description="Sign and verify software releases.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", metavar="<command>", parser_class=CliParser)
    commands.required = True

    p = commands.add_parser("keygen", help="Generate a key pair")
    p.add_argument("--algorithm", required=True, choices=ALGORITHMS, metavar="<profile>")
    p.add_argument("--out", required=True, metavar="<prefix>")
    p.add_argument("--force", action="store_true", help="Allow replacing either output key file")
    p.set_defaults(handler=cmd_keygen)

    p = commands.add_parser("sign", help="Sign an artifact, producing a bundle")
    p.add_argument("--file", required=True, metavar="<path>")
    p.add_argument("--package", required=True, metavar="<name>")
    p.add_argument("--version", required=True, metavar="<release-version>")
    p.add_argument("--key", required=True, metavar="<private.pem>")
    p.add_argument("--out", required=True, metavar="<bundle.json>")
    p.add_argument("--force", action="store_true", help="Allow replacing an existing output bundle file")
    p.set_defaults(handler=cmd_sign)

    p = commands.add_parser("verify", help="Verify an artifact against a bundle")
    p.add_argument("--file", required=True, metavar="<path>")
    p.add_argument("--bundle", required=True, metavar="<bundle.json>")
    p.add_argument("--trust-store", required=True, dest="trust_store", metavar="<trust.json>")
    p.add_argument("--package", required=True, metavar="<name>")
    p.add_argument("--version", required=True, metavar="<release-version>")
    p.add_argument("--json", action="store_true", dest="as_json")
    p.set_defaults(handler=cmd_verify)

    trust = commands.add_parser("trust", help="Manage the trust store")
    actions = trust.add_subparsers(dest="trust_command", metavar="<action>")
    actions.required = True
    p = actions.add_parser("add", help="Allow a public key for a package")
    p.add_argument("--key", required=True, metavar="<public.pem>")
    p.add_argument("--package", required=True, metavar="<name>")
    p.add_argument("--store", required=True, metavar="<trust.json>")
    p.set_defaults(handler=cmd_trust_add)
    p = actions.add_parser("list", help="List trusted keys")
    p.add_argument("--store", required=True, metavar="<trust.json>")
    p.set_defaults(handler=cmd_trust_list)
    p = actions.add_parser("remove", help="Remove a trusted key")
    p.add_argument("--keyid", required=True, metavar="<fingerprint>")
    p.add_argument("--store", required=True, metavar="<trust.json>")
    p.set_defaults(handler=cmd_trust_remove)
    return parser

def _validate_release_inputs(package: str, version: str) -> None:
    if not isinstance(package, str) or re.fullmatch(PACKAGE_RE, package) is None:
        raise ValueError("package name has an invalid format")
    if not isinstance(version, str) or re.fullmatch(VERSION_RE, version) is None:
        raise ValueError("release version has an invalid format")

def _atomic_exclusive_pair(key_path: Path, public_path: Path, key_pem: bytes, public_pem: bytes, force: bool) -> None:
    targets = (key_path, public_path)
    if not force and any(path.exists() for path in targets):
        raise FileExistsError("one or both key output files already exist; pass --force to replace them")
    temporaries: list[tuple[Path, Path]] = []
    try:
        for target, content in ((key_path, key_pem), (public_path, public_pem)):
            target.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
            temporary = Path(name)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            temporaries.append((temporary, target))
        if not force and any(target.exists() for target in targets):
            raise FileExistsError("a key output file appeared while generating keys")
        for temporary, target in temporaries:
            os.replace(temporary, target)
    finally:
        for temporary, _ in temporaries:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

def cmd_keygen(args: argparse.Namespace) -> int:
    try:
        key_pem, public_pem, keyid = keys.generate_keypair(args.algorithm)
        prefix = Path(args.out)
        key_path = Path(f"{prefix}.key.pem")
        public_path = Path(f"{prefix}.pub.pem")
        _atomic_exclusive_pair(key_path, public_path, key_pem, public_pem, args.force)
        print(keyid)
        return EXIT_OK
    except Exception as exc:
        print(f"minisign: {exc}", file=sys.stderr)
        return EXIT_ERROR

def _write_new(path: str, data: bytes, force: bool = False) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if not force:
        with open(target, "xb") as stream:
            stream.write(data)
        return
    fd = -1
    temporary: str | None = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(data)
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


def cmd_sign(args: argparse.Namespace) -> int:
    try:
        _validate_release_inputs(args.package, args.version)
        force = getattr(args, "force", False)
        if not force and Path(args.out).exists():
            raise FileExistsError("bundle output file already exists; pass --force to replace it")
        artifact_path = Path(args.file)
        artifact_bytes = artifact_path.read_bytes()
        private_pem = Path(args.key).read_bytes()
        private_key = keys.load_private_key(private_pem)
        algorithm = keys.get_algorithm(private_key)
        if algorithm not in ALGORITHMS:
            raise ValueError("private key uses an unsupported profile")
        public_key = keys.public_key_from_private(private_key)
        keyid = keys.fingerprint(public_key)
        if re.fullmatch(r"[0-9a-f]{64}", keyid) is None:
            raise ValueError("crypto core returned an invalid public-key fingerprint")
        _, manifest_bytes = build_manifest(
            args.package,
            args.version,
            algorithm,
            keyid,
            artifact_path.name,
            len(artifact_bytes),
            hashlib.sha256(artifact_bytes).hexdigest(),
        )
        signature = signing.sign(private_key, manifest_bytes)
        bundle_bytes = build_bundle(manifest_bytes, signature)
        _write_new(args.out, bundle_bytes, force=force)
        return EXIT_OK
    except Exception as exc:
        print(f"minisign: {exc}", file=sys.stderr)
        return EXIT_ERROR

def cmd_verify(args: argparse.Namespace) -> int:
    result = None
    try:
        _validate_release_inputs(args.package, args.version)
        result = read_verify_inputs(args.file, args.bundle, args.trust_store, args.package, args.version)
    except (OSError, ValueError, FormatError) as exc:
        result = VerifyResult(False, "INPUT_ERROR", str(exc))
    except Exception as exc:
        print(f"minisign: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.as_json:
        print(json.dumps(result.as_dict(), separators=(",", ":"), ensure_ascii=True))
    elif result.valid:
        print(f"OK: {result.message}")
    else:
        print(f"{result.status}: {result.message}", file=sys.stderr)
    return EXIT_OK if result.status == "OK" else EXIT_ERROR if result.status == "INPUT_ERROR" else EXIT_REJECTED

def cmd_trust_add(args: argparse.Namespace) -> int:
    try:
        result = truststore.add_key(args.store, Path(args.key).read_bytes(), args.package)
        print(f"{result['keyid']} {result['algorithm']} {result['package']}")
        return EXIT_OK
    except Exception as exc:
        print(f"minisign: {exc}", file=sys.stderr)
        return EXIT_ERROR

def cmd_trust_list(args: argparse.Namespace) -> int:
    try:
        store = truststore.load_store(args.store)
        for entry in store["keys"]:
            print(f"{entry['keyid']} {entry['algorithm']} {','.join(entry['packages'])}")
        return EXIT_OK
    except Exception as exc:
        print(f"minisign: {exc}", file=sys.stderr)
        return EXIT_ERROR

def cmd_trust_remove(args: argparse.Namespace) -> int:
    try:
        truststore.remove_key(args.store, args.keyid)
        return EXIT_OK
    except Exception as exc:
        print(f"minisign: {exc}", file=sys.stderr)
        return EXIT_ERROR

def main(argv: list[str] | None = None) -> int:
    effective_argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    try:
        args = parser.parse_args(effective_argv)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else EXIT_ERROR
        if code != EXIT_OK and len(effective_argv) >= 1 and effective_argv[0] == "verify" and "--json" in effective_argv:
            result = VerifyResult(False, "INPUT_ERROR", "Missing or invalid CLI arguments for verify.")
            print(json.dumps(result.as_dict(), separators=(",", ":"), ensure_ascii=True))
            return EXIT_ERROR
        raise
    return args.handler(args)

if __name__ == "__main__":
    raise SystemExit(main())