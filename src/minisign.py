import argparse

__version__ = "v0.0.1"

# Tabel 2.10
EXIT_OK = 0
EXIT_REJECTED = 1
EXIT_ERROR = 2

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="minisign", description="Sign and verify software releases.",)
    parser.add_argument("--version", action="version", version=f"{__version__}")

    commands = parser.add_subparsers(dest="command", metavar="<command>")
    commands.required = True

    # keygen --algorithm <profil> --out <prefix>
    p = commands.add_parser("keygen", help="Generate a key pair")
    p.add_argument("--algorithm", required=True, metavar="<profil>")
    p.add_argument("--out", required=True, metavar="<prefix>")
    p.set_defaults(handler=cmd_keygen)

    # sign --file --package --version --key --out
    p = commands.add_parser("sign", help="Sign an artifact, producing a bundle")
    p.add_argument("--file", required=True, metavar="<path>")
    p.add_argument("--package", required=True, metavar="<nama>")
    p.add_argument("--version", required=True, metavar="<versi>")
    p.add_argument("--key", required=True, metavar="<private.pem>")
    p.add_argument("--out", required=True, metavar="<bundle.json>")
    p.set_defaults(handler=cmd_sign)

    # verify --file --bundle --trust-store --package --version [--json]
    p = commands.add_parser("verify", help="Verify an artifact against a bundle")
    p.add_argument("--file", required=True, metavar="<path>")
    p.add_argument("--bundle", required=True, metavar="<bundle.json>")
    p.add_argument("--trust-store", required=True, dest="trust_store", metavar="<trust.json>")
    p.add_argument("--package", required=True, metavar="<nama>")
    p.add_argument("--version", required=True, metavar="<versi>")
    p.add_argument("--json", action="store_true", dest="as_json")
    p.set_defaults(handler=cmd_verify)

    # trust add|list|remove
    trust = commands.add_parser("trust", help="Manage the trust store")
    actions = trust.add_subparsers(dest="trust_command", metavar="<action>")
    actions.required = True

    p = actions.add_parser("add", help="Allow a public key for a package")
    p.add_argument("--key", required=True, metavar="<public.pem>")
    p.add_argument("--package", required=True, metavar="<nama>")
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

# Write <prefix>.key.pem and <prefix>.pub.pem, print the fingerprint.
def cmd_keygen(args: argparse.Namespace) -> int:
    return EXIT_OK

# Build the manifest, sign it, write the bundle to --out.
def cmd_sign(args: argparse.Namespace) -> int:
    return EXIT_OK

# Run verification, print the result.
def cmd_verify(args: argparse.Namespace) -> int:
    return EXIT_OK

def cmd_trust_add(args: argparse.Namespace) -> int:
    return EXIT_OK

def cmd_trust_list(args: argparse.Namespace) -> int:
    return EXIT_OK

def cmd_trust_remove(args: argparse.Namespace) -> int:
    return EXIT_OK

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)

if __name__ == "__main__":
    raise SystemExit(main())