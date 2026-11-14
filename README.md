# MiniSign

MiniSign signs release manifests and verifies artifact bundles against a user-managed trust store.

## CLI

Run from the repository root with `python src/minisign.py --help` (or `python -m src.main --help`):

```text
minisign keygen --algorithm <profile> --out <prefix> [--force]
minisign sign --file <path> --package <name> --version <version> --key <private.pem> --out <bundle.json>
minisign verify --file <path> --bundle <bundle.json> --trust-store <trust.json> --package <name> --version <version> [--json]
minisign trust add --key <public.pem> --package <name> --store <trust.json>
minisign trust list --store <trust.json>
minisign trust remove --keyid <fingerprint> --store <trust.json>
```

The three profile names are `rsa-pss-sha256`, `ecdsa-p256-sha256`, and `ed25519`. Key generation writes `<prefix>.key.pem` (PKCS8) and `<prefix>.pub.pem` (SPKI). Existing key files require the explicit `--force` option. Bundle output is created exclusively and is never silently overwritten.

## Crypto core integration (work item 1)

`src/keys.py` and `src/signing.py` define the stable integration surface for the crypto implementation. Replace their `CryptoNotReadyError` stubs with implementations that preserve these call signatures:

- `keys.generate_keypair(profile) -> (private_pkcs8_pem: bytes, public_spki_pem: bytes, keyid: str)`
- `keys.load_private_key(pem: bytes)` and `keys.load_public_key(pem: bytes)`
- `keys.get_algorithm(key) -> str`, `keys.public_key_from_private(private_key)`, and `keys.fingerprint(public_key) -> str`
- `signing.sign(private_key, message: bytes) -> bytes` and `signing.verify(public_key, message: bytes, signature: bytes) -> bool`

`message` is the exact serialized manifest byte string. RSA-PSS and ECDSA apply SHA-256 exactly once through the library's message-signing API; Ed25519 receives the original bytes. ECDSA signatures crossing the crypto boundary use fixed-width `r || s` (64 bytes), not DER.

## Format and verification flow

Manifests use canonical UTF-8 JSON (ASCII field values, fixed field order, no BOM, whitespace, newline, duplicate/extra fields, or `\\uXXXX` escape) and are limited to 16 KiB. Bundles are limited to 64 KiB and Base64 values must decode and re-encode identically. Trust-store mutations write a same-directory temporary file and replace the old file atomically.

Verification returns the first failing status from the required order: input/I/O, format, supported algorithm, trusted key and package permission, signature, expected metadata/name, artifact size and SHA-256, then `OK`. `verify --json` emits one JSON result object and uses exit codes 0 (valid), 1 (rejected), or 2 (input/I/O/environment error).

The crypto files are intentionally stubs until work item 1 is completed; key generation, signing, trust-key validation, and signature verification will report that the crypto core is unavailable in the meantime.
