# MiniSign

MiniSign is a small, Cosign-style release signing tool. It signs a canonical
JSON *manifest* that describes one artifact, packs the manifest and its
signature into a JSON *bundle*, and verifies bundles against a trust store that
lists which public key may sign which package.

Everything is one Python CLI with three signature profiles, packaged as a
container image that runs offline and unprivileged.

## Stack

| Component | Version |
| --- | --- |
| Python | 3.14 (`python:3.14-slim` in the image) |
| `cryptography` | 50.0.2 (only runtime dependency) |
| `pytest` | 9.2.0 (tests only, `requirements-dev.txt`) |

No other third-party packages are used: argument parsing, JSON, Base64, and
hashing come from the standard library.

## Container image

The image is published to GHCR and must be referenced by digest, not by tag:

```bash
docker run --rm ghcr.io/realnath/digital-signature@sha256:ae42a3d84e29a7961c4e0a97f4318f158be9070b3ddb731af94db43adf9b424f --help
```

It needs no network, no TTY, and no privileged user:

```bash
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" -v "$PWD/out:/output" \
  -v "$PWD/keys/publisher.key.pem:/run/signing.key.pem:ro" \
  ghcr.io/realnath/digital-signature@sha256:ae42… sign \
    --file /input/app.tar.gz --package demo-app --version 1.0.0 \
    --key /run/signing.key.pem --out /output/bundle.json
```

Signing keys are never part of the image; they arrive as a read-only mount.

## CLI

From a checkout, run `python3 -m src.minisign <command>` at the repository
root. Inside the image the entrypoint is the same, so `<image> <command>` works.

```text
minisign keygen --algorithm <profile> --out <prefix> [--force]
minisign sign --file <artifact> --package <name> --version <release> --key <private.pem> --out <bundle.json>
minisign verify --file <artifact> --bundle <bundle.json> --trust-store <trust.json> --package <name> --version <release> [--json]
minisign trust add --key <public.pem> --package <name> --store <trust.json>
minisign trust list --store <trust.json>
minisign trust remove --keyid <fingerprint> --store <trust.json>
```

A full local run:

```bash
python3 -m src.minisign keygen --algorithm ed25519 --out keys/publisher
python3 -m src.minisign trust add --key keys/publisher.pub.pem \
  --package demo-app --store keys/trust.json
python3 -m src.minisign sign --file dist/demo-app.tar.gz \
  --package demo-app --version 1.0.0 \
  --key keys/publisher.key.pem --out dist/bundle.json
python3 -m src.minisign verify --file dist/demo-app.tar.gz \
  --bundle dist/bundle.json --trust-store keys/trust.json \
  --package demo-app --version 1.0.0 --json
```

`keygen` prints the keyid. It writes `<prefix>.key.pem` (PKCS#8, unencrypted)
and `<prefix>.pub.pem` (SPKI), refuses to overwrite without `--force`, and
`sign` refuses to overwrite an existing bundle.

## Profiles

| Profile | Library primitive | Public key | Signature |
| --- | --- | --- | --- |
| `rsa-pss-sha256` | RSA-3072, e = 65537, PSS with MGF1-SHA256 and a 32-byte salt | ~625 B PEM | 384 B |
| `ecdsa-p256-sha256` | ECDSA on P-256 with SHA-256, signature stored as fixed-width `r \|\| s` | ~178 B PEM | 64 B |
| `ed25519` | Ed25519 (RFC 8032), pure, no prehash | ~113 B PEM | 64 B |

The ECDSA profile deliberately does not use DER: the 64-byte `r || s` form is
what the bundle carries, and DER conversion happens only at the OpenSSL
boundary in `tests/interop/`.

The keyid is `hex(SHA256(DER SPKI))`, so the same public key always produces the
same identifier regardless of PEM formatting.

## File formats

**Manifest** — canonical JSON, UTF-8, ASCII values, no whitespace, no trailing
newline, at most 16 KiB:

```json
{"schema":"minisign-manifest/v1","package":"demo-app","version":"1.0.0","algorithm":"ed25519","keyid":"576c…a473","artifact":{"name":"demo-app.tar.gz","size":139,"sha256":"9f2c…"}}
```

Field order is fixed, extra and duplicate fields are rejected, and a verifier
re-serialises the manifest and requires byte equality, so two encodings of the
same object cannot both be accepted.

**Bundle** — canonical JSON, at most 64 KiB, both values Base64:

```json
{"schema":"minisign-bundle/v1","manifest_b64":"eyJzY2hlbWEi…","signature_b64":"hL3k…"}
```

The signature covers the manifest bytes exactly as stored, not the artifact.

**Trust store** — the caller's policy, one entry per trusted key:

```json
{"schema":"minisign-trust/v1","keys":[{"keyid":"576c…a473","algorithm":"ed25519","public_key_pem":"-----BEGIN PUBLIC KEY-----\n…\n","packages":["demo-app"]}]}
```

A key may be trusted for several packages; a key trusted for `other-app` cannot
verify a `demo-app` release. Mutations rewrite the file through a temporary file
in the same directory and `os.replace`, so a crash cannot leave a truncated
store.

## Verification ladder

`verify` stops at the first failing step and reports that status:

| Order | Status | Meaning | Exit |
| --- | --- | --- | --- |
| 1 | `INPUT_ERROR` | an input file could not be read | 2 |
| 2 | `FORMAT_ERROR` | bundle, manifest, or trust store is malformed | 1 |
| 3 | `UNSUPPORTED_ALGORITHM` | manifest names a profile the tool does not implement | 1 |
| 4 | `KEY_NOT_TRUSTED` | keyid unknown, algorithm mismatch, or package not permitted | 1 |
| 5 | `INVALID_SIGNATURE` | signature does not verify over the manifest bytes | 1 |
| 6 | `METADATA_MISMATCH` | package, version, or artifact name differs from the expected release | 1 |
| 7 | `ARTIFACT_MISMATCH` | artifact size or SHA-256 differs from the manifest | 1 |
| 8 | `OK` | everything above held | 0 |

The order matters: a tampered manifest is reported as `INVALID_SIGNATURE`, not
as a metadata mismatch, and an untrusted key is rejected before its signature is
even checked.

## Tests

```bash
python3 -m pip install -r requirements-dev.txt

python3 -m pytest tests/unit -q      # U01-U14, 28 cases
bash tests/interop/openssl.sh        # OpenSSL interop, both directions
```

The integration scenarios need the published image and are described in
`tests/README.md`; they run the container with `--network none`, the runner's
UID/GID, and a pinned digest.

## Benchmark

```bash
python3 benchmark/bench.py           # 5 warmups, 30 measured runs
```

Results are written to `benchmark/results.md` and `benchmark/results.json`.
Headline numbers from the reference run (Intel Core 5 210H, Python 3.14.9):

| Profile | sign 1 MiB | verify 1 MiB | CLI sign+verify | Signature | Bundle |
| --- | ---: | ---: | ---: | ---: | ---: |
| `rsa-pss-sha256` | 1.72 ms | 0.55 ms | 187 ms | 384 B | 992 B |
| `ecdsa-p256-sha256` | 0.49 ms | 0.57 ms | 114 ms | 64 B | 572 B |
| `ed25519` | 0.49 ms | 0.57 ms | 108 ms | 64 B | 556 B |

Above 1 MiB the SHA-256 pass over the artifact dominates and the three profiles
converge. The CLI column is mostly interpreter start-up plus RSA key loading,
which is why it is two orders of magnitude larger than the crypto itself.

## Repository layout

```text
src/            CLI and crypto core (keys, signing, manifest, bundle, truststore, verify, formats)
tests/unit/     U01-U14 scenario suite
tests/ci/       C01-C05 integration scenarios against the published image
tests/interop/  OpenSSL interoperability check
benchmark/      bench.py plus generated results
ci/             committed demo public key and trust store used by the pipeline
.github/workflows/  image build/publish and release pipeline
```

## CI/CD

`.github/workflows/build-image.yml` builds and pushes the image on `v*` tags or
manual dispatch, and prints the resulting digest in the run summary.

`.github/workflows/user-pipeline.yml` pulls that image **by digest**, signs a
demo artifact with a key from repository secrets, verifies it, and runs the
negative scenarios. A new publish means updating the digest in the workflow —
that manual step is the point: the pipeline runs an image that was reviewed,
not whatever a tag happens to point at.
