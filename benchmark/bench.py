#!/usr/bin/env python3
# Benchmark sign dan verify pada ke-3 profil and 3 ukuran artifak.
# python3 benchmark/bench.py            # 5 warmups, 30 percobaan
# python3 benchmark/bench.py --runs 10  # 10 percobaan

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import random
import ssl
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import cryptography

from src import keys, signing
from src.bundle import build_bundle
from src.manifest import build_manifest
from src.truststore import add_key
from src.verify import verify_bytes

PROFILES = ("rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519")
PACKAGE = "benchmark-app"
VERSION = "1.0.0"

SIZES = (
    ("1 KiB", 1 << 10),
    ("1 MiB", 1 << 20),
    ("16 MiB", 16 << 20),
)

RUNS = 30
WARMUP = 5


def make_artifact(size: int) -> bytes:
    # Deterministic so every profile and every run sees the same bytes.
    return random.Random(20261116).randbytes(size)


def cli(*args: object, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "src.minisign", *(str(arg) for arg in args)],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(fraction * len(ordered)) - 1)
    return ordered[index]


def sample(operation, warmup: int, runs: int) -> list[float]:
    for _ in range(warmup):
        operation()
    timings: list[float] = []
    for _ in range(runs):
        started = time.perf_counter()
        operation()
        timings.append(time.perf_counter() - started)
    return timings


def milliseconds(values: list[float]) -> tuple[float, float]:
    return statistics.median(values) * 1000, percentile(values, 0.95) * 1000


def measure_profile(profile: str, workdir: Path, runs: int, warmup: int) -> dict:
    prefix = workdir / profile
    private_pem, public_pem, keyid = keys.generate_keypair(profile)
    key_path = Path(f"{prefix}.key.pem")
    pub_path = Path(f"{prefix}.pub.pem")
    key_path.write_bytes(private_pem)
    pub_path.write_bytes(public_pem)

    store_path = workdir / f"{profile}-trust.json"
    add_key(store_path, public_pem, PACKAGE)
    trust_bytes = store_path.read_bytes()

    private_key = keys.load_private_key(private_pem)

    artifacts = {label: make_artifact(size) for label, size in SIZES}

    rows = []
    sizes = None
    for label, size in SIZES:
        artifact = artifacts[label]
        name = "artifact.bin"
        _, manifest_bytes = build_manifest(
            PACKAGE, VERSION, profile, keyid, name, size, hashlib.sha256(artifact).hexdigest()
        )
        signature = signing.sign(private_key, manifest_bytes)
        bundle_bytes = build_bundle(manifest_bytes, signature)

        def sign_once() -> None:
            _, serialized = build_manifest(
                PACKAGE, VERSION, profile, keyid, name, size, hashlib.sha256(artifact).hexdigest()
            )
            signing.sign(private_key, serialized)

        def verify_once() -> None:
            result = verify_bytes(artifact, bundle_bytes, trust_bytes, PACKAGE, VERSION, name)
            assert result.status == "OK", result

        artifact_path = workdir / f"{profile}-{label.replace(' ', '')}.bin"
        artifact_path.write_bytes(artifact)
        bundle_path = workdir / f"{profile}-{label.replace(' ', '')}-bundle.json"

        def cli_once() -> None:
            bundle_path.unlink(missing_ok=True)
            cli(
                "sign",
                "--file", artifact_path,
                "--package", PACKAGE,
                "--version", VERSION,
                "--key", key_path,
                "--out", bundle_path,
            )
            cli(
                "verify",
                "--file", artifact_path,
                "--bundle", bundle_path,
                "--trust-store", store_path,
                "--package", PACKAGE,
                "--version", VERSION,
                "--json",
            )

        sign_times = sample(sign_once, warmup, runs)
        verify_times = sample(verify_once, warmup, runs)
        cli_times = sample(cli_once, warmup, runs)

        rows.append(
            {
                "artifact": label,
                "artifact_bytes": size,
                "sign_ms": milliseconds(sign_times),
                "verify_ms": milliseconds(verify_times),
                "cli_ms": milliseconds(cli_times),
            }
        )

        if label == "1 MiB":
            sizes = {
                "private_key_bytes": len(private_pem),
                "public_key_bytes": len(public_pem),
                "signature_bytes": len(signature),
                "manifest_bytes": len(manifest_bytes),
                "bundle_bytes": len(bundle_bytes),
            }

    return {
        "profile": profile,
        "keyid": keyid,
        "sizes": sizes,
        "rows": rows,
    }


def render(results: dict) -> str:
    lines: list[str] = []
    add = lines.append

    add("# Hasil benchmark")
    add("")
    add(f"Dihasilkan oleh `python3 benchmark/bench.py --runs {results['runs']} "
        f"--warmup {results['warmup']}`.")
    add(f"Median dan P95 (nearest rank) dari {results['runs']} percobaan terukur "
        f"setelah {results['warmup']} warmup.")
    add("")
    add("| Item | Value |")
    add("| --- | --- |")
    for key, value in results["environment"].items():
        add(f"| {key} | {value} |")
    add("")

    add("## Key, signature, and bundle sizes")
    add("")
    add("| Profile | Private key | Public key | Signature | Manifest | Bundle |")
    add("| --- | ---: | ---: | ---: | ---: | ---: |")
    for profile in results["profiles"]:
        sizes = profile["sizes"]
        add(
            f"| `{profile['profile']}` | {sizes['private_key_bytes']} B | "
            f"{sizes['public_key_bytes']} B | {sizes['signature_bytes']} B | "
            f"{sizes['manifest_bytes']} B | {sizes['bundle_bytes']} B |"
        )
    add("")
    add("Ukuran dalam byte seperti tertulis di disk (PEM/DER). "
        "Kolom manifest dan bundle diukur pada artefak 1 MiB: "
        "manifest tidak bergantung ukuran, bundle hanya berbeda pada panjang signature.")
    add("")

    add("## Timings")
    add("")
    add("| Profile | Artifact | sign median | sign P95 | verify median | verify P95 | CLI sign+verify median | CLI P95 |")
    add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for profile in results["profiles"]:
        for row in profile["rows"]:
            sign_median, sign_p95 = row["sign_ms"]
            verify_median, verify_p95 = row["verify_ms"]
            cli_median, cli_p95 = row["cli_ms"]
            add(
                f"| `{profile['profile']}` | {row['artifact']} | "
                f"{sign_median:.3f} ms | {sign_p95:.3f} ms | "
                f"{verify_median:.3f} ms | {verify_p95:.3f} ms | "
                f"{cli_median:.1f} ms | {cli_p95:.1f} ms |"
            )
    add("")
    add("`CLI` memulai interpreter dua kali dan menyentuh filesystem, "
    "sebagian besar waktu dari start-up proses, bukan kriptografi.")
    add("")
    return "\n".join(lines)


def cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=RUNS)
    parser.add_argument("--warmup", type=int, default=WARMUP)
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args(argv[1:])

    environment = {
        "Python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "OpenSSL": ssl.OPENSSL_VERSION,
        "Platform": f"{platform.system()} {platform.machine()}",
        "CPU": cpu_model(),
    }

    results: dict = {
        "runs": args.runs,
        "warmup": args.warmup,
        "environment": environment,
        "profiles": [],
    }

    with tempfile.TemporaryDirectory(prefix="minisign-bench-") as directory:
        workdir = Path(directory)
        for profile in PROFILES:
            print(f"measuring {profile} ...", file=sys.stderr)
            results["profiles"].append(measure_profile(profile, workdir, args.runs, args.warmup))

    report = render(results)
    (args.out / "results.md").write_text(report, encoding="utf-8")
    (args.out / "results.json").write_text(
        json.dumps(results, indent=2) + "\n", encoding="utf-8"
    )
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
