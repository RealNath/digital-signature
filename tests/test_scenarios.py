from __future__ import annotations

import base64
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src import bundle, keys, main, manifest, signing


def find_openssl() -> str | None:
    found = shutil.which("openssl")
    if found:
        return found
    git_openssl = Path(r"C:\Program Files\Git\usr\bin\openssl.exe")
    if git_openssl.exists():
        return str(git_openssl)
    return None


def run_cli(argv: list[str]) -> tuple[int, str, str]:
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = main.main(argv)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 2
    return code, out.getvalue(), err.getvalue()


class TestSpecificationScenarios(unittest.TestCase):
    # Pengujian skenario minimum Tabel 2.11 (U01-U14) dan Interoperabilitas.

    @classmethod
    def setUpClass(cls) -> None:
        # Membangkitkan pasangan kunci sekali per kelas untuk mempercepat pengujian RSA-3072.
        cls.keypairs: dict[str, tuple[bytes, bytes, str]] = {}
        cls.alt_keypairs: dict[str, tuple[bytes, bytes, str]] = {}
        for alg in manifest.ALGORITHMS:
            cls.keypairs[alg] = keys.generate_keypair(alg)
            cls.alt_keypairs[alg] = keys.generate_keypair(alg)

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.workdir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write_keypair(self, alg: str, prefix_name: str = "publisher", alt: bool = False) -> tuple[Path, Path, str]:
        priv_pem, pub_pem, keyid = (self.alt_keypairs if alt else self.keypairs)[alg]
        priv_path = self.workdir / f"{prefix_name}.key.pem"
        pub_path = self.workdir / f"{prefix_name}.pub.pem"
        priv_path.write_bytes(priv_pem)
        pub_path.write_bytes(pub_pem)
        return priv_path, pub_path, keyid

    def test_u01_sign_and_verify_text_binary_empty_all_algorithms(self) -> None:
        # U01: Tandatangani dan verifikasi berkas teks, biner, dan kosong pada ketiga algoritma.
        artifacts = {
            "release-notes.txt": b"Release v1.0.0\nSigned software release notes.\n",
            "firmware.bin": bytes(range(256)) * 16 + os.urandom(512),
            "empty.dat": b"",
        }
        for alg in manifest.ALGORITHMS:
            with self.subTest(algorithm=alg):
                priv_path, pub_path, keyid = self.write_keypair(alg, f"pub-{alg}")
                store_path = self.workdir / f"trust-{alg}.json"
                code, out, err = run_cli([
                    "trust", "add",
                    "--key", str(pub_path),
                    "--package", "contoh-app",
                    "--store", str(store_path),
                ])
                self.assertEqual(code, 0, err)
                self.assertEqual(out.strip(), f"{keyid} {alg} contoh-app")

                for filename, payload in artifacts.items():
                    with self.subTest(algorithm=alg, artifact=filename):
                        art_path = self.workdir / filename
                        art_path.write_bytes(payload)
                        bundle_path = self.workdir / f"{alg}-{filename}.bundle.json"

                        code, _, err = run_cli([
                            "sign",
                            "--file", str(art_path),
                            "--package", "contoh-app",
                            "--version", "1.0.0",
                            "--key", str(priv_path),
                            "--out", str(bundle_path),
                        ])
                        self.assertEqual(code, 0, err)

                        code, out, err = run_cli([
                            "verify",
                            "--file", str(art_path),
                            "--bundle", str(bundle_path),
                            "--trust-store", str(store_path),
                            "--package", "contoh-app",
                            "--version", "1.0.0",
                            "--json",
                        ])
                        self.assertEqual(code, 0, err)
                        res = json.loads(out)
                        self.assertTrue(res["valid"])
                        self.assertEqual(res["status"], "OK")
                        self.assertEqual(res["algorithm"], alg)
                        self.assertEqual(res["keyid"], keyid)
                        self.assertEqual(res["package"], "contoh-app")
                        self.assertEqual(res["version"], "1.0.0")

    def test_u02_modify_one_byte_artifact_same_size(self) -> None:
        # U02: Ubah satu byte artefak tanpa mengubah ukuran atau nama berkas.
        priv_path, pub_path, _ = self.write_keypair("ed25519")
        store_path = self.workdir / "trust.json"
        art_path = self.workdir / "contoh-app.zip"
        bundle_path = self.workdir / "release.json"
        art_path.write_bytes(b"ABCDEF0123456789")

        run_cli(["trust", "add", "--key", str(pub_path), "--package", "contoh-app", "--store", str(store_path)])
        run_cli([
            "sign", "--file", str(art_path), "--package", "contoh-app",
            "--version", "1.0.0", "--key", str(priv_path), "--out", str(bundle_path),
        ])

        # Mengubah 1 byte tanpa mengubah ukuran atau nama berkas.
        art_path.write_bytes(b"XBCDEF0123456789")

        code, out, _ = run_cli([
            "verify", "--file", str(art_path), "--bundle", str(bundle_path),
            "--trust-store", str(store_path), "--package", "contoh-app", "--version", "1.0.0", "--json",
        ])
        self.assertEqual(code, 1)
        res = json.loads(out)
        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "ARTIFACT_MISMATCH")

    def test_u03_add_or_remove_byte_on_artifact(self) -> None:
        # U03: Tambahkan atau hapus byte pada artefak.
        priv_path, pub_path, _ = self.write_keypair("ecdsa-p256-sha256")
        store_path = self.workdir / "trust.json"
        art_path = self.workdir / "contoh-app.zip"
        bundle_path = self.workdir / "release.json"
        original = b"artifact-binary-content"
        art_path.write_bytes(original)

        run_cli(["trust", "add", "--key", str(pub_path), "--package", "contoh-app", "--store", str(store_path)])
        run_cli([
            "sign", "--file", str(art_path), "--package", "contoh-app",
            "--version", "1.0.0", "--key", str(priv_path), "--out", str(bundle_path),
        ])

        for mutated in (original + b"!", original[:-1]):
            art_path.write_bytes(mutated)
            code, out, _ = run_cli([
                "verify", "--file", str(art_path), "--bundle", str(bundle_path),
                "--trust-store", str(store_path), "--package", "contoh-app", "--version", "1.0.0", "--json",
            ])
            self.assertEqual(code, 1)
            res = json.loads(out)
            self.assertFalse(res["valid"])
            self.assertEqual(res["status"], "ARTIFACT_MISMATCH")

    def test_u04_modify_manifest_version_keep_old_signature(self) -> None:
        # U04: Ubah versi pada manifest dengan serialisasi canonical dan pertahankan tanda tangan lama.
        priv_path, pub_path, _ = self.write_keypair("ed25519")
        store_path = self.workdir / "trust.json"
        art_path = self.workdir / "contoh-app.zip"
        bundle_path = self.workdir / "release.json"
        art_path.write_bytes(b"payload")

        run_cli(["trust", "add", "--key", str(pub_path), "--package", "contoh-app", "--store", str(store_path)])
        run_cli([
            "sign", "--file", str(art_path), "--package", "contoh-app",
            "--version", "1.0.0", "--key", str(priv_path), "--out", str(bundle_path),
        ])

        manifest_bytes, sig = bundle.parse_bundle(bundle_path.read_bytes())
        parsed_manifest = manifest.parse_manifest(manifest_bytes)
        parsed_manifest["version"] = "1.0.1"
        tampered_manifest_bytes = manifest.serialize_manifest(parsed_manifest)
        bundle_path.write_bytes(bundle.build_bundle(tampered_manifest_bytes, sig))

        code, out, _ = run_cli([
            "verify", "--file", str(art_path), "--bundle", str(bundle_path),
            "--trust-store", str(store_path), "--package", "contoh-app", "--version", "1.0.1", "--json",
        ])
        self.assertEqual(code, 1)
        res = json.loads(out)
        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "INVALID_SIGNATURE")

    def test_u05_flip_one_bit_in_signature(self) -> None:
        # U05: Ubah satu bit tanda tangan dengan tetap mempertahankan panjang dan Base64 valid.
        for alg in manifest.ALGORITHMS:
            with self.subTest(algorithm=alg):
                priv_path, pub_path, _ = self.write_keypair(alg, f"u05-{alg}")
                store_path = self.workdir / f"trust-{alg}.json"
                art_path = self.workdir / "contoh-app.zip"
                bundle_path = self.workdir / f"release-{alg}.json"
                art_path.write_bytes(b"payload-u05")

                run_cli(["trust", "add", "--key", str(pub_path), "--package", "contoh-app", "--store", str(store_path)])
                run_cli([
                    "sign", "--file", str(art_path), "--package", "contoh-app",
                    "--version", "1.0.0", "--key", str(priv_path), "--out", str(bundle_path),
                ])

                m_bytes, sig = bundle.parse_bundle(bundle_path.read_bytes())
                flipped_sig = bytes([sig[0] ^ 0x01]) + sig[1:]
                self.assertEqual(len(flipped_sig), len(sig))
                bundle_path.write_bytes(bundle.build_bundle(m_bytes, flipped_sig))

                code, out, _ = run_cli([
                    "verify", "--file", str(art_path), "--bundle", str(bundle_path),
                    "--trust-store", str(store_path), "--package", "contoh-app", "--version", "1.0.0", "--json",
                ])
                self.assertEqual(code, 1)
                res = json.loads(out)
                self.assertFalse(res["valid"])
                self.assertEqual(res["status"], "INVALID_SIGNATURE")

    def test_u06_empty_trust_store_or_removed_key(self) -> None:
        # U06: Gunakan trust store kosong atau hapus kunci penerbit dari trust store sebelum verifikasi.
        priv_path, pub_path, keyid = self.write_keypair("ed25519")
        store_path = self.workdir / "trust.json"
        art_path = self.workdir / "contoh-app.zip"
        bundle_path = self.workdir / "release.json"
        art_path.write_bytes(b"payload-u06")

        run_cli(["trust", "add", "--key", str(pub_path), "--package", "contoh-app", "--store", str(store_path)])
        run_cli([
            "sign", "--file", str(art_path), "--package", "contoh-app",
            "--version", "1.0.0", "--key", str(priv_path), "--out", str(bundle_path),
        ])

        # Menghapus kunci dengan trust remove
        code, _, err = run_cli(["trust", "remove", "--keyid", keyid, "--store", str(store_path)])
        self.assertEqual(code, 0, err)

        code, out, _ = run_cli([
            "verify", "--file", str(art_path), "--bundle", str(bundle_path),
            "--trust-store", str(store_path), "--package", "contoh-app", "--version", "1.0.0", "--json",
        ])
        self.assertEqual(code, 1)
        res = json.loads(out)
        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "KEY_NOT_TRUSTED")

    def test_u07_key_authorized_only_for_other_package(self) -> None:
        # U07: Gunakan kunci yang hanya diizinkan untuk paket lain.
        priv_path, pub_path, _ = self.write_keypair("ed25519")
        store_path = self.workdir / "trust.json"
        art_path = self.workdir / "contoh-app.zip"
        bundle_path = self.workdir / "release.json"
        art_path.write_bytes(b"payload-u07")

        run_cli(["trust", "add", "--key", str(pub_path), "--package", "paket-lain", "--store", str(store_path)])
        run_cli([
            "sign", "--file", str(art_path), "--package", "contoh-app",
            "--version", "1.0.0", "--key", str(priv_path), "--out", str(bundle_path),
        ])

        code, out, _ = run_cli([
            "verify", "--file", str(art_path), "--bundle", str(bundle_path),
            "--trust-store", str(store_path), "--package", "contoh-app", "--version", "1.0.0", "--json",
        ])
        self.assertEqual(code, 1)
        res = json.loads(out)
        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "KEY_NOT_TRUSTED")

    def test_u08_verify_valid_bundle_with_different_version(self) -> None:
        # U08: Verifikasi bundle sah dengan nama paket yang sesuai dan versi yang berbeda dari manifest.
        priv_path, pub_path, _ = self.write_keypair("ed25519")
        store_path = self.workdir / "trust.json"
        art_path = self.workdir / "contoh-app.zip"
        bundle_path = self.workdir / "release.json"
        art_path.write_bytes(b"payload-u08")

        run_cli(["trust", "add", "--key", str(pub_path), "--package", "contoh-app", "--store", str(store_path)])
        run_cli([
            "sign", "--file", str(art_path), "--package", "contoh-app",
            "--version", "1.0.0", "--key", str(priv_path), "--out", str(bundle_path),
        ])

        code, out, _ = run_cli([
            "verify", "--file", str(art_path), "--bundle", str(bundle_path),
            "--trust-store", str(store_path), "--package", "contoh-app", "--version", "2.0.0", "--json",
        ])
        self.assertEqual(code, 1)
        res = json.loads(out)
        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "METADATA_MISMATCH")

    def test_u09_rename_artifact_file_without_changing_content(self) -> None:
        # U09: Ubah nama berkas artefak tanpa mengubah isinya.
        priv_path, pub_path, _ = self.write_keypair("ed25519")
        store_path = self.workdir / "trust.json"
        art_path = self.workdir / "contoh-app.zip"
        renamed_path = self.workdir / "renamed-app.zip"
        bundle_path = self.workdir / "release.json"
        art_path.write_bytes(b"payload-u09")
        renamed_path.write_bytes(b"payload-u09")

        run_cli(["trust", "add", "--key", str(pub_path), "--package", "contoh-app", "--store", str(store_path)])
        run_cli([
            "sign", "--file", str(art_path), "--package", "contoh-app",
            "--version", "1.0.0", "--key", str(priv_path), "--out", str(bundle_path),
        ])

        code, out, _ = run_cli([
            "verify", "--file", str(renamed_path), "--bundle", str(bundle_path),
            "--trust-store", str(store_path), "--package", "contoh-app", "--version", "1.0.0", "--json",
        ])
        self.assertEqual(code, 1)
        res = json.loads(out)
        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "METADATA_MISMATCH")

    def test_u10_format_errors_duplicate_field_wrong_type_invalid_b64_oversize_manifest(self) -> None:
        # U10: Uji field duplikat, tipe data salah, Base64 tidak valid, dan manifest > 16 KiB secara terpisah.
        priv_path, pub_path, _ = self.write_keypair("ed25519")
        store_path = self.workdir / "trust.json"
        art_path = self.workdir / "contoh-app.zip"
        valid_bundle_path = self.workdir / "release.json"
        art_path.write_bytes(b"payload-u10")

        run_cli(["trust", "add", "--key", str(pub_path), "--package", "contoh-app", "--store", str(store_path)])
        run_cli([
            "sign", "--file", str(art_path), "--package", "contoh-app",
            "--version", "1.0.0", "--key", str(priv_path), "--out", str(valid_bundle_path),
        ])
        valid_bundle_obj = json.loads(valid_bundle_path.read_text("utf-8"))
        manifest_bytes, sig_bytes = bundle.parse_bundle(valid_bundle_path.read_bytes())
        manifest_obj = manifest.parse_manifest(manifest_bytes)

        # 1. Field duplikat pada bundle JSON
        dup_bundle_path = self.workdir / "dup-bundle.json"
        dup_bundle_path.write_bytes(
            b'{"schema":"minisign-bundle/v1","schema":"minisign-bundle/v1",'
            + f'"manifest_b64":"{valid_bundle_obj["manifest_b64"]}",'
            f'"signature_b64":"{valid_bundle_obj["signature_b64"]}"}}'.encode("ascii")
        )
        code, out, _ = run_cli([
            "verify", "--file", str(art_path), "--bundle", str(dup_bundle_path),
            "--trust-store", str(store_path), "--package", "contoh-app", "--version", "1.0.0", "--json",
        ])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["status"], "FORMAT_ERROR")

        # 2. Tipe data salah pada manifest (size bertipe boolean true)
        bad_type_manifest = dict(manifest_obj)
        bad_type_manifest["artifact"] = dict(manifest_obj["artifact"], size=True)
        bad_type_bytes = json.dumps(bad_type_manifest, separators=(",", ":")).encode("utf-8")
        bad_type_bundle = self.workdir / "bad-type-bundle.json"
        bad_type_bundle.write_bytes(bundle.build_bundle(bad_type_bytes, sig_bytes))
        code, out, _ = run_cli([
            "verify", "--file", str(art_path), "--bundle", str(bad_type_bundle),
            "--trust-store", str(store_path), "--package", "contoh-app", "--version", "1.0.0", "--json",
        ])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["status"], "FORMAT_ERROR")

        # 3. Base64 tidak valid
        bad_b64_bundle = self.workdir / "bad-b64-bundle.json"
        bad_b64_bundle.write_text(json.dumps({
            "schema": "minisign-bundle/v1",
            "manifest_b64": valid_bundle_obj["manifest_b64"],
            "signature_b64": "!!!not_valid_base64!!!",
        }), encoding="utf-8")
        code, out, _ = run_cli([
            "verify", "--file", str(art_path), "--bundle", str(bad_b64_bundle),
            "--trust-store", str(store_path), "--package", "contoh-app", "--version", "1.0.0", "--json",
        ])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["status"], "FORMAT_ERROR")

        # 4. Manifest melebihi batas ukuran 16 KiB (16384 byte)
        oversize_manifest = (
            b'{"schema":"minisign-manifest/v1","package":"contoh-app","version":"1.0.0","algorithm":"'
            + (b"a" * 16400)
            + b'","keyid":"' + manifest_obj["keyid"].encode("ascii") + b'","artifact":{"name":"contoh-app.zip","size":11,"sha256":"'
            + manifest_obj["artifact"]["sha256"].encode("ascii") + b'"}}'
        )
        self.assertGreater(len(oversize_manifest), manifest.MAX_MANIFEST_BYTES)
        oversize_bundle = self.workdir / "oversize-manifest-bundle.json"
        oversize_bundle.write_bytes(bundle.build_bundle(oversize_manifest, sig_bytes))
        code, out, _ = run_cli([
            "verify", "--file", str(art_path), "--bundle", str(oversize_bundle),
            "--trust-store", str(store_path), "--package", "contoh-app", "--version", "1.0.0", "--json",
        ])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["status"], "FORMAT_ERROR")

    def test_u11_unsupported_algorithm_in_manifest(self) -> None:
        # U11: Gunakan nilai string algorithm yang tidak didukung pada manifest.
        priv_path, pub_path, _ = self.write_keypair("ed25519")
        store_path = self.workdir / "trust.json"
        art_path = self.workdir / "contoh-app.zip"
        bundle_path = self.workdir / "release.json"
        art_path.write_bytes(b"payload-u11")

        run_cli(["trust", "add", "--key", str(pub_path), "--package", "contoh-app", "--store", str(store_path)])
        run_cli([
            "sign", "--file", str(art_path), "--package", "contoh-app",
            "--version", "1.0.0", "--key", str(priv_path), "--out", str(bundle_path),
        ])

        m_bytes, sig = bundle.parse_bundle(bundle_path.read_bytes())
        m_obj = manifest.parse_manifest(m_bytes)
        m_obj["algorithm"] = "rsa-pkcs1-v1_5-sha256"
        new_m_bytes = manifest.serialize_manifest(m_obj)
        bundle_path.write_bytes(bundle.build_bundle(new_m_bytes, sig))

        code, out, _ = run_cli([
            "verify", "--file", str(art_path), "--bundle", str(bundle_path),
            "--trust-store", str(store_path), "--package", "contoh-app", "--version", "1.0.0", "--json",
        ])
        self.assertEqual(code, 1)
        res = json.loads(out)
        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "UNSUPPORTED_ALGORITHM")
        self.assertEqual(res["algorithm"], "rsa-pkcs1-v1_5-sha256")

    def test_u12_signed_with_untrusted_key_same_profile(self) -> None:
        # U12: Tandatangani dengan kunci lain pada profil yang sama yang tidak ada di trust store.
        _, trusted_pub_path, _ = self.write_keypair("ed25519", "trusted", alt=False)
        untrusted_priv_path, _, untrusted_keyid = self.write_keypair("ed25519", "untrusted", alt=True)
        store_path = self.workdir / "trust.json"
        art_path = self.workdir / "contoh-app.zip"
        bundle_path = self.workdir / "release.json"
        art_path.write_bytes(b"payload-u12")

        run_cli(["trust", "add", "--key", str(trusted_pub_path), "--package", "contoh-app", "--store", str(store_path)])
        run_cli([
            "sign", "--file", str(art_path), "--package", "contoh-app",
            "--version", "1.0.0", "--key", str(untrusted_priv_path), "--out", str(bundle_path),
        ])

        code, out, _ = run_cli([
            "verify", "--file", str(art_path), "--bundle", str(bundle_path),
            "--trust-store", str(store_path), "--package", "contoh-app", "--version", "1.0.0", "--json",
        ])
        self.assertEqual(code, 1)
        res = json.loads(out)
        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "KEY_NOT_TRUSTED")
        self.assertEqual(res["keyid"], untrusted_keyid)

    def test_u13_reorder_fields_and_whitespace_in_bundle_json(self) -> None:
        # U13: Ubah white space dan urutan field pada JSON bundle tanpa mengubah kedua string Base64.
        priv_path, pub_path, _ = self.write_keypair("ed25519")
        store_path = self.workdir / "trust.json"
        art_path = self.workdir / "contoh-app.zip"
        bundle_path = self.workdir / "release.json"
        art_path.write_bytes(b"payload-u13")

        run_cli(["trust", "add", "--key", str(pub_path), "--package", "contoh-app", "--store", str(store_path)])
        run_cli([
            "sign", "--file", str(art_path), "--package", "contoh-app",
            "--version", "1.0.0", "--key", str(priv_path), "--out", str(bundle_path),
        ])

        raw = json.loads(bundle_path.read_text("utf-8"))
        reformatted = (
            "{\n"
            f'  "signature_b64" : "{raw["signature_b64"]}",\n'
            f'  "manifest_b64"  : "{raw["manifest_b64"]}",\n'
            f'  "schema"        : "{raw["schema"]}"\n'
            "}\n"
        )
        bundle_path.write_text(reformatted, encoding="utf-8")

        code, out, _ = run_cli([
            "verify", "--file", str(art_path), "--bundle", str(bundle_path),
            "--trust-store", str(store_path), "--package", "contoh-app", "--version", "1.0.0", "--json",
        ])
        self.assertEqual(code, 0)
        res = json.loads(out)
        self.assertTrue(res["valid"])
        self.assertEqual(res["status"], "OK")

    def test_u14_sign_identical_manifest_twice_all_algorithms(self) -> None:
        # U14: Tandatangani manifest identik dua kali dengan kunci yang sama pada ketiga algoritma.
        art_path = self.workdir / "contoh-app.zip"
        art_path.write_bytes(b"payload-u14-determinism-vs-randomness")

        for alg in manifest.ALGORITHMS:
            with self.subTest(algorithm=alg):
                priv_path, pub_path, _ = self.write_keypair(alg, f"u14-{alg}")
                store_path = self.workdir / f"trust-{alg}.json"
                bundle1_path = self.workdir / f"b1-{alg}.json"
                bundle2_path = self.workdir / f"b2-{alg}.json"

                run_cli(["trust", "add", "--key", str(pub_path), "--package", "contoh-app", "--store", str(store_path)])
                for bpath in (bundle1_path, bundle2_path):
                    code, _, err = run_cli([
                        "sign", "--file", str(art_path), "--package", "contoh-app",
                        "--version", "1.0.0", "--key", str(priv_path), "--out", str(bpath),
                    ])
                    self.assertEqual(code, 0, err)

                m1, sig1 = bundle.parse_bundle(bundle1_path.read_bytes())
                m2, sig2 = bundle.parse_bundle(bundle2_path.read_bytes())
                self.assertEqual(m1, m2)

                if alg == "ed25519":
                    # Ed25519 (RFC 8032) membangkitkan nonce deterministik via SHA-512(prefix || M)
                    self.assertEqual(sig1, sig2)
                else:
                    # RSA-PSS (32-byte random salt) dan ECDSA P-256 (CSPRNG nonce) menghasilkan signature berbeda
                    self.assertNotEqual(sig1, sig2)

                for bpath in (bundle1_path, bundle2_path):
                    code, out, _ = run_cli([
                        "verify", "--file", str(art_path), "--bundle", str(bpath),
                        "--trust-store", str(store_path), "--package", "contoh-app", "--version", "1.0.0", "--json",
                    ])
                    self.assertEqual(code, 0)
                    self.assertEqual(json.loads(out)["status"], "OK")

    def test_interoperability_with_openssl_all_algorithms(self) -> None:
        # Uji interoperabilitas dua arah dengan OpenSSL CLI untuk ketiga algoritma.
        openssl_bin = find_openssl()
        if openssl_bin is None:
            self.skipTest("OpenSSL CLI tidak ditemukan pada sistem")

        art_path = self.workdir / "interop.bin"
        art_path.write_bytes(b"interoperability-test-artifact-bytes")

        for alg in manifest.ALGORITHMS:
            with self.subTest(algorithm=alg):
                priv_path, pub_path, keyid = self.write_keypair(alg, f"interop-{alg}")
                store_path = self.workdir / f"interop-trust-{alg}.json"
                bundle_path = self.workdir / f"interop-bundle-{alg}.json"

                run_cli(["trust", "add", "--key", str(pub_path), "--package", "interop-pkg", "--store", str(store_path)])
                run_cli([
                    "sign", "--file", str(art_path), "--package", "interop-pkg",
                    "--version", "1.0.0", "--key", str(priv_path), "--out", str(bundle_path),
                ])

                m_bytes, sig_bytes = bundle.parse_bundle(bundle_path.read_bytes())
                m_file = self.workdir / f"manifest-{alg}.bin"
                sig_file = self.workdir / f"sig-{alg}.bin"
                m_file.write_bytes(m_bytes)

                # Arah 1: Tandatangani dengan minisign, verifikasi dengan OpenSSL CLI
                if alg == "rsa-pss-sha256":
                    sig_file.write_bytes(sig_bytes)
                    proc = subprocess.run(
                        [
                            openssl_bin, "dgst", "-sha256",
                            "-verify", str(pub_path),
                            "-sigopt", "rsa_padding_mode:pss",
                            "-sigopt", "rsa_pss_saltlen:32",
                            "-sigopt", "rsa_mgf1_md:sha256",
                            "-signature", str(sig_file),
                            str(m_file),
                        ],
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                elif alg == "ecdsa-p256-sha256":
                    # Konversi r || s (64 byte) -> ASN.1 DER untuk OpenSSL
                    r = int.from_bytes(sig_bytes[:32], "big")
                    s = int.from_bytes(sig_bytes[32:], "big")
                    sig_file.write_bytes(encode_dss_signature(r, s))
                    proc = subprocess.run(
                        [
                            openssl_bin, "dgst", "-sha256",
                            "-verify", str(pub_path),
                            "-signature", str(sig_file),
                            str(m_file),
                        ],
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                elif alg == "ed25519":
                    sig_file.write_bytes(sig_bytes)
                    proc = subprocess.run(
                        [
                            openssl_bin, "pkeyutl", "-verify",
                            "-pubin", "-inkey", str(pub_path),
                            "-rawin", "-in", str(m_file),
                            "-sigfile", str(sig_file),
                        ],
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(proc.returncode, 0, proc.stderr)

                # Arah 2: Tandatangani dengan OpenSSL CLI, verifikasi dengan minisign
                ext_sig_file = self.workdir / f"ext-sig-{alg}.bin"
                if alg == "rsa-pss-sha256":
                    subprocess.run(
                        [
                            openssl_bin, "dgst", "-sha256",
                            "-sign", str(priv_path),
                            "-sigopt", "rsa_padding_mode:pss",
                            "-sigopt", "rsa_pss_saltlen:32",
                            "-sigopt", "rsa_mgf1_md:sha256",
                            "-out", str(ext_sig_file),
                            str(m_file),
                        ],
                        check=True, capture_output=True,
                    )
                    ext_sig = ext_sig_file.read_bytes()
                elif alg == "ecdsa-p256-sha256":
                    subprocess.run(
                        [
                            openssl_bin, "dgst", "-sha256",
                            "-sign", str(priv_path),
                            "-out", str(ext_sig_file),
                            str(m_file),
                        ],
                        check=True, capture_output=True,
                    )
                    r, s = decode_dss_signature(ext_sig_file.read_bytes())
                    ext_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
                else:
                    subprocess.run(
                        [
                            openssl_bin, "pkeyutl", "-sign",
                            "-inkey", str(priv_path),
                            "-rawin", "-in", str(m_file),
                            "-out", str(ext_sig_file),
                        ],
                        check=True, capture_output=True,
                    )
                    ext_sig = ext_sig_file.read_bytes()

                ext_bundle_path = self.workdir / f"ext-bundle-{alg}.json"
                ext_bundle_path.write_bytes(bundle.build_bundle(m_bytes, ext_sig))
                code, out, _ = run_cli([
                    "verify", "--file", str(art_path), "--bundle", str(ext_bundle_path),
                    "--trust-store", str(store_path), "--package", "interop-pkg", "--version", "1.0.0", "--json",
                ])
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(out)["status"], "OK")

    def test_key_validation_and_pem_line_ending_invariance(self) -> None:
        # Memastikan CRLF/pemenggalan PEM tidak mengubah keyid dan format kunci non-SPKI/kompresi ditolak.
        _, pub_pem, keyid = self.keypairs["ecdsa-p256-sha256"]
        crlf_pem = pub_pem.replace(b"\n", b"\r\n")
        pub_key = keys.load_public_key(crlf_pem)
        self.assertEqual(keys.fingerprint(pub_key), keyid)

        # Kunci publik dengan titik EC terkompresi pada SPKI wajib ditolak
        compressed_point = pub_key.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
        )
        spki_header = bytes.fromhex("3039301306072a8648ce3d020106082a8648ce3d030107032200")
        compressed_spki_b64 = base64.b64encode(spki_header + compressed_point).decode("ascii")
        compressed_pem = f"-----BEGIN PUBLIC KEY-----\n{compressed_spki_b64}\n-----END PUBLIC KEY-----\n".encode("ascii")
        with self.assertRaises(ValueError):
            keys.load_public_key(compressed_pem)

        # Kunci RSA dengan ukuran salah (2048 bit) wajib ditolak
        rsa2048 = rsa.generate_private_key(65537, 2048)
        rsa2048_pem = rsa2048.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        with self.assertRaises(ValueError):
            keys.load_private_key(rsa2048_pem)

    def test_cli_input_errors_and_verify_json_on_missing_args(self) -> None:
        # Pastikan kegagalan argumen atau berkas hilang pada verify --json menghasilkan INPUT_ERROR dan exit code 2.
        code, out, _ = run_cli(["verify", "--json"])
        self.assertEqual(code, 2)
        res = json.loads(out)
        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "INPUT_ERROR")

        # Berkas masukan tidak tersedia (C04)
        code, out, _ = run_cli([
            "verify",
            "--file", str(self.workdir / "missing.zip"),
            "--bundle", str(self.workdir / "missing-bundle.json"),
            "--trust-store", str(self.workdir / "missing-trust.json"),
            "--package", "contoh-app",
            "--version", "1.0.0",
            "--json",
        ])
        self.assertEqual(code, 2)
        res = json.loads(out)
        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "INPUT_ERROR")

    def test_keygen_overwrite_protection_and_trust_commands(self) -> None:
        # Pastikan keygen menolak menimpa kunci tanpa --force, dan trust add/list/remove sesuai kontrak.
        prefix = self.workdir / "keys" / "testkey"
        code, out, err = run_cli(["keygen", "--algorithm", "ed25519", "--out", str(prefix)])
        self.assertEqual(code, 0, err)
        first_keyid = out.strip()
        self.assertEqual(len(first_keyid), 64)

        # Tanpa --force wajib ditolak dengan exit code 2
        code, _, _ = run_cli(["keygen", "--algorithm", "ed25519", "--out", str(prefix)])
        self.assertEqual(code, 2)

        # Dengan --force diperbolehkan menimpa
        code, out, err = run_cli(["keygen", "--algorithm", "ed25519", "--out", str(prefix), "--force"])
        self.assertEqual(code, 0, err)
        second_keyid = out.strip()
        self.assertNotEqual(first_keyid, second_keyid)

        # trust add idempoten & multi-package
        store_path = self.workdir / "trust.json"
        pub_path = Path(f"{prefix}.pub.pem")
        code, out, _ = run_cli(["trust", "add", "--key", str(pub_path), "--package", "pkg-a", "--store", str(store_path)])
        self.assertEqual(code, 0)
        code, out, _ = run_cli(["trust", "add", "--key", str(pub_path), "--package", "pkg-a", "--store", str(store_path)])
        self.assertEqual(code, 0)
        code, out, _ = run_cli(["trust", "add", "--key", str(pub_path), "--package", "pkg-b", "--store", str(store_path)])
        self.assertEqual(code, 0)

        code, out, _ = run_cli(["trust", "list", "--store", str(store_path)])
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), f"{second_keyid} ed25519 pkg-a,pkg-b")

        # trust remove dengan keyid yang tidak ada -> exit code 2
        code, _, _ = run_cli(["trust", "remove", "--keyid", "0" * 64, "--store", str(store_path)])
        self.assertEqual(code, 2)

    def test_ecdsa_high_s_and_out_of_domain_scalars(self) -> None:
        # Pastikan ECDSA menerima baik low-S maupun non-low-S, dan menolak r/s di luar domain [1, n-1].
        p256_order = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        priv_pem, pub_pem, _ = self.keypairs["ecdsa-p256-sha256"]
        priv = keys.load_private_key(priv_pem)
        pub = keys.load_public_key(pub_pem)
        msg = b"manifest-bytes-for-ecdsa-domain-check"
        sig = signing.sign(priv, msg)
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")

        # Tanda tangan dengan (r, n - s) tetap valid menurut ECDSA P-256
        alt_s = p256_order - s
        alt_sig = r.to_bytes(32, "big") + alt_s.to_bytes(32, "big")
        self.assertTrue(signing.verify(pub, msg, alt_sig))

        # r = 0, s = 0, r = n, s = n wajib ditolak (INVALID_SIGNATURE)
        for bad_r, bad_s in ((0, s), (r, 0), (p256_order, s), (r, p256_order)):
            bad_sig = bad_r.to_bytes(32, "big") + bad_s.to_bytes(32, "big")
            self.assertFalse(signing.verify(pub, msg, bad_sig))


if __name__ == "__main__":
    unittest.main()
