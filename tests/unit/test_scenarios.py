# Assert exit code dan status yang dilaporkan
# U01, U14 pakai ketiga profil, sisanya hanya ed25519

from __future__ import annotations
import json
import pytest
from support import (
    BINARY,
    EMPTY,
    PACKAGE,
    PROFILES,
    TEXT,
    b64,
    canonical,
    manifest_of,
    read_bundle,
    result,
    run_tool,
    sign,
    signature_of,
    signed_release,
    trust_add,
    verify,
    write_bundle,
)

@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize(
    ("data", "name"),
    [(TEXT, "artifact.txt"), (BINARY, "artifact.bin"), (EMPTY, "empty.bin")],
    ids=["text", "binary", "empty"],
)
def test_u01(tmp_path, keyring, profile, data, name):
    '''Tandatangani dan verifikasi berkas teks, berkas biner, serta berkas kosong
    menggunakan kunci dan metadata yang sesuai.'''
    artifact, bundle, store = signed_release(tmp_path, keyring, profile, data, name)

    proc = verify(artifact, bundle, store)

    assert proc.returncode == 0, proc.stderr
    payload = result(proc)
    assert payload["valid"] is True
    assert payload["status"] == "OK"
    assert payload["algorithm"] == profile
    assert payload["keyid"] == keyring[profile]["keyid"]

def test_u02(tmp_path, keyring):
    '''Ubah satu byte artefak tanpa mengubah ukuran atau nama berkas.'''
    artifact, bundle, store = signed_release(tmp_path, keyring)
    payload = bytearray(artifact.read_bytes())
    payload[0] ^= 0x01
    artifact.write_bytes(bytes(payload))

    proc = verify(artifact, bundle, store)

    assert proc.returncode == 1
    assert result(proc)["status"] == "ARTIFACT_MISMATCH"

@pytest.mark.parametrize("mutation", ["append", "truncate"])
def test_u03(tmp_path, keyring, mutation):
    '''Tambahkan atau hapus byte pada artefak.'''
    artifact, bundle, store = signed_release(tmp_path, keyring)
    data = artifact.read_bytes()
    artifact.write_bytes(data + b"\x00" if mutation == "append" else data[:-1])

    proc = verify(artifact, bundle, store)

    assert proc.returncode == 1
    assert result(proc)["status"] == "ARTIFACT_MISMATCH"

def test_u04(tmp_path, keyring):
    '''Ubah versi pada manifest dan pertahankan aturan serialisasinya.
    Gunakan tanda tangan dari manifest sebelum diubah.'''
    artifact, bundle, store = signed_release(tmp_path, keyring)
    original = read_bundle(bundle)
    manifest = json.loads(manifest_of(original))
    manifest["version"] = "9.9.9"
    write_bundle(bundle, b64(canonical(manifest)), original["signature_b64"])

    proc = verify(artifact, bundle, store)

    assert proc.returncode == 1
    assert result(proc)["status"] == "INVALID_SIGNATURE"

def test_u05(tmp_path, keyring):
    '''Ubah satu bit tanda tangan. Pertahankan panjang tanda tangan
    dan gunakan encoding Base64 yang valid.'''
    artifact, bundle, store = signed_release(tmp_path, keyring)
    original = read_bundle(bundle)
    signature = bytearray(signature_of(original))
    signature[0] ^= 0x01
    assert len(signature) == len(signature_of(original))
    write_bundle(bundle, original["manifest_b64"], b64(bytes(signature)))

    proc = verify(artifact, bundle, store)

    assert proc.returncode == 1
    assert result(proc)["status"] == "INVALID_SIGNATURE"

def test_u06(tmp_path, keyring):
    '''Gunakan trust store kosong atau hapus kunci penerbit dari trust store sebelum verifikasi.'''
    artifact, bundle, store = signed_release(tmp_path, keyring)

    empty = tmp_path / "empty-trust.json"
    empty.write_text('{"schema":"minisign-trust/v1","keys":[]}', encoding="utf-8")
    proc = verify(artifact, bundle, empty)
    assert proc.returncode == 1
    assert result(proc)["status"] == "KEY_NOT_TRUSTED"

    removed = run_tool(
        "trust", "remove", "--keyid", keyring["ed25519"]["keyid"], "--store", store
    )
    assert removed.returncode == 0, removed.stderr
    proc = verify(artifact, bundle, store)
    assert proc.returncode == 1
    assert result(proc)["status"] == "KEY_NOT_TRUSTED"

def test_u07(tmp_path, keyring):
    '''Gunakan kunci yang hanya diizinkan untuk paket lain.'''
    artifact = tmp_path / "artifact.txt"
    artifact.write_bytes(TEXT)
    bundle = tmp_path / "bundle.json"
    store = tmp_path / "trust.json"

    assert sign(artifact, keyring["ed25519"]["key"], bundle).returncode == 0
    proc = trust_add(keyring["ed25519"]["pub"], "other-app", store)
    assert proc.returncode == 0, proc.stderr

    proc = verify(artifact, bundle, store)

    assert proc.returncode == 1
    assert result(proc)["status"] == "KEY_NOT_TRUSTED"

def test_u08(tmp_path, keyring):
    '''Verifikasi bundle sah dengan nama paket yang sesuai dan
    versi yang berbeda dari manifest.'''
    artifact, bundle, store = signed_release(tmp_path, keyring)

    proc = verify(artifact, bundle, store, version="2.0.0")

    assert proc.returncode == 1
    assert result(proc)["status"] == "METADATA_MISMATCH"

def test_u09(tmp_path, keyring):
    '''Ubah nama berkas artefak tanpa mengubah isinya.'''
    artifact, bundle, store = signed_release(tmp_path, keyring)
    renamed = tmp_path / "renamed.txt"
    renamed.write_bytes(artifact.read_bytes())

    proc = verify(renamed, bundle, store)

    assert proc.returncode == 1
    assert result(proc)["status"] == "METADATA_MISMATCH"

@pytest.mark.parametrize(
    "case", ["duplicate_field", "wrong_type", "invalid_base64", "oversized"]
)
def test_u10(tmp_path, keyring, case):
    '''Uji field duplikat, tipe data yang salah, Base64 yang tidak valid,
    dan manifest yang melebihi batas ukuran. Setiap kondisi diuji secara terpisah.'''
    artifact, bundle, store = signed_release(tmp_path, keyring)
    original = read_bundle(bundle)
    manifest = json.loads(manifest_of(original))

    if case == "duplicate_field":
        text = canonical(manifest).decode("utf-8")
        text = text.replace(
            '"package":"demo-app"', '"package":"demo-app","package":"demo-app"', 1
        )
        write_bundle(bundle, b64(text.encode("utf-8")), original["signature_b64"])
    elif case == "wrong_type":
        manifest["artifact"]["size"] = str(manifest["artifact"]["size"])
        write_bundle(bundle, b64(canonical(manifest)), original["signature_b64"])
    elif case == "invalid_base64":
        write_bundle(bundle, original["manifest_b64"], "not*valid*base64")
    else:
        oversized = b'{"schema":"minisign-manifest/v1"' + b" " * (16 * 1024) + b"}"
        assert len(oversized) > 16 * 1024
        write_bundle(bundle, b64(oversized), original["signature_b64"])

    proc = verify(artifact, bundle, store)

    assert proc.returncode == 1
    assert result(proc)["status"] == "FORMAT_ERROR"

def test_u11(tmp_path, keyring):
    '''Gunakan nilai string algorithm yang tidak didukung pada manifest.'''
    artifact, bundle, store = signed_release(tmp_path, keyring)
    original = read_bundle(bundle)
    manifest = json.loads(manifest_of(original))
    manifest["algorithm"] = "dsa-sha256"
    write_bundle(bundle, b64(canonical(manifest)), original["signature_b64"])

    proc = verify(artifact, bundle, store)

    assert proc.returncode == 1
    assert result(proc)["status"] == "UNSUPPORTED_ALGORITHM"

def test_u12(tmp_path, keyring, other_key):
    '''Tandatangani dengan kunci lain pada profil yang sama.
    Isi keyid sesuai kunci tersebut, tetapi jangan tambahkan kuncinya ke trust store.'''
    artifact = tmp_path / "artifact.txt"
    artifact.write_bytes(TEXT)
    bundle = tmp_path / "bundle.json"
    store = tmp_path / "trust.json"

    assert sign(artifact, other_key["key"], bundle).returncode == 0
    assert trust_add(keyring["ed25519"]["pub"], PACKAGE, store).returncode == 0
    assert json.loads(manifest_of(read_bundle(bundle)))["keyid"] == other_key["keyid"]

    proc = verify(artifact, bundle, store)

    assert proc.returncode == 1
    assert result(proc)["status"] == "KEY_NOT_TRUSTED"

def test_u13(tmp_path, keyring):
    '''Ubah white space dan urutan field pada JSON bundle.
    Pertahankan kedua string Base64 tanpa perubahan.'''
    artifact, bundle, store = signed_release(tmp_path, keyring)
    original = read_bundle(bundle)

    bundle.write_text(
        "{\n"
        f'  "signature_b64": "{original["signature_b64"]}",\n'
        '  "schema": "minisign-bundle/v1",\n'
        f'  "manifest_b64": "{original["manifest_b64"]}"\n'
        "}\n",
        encoding="utf-8",
    )

    proc = verify(artifact, bundle, store)

    assert proc.returncode == 0, proc.stderr
    assert result(proc)["status"] == "OK"

@pytest.mark.parametrize("profile", PROFILES)
def test_u14(tmp_path, keyring, profile):
    '''Tandatangani manifest yang identik sebanyak dua kali menggunakan kunci yang sama.
    Bandingkan kedua tanda tangan yang dihasilkan dan jelaskan apakah hasilnya identik atau berbeda
    berdasarkan karakteristik algoritma serta mekanisme pembangkitan randomness atau nonce yang digunakan.
    Kedua bundle wajib berhasil diverifikasi.'''
    artifact, bundle, store = signed_release(tmp_path, keyring, profile)
    second = tmp_path / "second-bundle.json"
    assert sign(artifact, keyring[profile]["key"], second).returncode == 0

    first_signature = signature_of(read_bundle(bundle))
    second_signature = signature_of(read_bundle(second))

    if profile == "ed25519":
        # Ed25519 (RFC 8032) derives its nonce from the key and message.
        assert first_signature == second_signature
    else:
        # RSA-PSS draws a fresh 32-byte salt; ECDSA draws a fresh nonce.
        assert first_signature != second_signature

    for candidate in (bundle, second):
        proc = verify(artifact, candidate, store)
        assert proc.returncode == 0, proc.stderr
        assert result(proc)["status"] == "OK"