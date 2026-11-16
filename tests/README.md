# Pengujian

| Skenario | Lokasi | Sasaran |
| --- | --- | --- |
| Unit U01–U14 | `tests/unit/` | CLI `python3 -m src.minisign` |
| Integrasi C01–C05 | `tests/ci/` | Container image (digest tetap) |
| Interop | `tests/interop/` | OpenSSL |

## Cara Menjalankan

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest tests/unit -q      # 28 passed
bash tests/interop/openssl.sh
```

Tiap tes menjalankan program dan memeriksa exit code serta `status` dari
`verify --json`. Keypair dibuat baru di folder sementara tiap sesi, jadi tidak ada kunci yang di-commit.

## Skenario unit

| ID | Input | Hasil |
| --- | --- | --- |
| U01 | Artefak teks, binary, kosong. Ketiga profil | `OK`, exit 0 |
| U02 | 1 byte artefak diubah, nama dan ukuran tetap | `ARTIFACT_MISMATCH`, exit 1 |
| U03 | 1 byte ditambah/dihapus | `ARTIFACT_MISMATCH`, exit 1 |
| U04 | `version` manifest diubah, signature lama dipakai | `INVALID_SIGNATURE`, exit 1 |
| U05 | 1 bit signature dibalik | `INVALID_SIGNATURE`, exit 1 |
| U06 | Trust store kosong, lalu kunci dihapus | `KEY_NOT_TRUSTED`, exit 1 |
| U07 | Kunci hanya dipercaya untuk paket lain | `KEY_NOT_TRUSTED`, exit 1 |
| U08 | `--version` berbeda dari manifest | `METADATA_MISMATCH`, exit 1 |
| U09 | Rename artefak, isi sama | `METADATA_MISMATCH`, exit 1 |
| U10 | Field duplikat, tipe salah, Base64 rusak, manifest > 16 KiB | `FORMAT_ERROR`, exit 1 |
| U11 | `algorithm` tidak didukung | `UNSUPPORTED_ALGORITHM`, exit 1 |
| U12 | Bundle ditandatangani kunci di luar trust store | `KEY_NOT_TRUSTED`, exit 1 |
| U13 | Bundle dirapikan ulang (spasi, urutan field) | `OK`, exit 0 |
| U14 | Manifest sama ditandatangani dua kali | `OK`, exit 0 |

U01 dan U14 dijalankan pada ketiga profil. U14 memeriksa sifat tiap profil: Ed25519 deterministik (signature identik), RSA-PSS dan ECDSA acak (signature berbeda, keduanya valid).

## Skenario integrasi

C01-C05 memakai image yang sudah dipublikasikan. Lihat README utama untuk
perintah dengan digest. Tiap skenario menulis ke `dist/<skenario>/` dan
`out/<skenario>/` sendiri agar bukti satu skenario tidak merusak skenario lain.
