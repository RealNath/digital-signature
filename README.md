# MiniSign

MiniSign adalah alat penandatanganan rilis yang ringan, dengan gaya serupa Cosign. Alat ini menandatangani *manifest* canonical JSON yang mendeskripsikan suatu artefak, mengemas *manifest* tersebut dan and tanda tangannya ke dalam sebuah *bundle* JSON, lalu memverifikasi *bundle* tersebut dengan mencocokkannya terhadap *trust store* yang menentukan kunci publik mana yang diizinkan untuk menandatangani paket tertentu.

Semuanya merupakan satu CLI Python dengan tiga profil khusus yang dikemas sebagai citra kontainer yang dapat dijalankan secara luring dan tanpa hak akses istimewa (unprivileged).

## Stack

| Komponen | Versi |
| --- | --- |
| Python | 3.14 (`python:3.14-slim` in the image) |
| `cryptography` | 50.0.2 (only runtime dependency) |
| `pytest` | 9.2.0 (tests only, `requirements-dev.txt`) |

Tidak ada paket pihak ketiga lain yang digunakan: argument parsing, JSON, Base64, dan hashing semuanya berasal dari pustaka standar.

## Citra kontainer

Citra tersebut dipublikasikan ke GHCR dan harus dirujuk menggunakan digest, bukan tag:

```bash
docker run --rm ghcr.io/realnath/digital-signature@sha256:ae42a3d84e29a7961c4e0a97f4318f158be9070b3ddb731af94db43adf9b424f --help
```

Tidak memerlukan jaringan, tidak memerlukan TTY, dan tidak memerlukan pengguna dengan hak akses khusus:

```bash
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" -v "$PWD/out:/output" \
  -v "$PWD/keys/publisher.key.pem:/run/signing.key.pem:ro" \
  ghcr.io/realnath/digital-signature@sha256:ae42… sign \
    --file /input/app.tar.gz --package demo-app --version 1.0.0 \
    --key /run/signing.key.pem --out /output/bundle.json
```

Kunci penandatanganan tidak pernah menjadi bagian dari citra, tapi dihadirkan sebagai *mount* yang bersifat *read-only*.

## CLI

Dari direktori hasil *checkout*, jalankan `python3 -m src.minisign <command>` pada akar repositori. Di dalam *image*, *entrypoint* tetap sama, sehingga perintah `<image> <command>` dapat digunakan.

```text
minisign keygen --algorithm <profile> --out <prefix> [--force]
minisign sign --file <artifact> --package <name> --version <release> --key <private.pem> --out <bundle.json>
minisign verify --file <artifact> --bundle <bundle.json> --trust-store <trust.json> --package <name> --version <release> [--json]
minisign trust add --key <public.pem> --package <name> --store <trust.json>
minisign trust list --store <trust.json>
minisign trust remove --keyid <fingerprint> --store <trust.json>
```

Satu kali eksekusi lokal secara menyeluruh:

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

`keygen` mencetak keyid. Perintah ini menulis `<prefix>.key.pem` (PKCS#8, unencrypted) dan `<prefix>.pub.pem` (SPKI), menolak untuk *overwrite* tanpa `--force`, dan
`sign` menolak untuk *overwrite* bundel yang sudah ada.

## Profil

| Profil | Library primitive | Kunci publik | Tanda tangan |
| --- | --- | --- | --- |
| `rsa-pss-sha256` | RSA-3072, e = 65537, PSS dengan MGF1-SHA256 dan 32-byte salt | ~625 B PEM | 384 B |
| `ecdsa-p256-sha256` | ECDSA pada P-256 dengan SHA-256, tanda tangan disimpan dengan lebar tetap `r \|\| s` | ~178 B PEM | 64 B |
| `ed25519` | Ed25519 (RFC 8032), murni, tanpa prehash | ~113 B PEM | 64 B |

Profil ECDSA sengaja tidak menggunakan DER: format yang dibawa oleh bundel tersebut adalah `r || s` sepanjang 64 byte, dan konversi ke DER hanya terjadi pada batas OpenSSL di dalam `tests/interop/`.

Keyid tersebut `hex(SHA256(DER SPKI))`, sehingga kunci publik yang sama akan selalu menghasilkan *identifier* yang sama, terlepas dari format PEM yang digunakan.

## Format file

**Manifest** — canonical JSON, UTF-8, nilai ASCII, tanpa spasi, tanpa karakter baris baru di akhir, maksimal 16 KiB:

```json
{"schema":"minisign-manifest/v1","package":"demo-app","version":"1.0.0","algorithm":"ed25519","keyid":"576c…a473","artifact":{"name":"demo-app.tar.gz","size":139,"sha256":"9f2c…"}}
```

Urutan kolom ditetapkan secara tetap, kolom tambahan maupun duplikat akan ditolak, dan sebuah verifikator akan menyusun ulang *manifest* tersebut dengan mengharuskan kesamaan byte supaya dua penyandian untuk objek yang sama tidak mungkin keduanya dapat diterima.

**Bundle** — canonical JSON, paling banyak 64 KiB, kedua nilai dalam format Base64:

```json
{"schema":"minisign-bundle/v1","manifest_b64":"eyJzY2hlbWEi…","signature_b64":"hL3k…"}
```

Tanda tangan tersebut mencakup byte *manifest* persis seperti yang tersimpan, bukan artefaknya.

**Trust store** — kebijakan pihak pemanggil, satu entri untuk setiap kunci tepercaya:

```json
{"schema":"minisign-trust/v1","keys":[{"keyid":"576c…a473","algorithm":"ed25519","public_key_pem":"-----BEGIN PUBLIC KEY-----\n…\n","packages":["demo-app"]}]}
```

Sebuah kunci dapat dipercaya untuk beberapa paket; kunci yang dipercaya untuk `other-app` tidak dapat digunakan untuk memverifikasi rilis `demo-app`. Operasi perubahan mutasi menulis ulang berkas melalui berkas sementara di direktori yang sama menggunakan `os.replace`, sehingga jika terjadi *crash*, penyimpanan data tidak akan tertinggal dalam kondisi terpotong (*truncated*).

## Jenjang verifikasi

`verify` berhenti pada langkah pertama yang gagal dan melaporkan status tersebut:

| Urutan | Status | Makna | Keluar |
| --- | --- | --- | --- |
| 1 | `INPUT_ERROR` | file masukan tidak dapat dibaca | 2 |
| 2 | `FORMAT_ERROR` | *bundle*, *manifest*, atau *trust store* tidak tersusun dengan benar | 1 |
| 3 | `UNSUPPORTED_ALGORITHM` | *manifest* menyebutkan profil yang tidak diimplementasikan oleh alat tersebut | 1 |
| 4 | `KEY_NOT_TRUSTED` | keyid tidak diketahui, ketidakcocokan algoritma, atau paket tidak diizinkan | 1 |
| 5 | `INVALID_SIGNATURE` | tanda tangan tidak terverifikasi terhadap byte *manifest* | 1 |
| 6 | `METADATA_MISMATCH` | nama paket, versi, atau artefak berbeda dari rilis yang diharapkan | 1 |
| 7 | `ARTIFACT_MISMATCH` | ukuran artefak atau SHA-256 berbeda dari *manifest*. | 1 |
| 8 | `OK` | semua hal di atas tetap berlaku | 0 |

Urutan berpengaruh: *manifest* yang telah diubah akan dilaporkan sebagai `INVALID_SIGNATURE`, bukan sebagai ketidakcocokan metadata, dan kunci yang tidak tepercaya akan ditolak bahkan sebelum tanda tangannya diperiksa.

## Tes

```bash
python3 -m pip install -r requirements-dev.txt

python3 -m pytest tests/unit -q      # U01-U14, 28 cases
bash tests/interop/openssl.sh        # OpenSSL interop, both directions
```

Skenario integrasi memerlukan citra yang telah dipublikasikan dan dijelaskan dalam `tests/README.md`; skenario tersebut menjalankan kontainer dengan opsi `--network none`, menggunakan UID/GID milik *runner*, dan menyertakan *digest* yang telah dipatok (*pinned digest*).

## Benchmark

```bash
python3 benchmark/bench.py           # 5 warmups, 30 measured runs
```

Hasil ditulis ke dalam `benchmark/results.md` dan `benchmark/results.json`. Angka-angka utama dari pengujian referensi (Intel Core 5 210H, Python 3.14.9):

| Profil | sign 1 MiB | verify 1 MiB | CLI sign+verify | Tanda tangan | Bundle |
| --- | ---: | ---: | ---: | ---: | ---: |
| `rsa-pss-sha256` | 1.72 ms | 0.55 ms | 187 ms | 384 B | 992 B |
| `ecdsa-p256-sha256` | 0.49 ms | 0.57 ms | 114 ms | 64 B | 572 B |
| `ed25519` | 0.49 ms | 0.57 ms | 108 ms | 64 B | 556 B |

Di atas 1 MiB, proses SHA-256 terhadap artefak menjadi faktor yang paling dominan, sehingga ketiga profil tersebut bertemu di titik yang sama. Kolom CLI sebagian besar mencakup waktu inisialisasi interpreter serta pemuatan kunci RSA. Itulah sebabnya nilainya dua orde besaran lebih besar daripada proses kriptografinya sendiri.

## Tata Letak Repositori

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

`.github/workflows/build-image.yml` membangun dan mendorong *image* saat terdapat *tag* dengan pola `v*` atau melalui pemicuan manual, dan mencetak *digest* yang dihasilkan dalam ringkasan eksekusi (*run summary*).

`.github/workflows/user-pipeline.yml` menarik citra tersebut **berdasarkan digest**-nya, menandatangani artefak demo menggunakan kunci dari *repository secrets*, memverifikasinya, lalu menjalankan skenario negatif. Setiap kali ada publikasi baru, *digest* dalam alur kerja (*workflow*) tersebut harus diperbarui; langkah manual inilah intinya: *pipeline* menjalankan citra yang telah ditinjau, bukan sekadar citra yang kebetulan dirujuk oleh suatu *tag*.
