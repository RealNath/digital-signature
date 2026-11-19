# Hasil benchmark

Dihasilkan oleh `python3 benchmark/bench.py --runs 30 --warmup 5`.
Median dan P95 (nearest rank) dari 30 percobaan terukur setelah 5 warmup.

| Item | Value |
| --- | --- |
| Python | 3.14.10 |
| cryptography | 50.0.2 |
| OpenSSL | OpenSSL 3.5.9 29 Sep 2026 |
| Platform | Linux x86_64 |
| CPU | Intel(R) Core(TM) 5 210H |

## Key, signature, and bundle sizes

| Profile | Private key | Public key | Signature | Manifest | Bundle |
| --- | ---: | ---: | ---: | ---: | ---: |
| `rsa-pss-sha256` | 2484 B | 625 B | 384 B | 307 B | 992 B |
| `ecdsa-p256-sha256` | 241 B | 178 B | 64 B | 310 B | 572 B |
| `ed25519` | 119 B | 113 B | 64 B | 300 B | 556 B |

Ukuran dalam byte seperti tertulis di disk (PEM/DER). Kolom manifest dan bundle diukur pada artefak 1 MiB: manifest tidak bergantung ukuran, bundle hanya berbeda pada panjang signature.

## Timings

| Profile | Artifact | sign median | sign P95 | verify median | verify P95 | CLI sign+verify median | CLI P95 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `rsa-pss-sha256` | 1 KiB | 2.707 ms | 2.921 ms | 0.216 ms | 0.228 ms | 383.2 ms | 426.8 ms |
| `rsa-pss-sha256` | 1 MiB | 3.727 ms | 4.005 ms | 1.244 ms | 1.391 ms | 434.4 ms | 533.6 ms |
| `rsa-pss-sha256` | 16 MiB | 18.532 ms | 19.300 ms | 16.141 ms | 16.194 ms | 434.8 ms | 463.0 ms |
| `ecdsa-p256-sha256` | 1 KiB | 0.059 ms | 0.066 ms | 0.267 ms | 0.442 ms | 219.7 ms | 236.8 ms |
| `ecdsa-p256-sha256` | 1 MiB | 1.063 ms | 1.154 ms | 1.351 ms | 1.503 ms | 225.0 ms | 246.8 ms |
| `ecdsa-p256-sha256` | 16 MiB | 15.922 ms | 16.329 ms | 16.115 ms | 16.191 ms | 273.0 ms | 292.3 ms |
| `ed25519` | 1 KiB | 0.078 ms | 0.081 ms | 0.250 ms | 0.288 ms | 207.4 ms | 214.4 ms |
| `ed25519` | 1 MiB | 1.072 ms | 1.573 ms | 1.269 ms | 1.292 ms | 213.4 ms | 228.9 ms |
| `ed25519` | 16 MiB | 15.825 ms | 15.861 ms | 16.064 ms | 16.144 ms | 254.8 ms | 267.9 ms |

`CLI` memulai interpreter dua kali dan menyentuh filesystem, sebagian besar waktu dari start-up proses, bukan kriptografi.
