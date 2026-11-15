#!/usr/bin/env bash
# C05: Setelah image diambil, jalankan CLI dengan UID/GID runner, tanpa TTY, dan menggunakan --network none.

set -euo pipefail
SCENARIO=c05
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

clean_output

version=$(docker_cmd "$IMAGE" --version </dev/null)
docker_cmd "$IMAGE" --help </dev/null >/dev/null

keyid=$(docker_cmd -v "$OUT_DIR:/output" "$IMAGE" keygen \
  --algorithm ed25519 --out /output/c05-key </dev/null)

test -s "$OUT_DIR/c05-key.key.pem"
test -s "$OUT_DIR/c05-key.pub.pem"
test "$(stat -c %u "$OUT_DIR/c05-key.pub.pem")" = "$(id -u)"
rm -f "$OUT_DIR/c05-key.key.pem" "$OUT_DIR/c05-key.pub.pem"

cat >"$OUT_DIR/evidence.txt" <<EOF
stdin=closed, tty=none, network=none
image=$IMAGE
cli_version=$version
runner_uid=$(id -u)
runner_gid=$(id -g)
keygen_fingerprint=$keyid
note=keypair yang di-generate dihapus (private key tidak disimpan)
EOF

cat "$OUT_DIR/evidence.txt"
