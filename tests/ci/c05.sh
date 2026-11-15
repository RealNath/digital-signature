#!/usr/bin/env bash
# C05: Setelah image diambil, jalankan CLI dengan UID/GID runner, tanpa TTY, dan menggunakan --network none.

set -euo pipefail
SCENARIO=c05-no-tty
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

clean_output

docker_cmd "$IMAGE" --version </dev/null
docker_cmd "$IMAGE" --help </dev/null >/dev/null

docker_cmd -v "$OUT_DIR:/output" "$IMAGE" keygen \
  --algorithm ed25519 --out /output/c05-key </dev/null

test -s "$OUT_DIR/c05-key.key.pem"
test -s "$OUT_DIR/c05-key.pub.pem"
test "$(stat -c %u "$OUT_DIR/c05-key.pub.pem")" = "$(id -u)"

echo "ran with uid $(id -u), no TTY, no network"
