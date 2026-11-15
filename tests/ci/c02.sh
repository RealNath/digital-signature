#!/usr/bin/env bash
# C02: Ubah satu byte artefak setelah sign.
# Pertahankan ukuran dan nama berkas, lalu ulangi alur verifikasi.

set -euo pipefail
SCENARIO=c02
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

clean_output
prepare_artifact
sign_release

printf 'X' | dd of="$DIST_DIR/$PACKAGE.tar.gz" bs=1 seek=0 conv=notrunc status=none

verify_expect 1 ARTIFACT_MISMATCH

# The marker must never exist for a rejected release.
test ! -e "$OUT_DIR/deployed.marker"
echo "rejected as expected: ARTIFACT_MISMATCH"
