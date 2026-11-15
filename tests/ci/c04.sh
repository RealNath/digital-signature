#!/usr/bin/env bash
# C04: Jalankan verifikasi dengan path artefak yang berkasnya tidak tersedia. 

set -euo pipefail
SCENARIO=c04
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

clean_output
prepare_artifact
sign_release

verify_expect 2 INPUT_ERROR "missing-$PACKAGE.tar.gz"

test ! -e "$OUT_DIR/deployed.marker"
echo "rejected as expected: INPUT_ERROR"
