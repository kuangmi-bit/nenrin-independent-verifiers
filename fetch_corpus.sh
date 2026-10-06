#!/usr/bin/env bash
# Fetch the interop corpora at the pinned upstream commit and reproduce every verdict
# signature with the two independent readers in verifiers/.
#
#   ./fetch_corpus.sh [corpus_root]
#
# corpus_root defaults to .corpus. Pass a directory that already holds the upstream tree
# to run fully offline (no network, and no re-fetch if the pin is already there).
#
# Expected output, all three lines:
#   interop-v0: 5/5 verdict signatures reproduced
#   interop-v0.1: 13/13 verdict signatures reproduced
#   36/36 verdict signatures reproduced
set -euo pipefail

PIN=7546b106ec37f9298725e2cfcc5c4647f2ebe08e
REPO=https://github.com/ogasurfproject-jpg/horizon-shield.git
ROOT="${1:-.corpus}"
BASE="$ROOT/workers/hs-ledger/nenrin"
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${PYTHON:-python3}"

if [ ! -d "$BASE/interop-v0" ]; then
  echo "fetching $PIN (sparse, blobless) into $ROOT"
  rm -rf "$ROOT"
  mkdir -p "$ROOT"
  git -C "$ROOT" init -q
  git -C "$ROOT" remote add origin "$REPO"
  git -C "$ROOT" config core.sparseCheckout true
  printf 'workers/hs-ledger/nenrin/interop-v0/\nworkers/hs-ledger/nenrin/interop-v0.1/\nworkers/hs-ledger/nenrin/interop-v0.2/edge/\n' \
    > "$ROOT/.git/info/sparse-checkout"
  git -C "$ROOT" fetch -q --filter=blob:none --depth 1 origin "$PIN"
  git -C "$ROOT" checkout -q FETCH_HEAD
fi

fail=0
PYTHONPATH="$HERE/verifiers" "$PY" "$HERE/runners/run_corpus.py" "$BASE/interop-v0"   nenrin_verify_v0 || fail=1
PYTHONPATH="$HERE/verifiers" "$PY" "$HERE/runners/run_corpus.py" "$BASE/interop-v0.1" nenrin_verify_v0 || fail=1
"$PY" "$HERE/runners/run_edge.py" "$BASE/interop-v0.2/edge" || fail=1

echo
echo "corpora: $REPO @ $PIN"
echo "checked against the published snapshot DOI 10.5281/zenodo.23136978"
exit $fail
