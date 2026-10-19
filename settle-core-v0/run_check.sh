#!/bin/sh
# Point this at a checkout of ogasurfproject-jpg/horizon-shield and run the checker.
set -e
VECTORS="${1:?usage: run_check.sh <path to .../musubi-v0/settle-core-v0/vectors>}"
cd "$(dirname "$0")"
exec python3 settle_core_v0.py --check "$VECTORS"
