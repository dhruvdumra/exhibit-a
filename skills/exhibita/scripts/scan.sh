#!/usr/bin/env bash
# Run ExhibitA on a path and fail if a critical issue is proven exploitable.
# Usage: scan.sh <path> [--no-verify]
set -euo pipefail

TARGET="${1:-.}"
VERIFY="--verify"
[ "${2:-}" = "--no-verify" ] && VERIFY=""

exec exhibita scan "$TARGET" $VERIFY \
  --sarif exhibita.sarif \
  --markdown exhibita.md \
  --comments exhibita-comments.json
