#!/usr/bin/env bash
set -euo pipefail

destination=$(mktemp -d "${TMPDIR:-/tmp}/acta-public-check.XXXXXX")
rmdir "$destination"
cleanup() {
  rm -rf "$destination"
}
trap cleanup EXIT

"$(dirname "$0")/public-snapshot.sh" "$destination" HEAD
test ! -e "$destination/.git"

# Prove the verifier rejects a known removed transcript identifier without
# storing that identifier contiguously in this source tree.
forbidden='019d10a0-''b7b9-7fa3-b2b9-94142506ab90'
printf '%s\n' "$forbidden" >"$destination/forbidden-fixture.txt"
if "$(dirname "$0")/check-public-tree.sh" "$destination"; then
  echo "public tree checker accepted a forbidden fixture" >&2
  exit 1
else
  status=$?
  if [[ $status -ne 1 ]]; then
    echo "public tree checker failed unexpectedly (exit $status)" >&2
    exit "$status"
  fi
fi
