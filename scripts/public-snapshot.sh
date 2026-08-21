#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: scripts/public-snapshot.sh OUTPUT_DIRECTORY [GIT_REF]" >&2
  exit 2
fi

output=$1
ref=${2:-HEAD}
repo_root=$(git rev-parse --show-toplevel)

if [[ -e "$output" ]]; then
  echo "output path already exists: $output" >&2
  exit 1
fi

commit=$(git -C "$repo_root" rev-parse --verify "${ref}^{commit}")
parent=$(dirname "$output")
mkdir -p "$parent"
archive=$(mktemp "${TMPDIR:-/tmp}/acta-public-snapshot.XXXXXX.tar")
cleanup() {
  rm -f "$archive"
}
trap cleanup EXIT

mkdir "$output"
git -C "$repo_root" archive --format=tar --output="$archive" "$commit"
tar -xf "$archive" -C "$output"

"$(dirname "$0")/check-public-tree.sh" "$output"

printf 'Created history-free public snapshot of %s at %s\n' "$commit" "$output"
