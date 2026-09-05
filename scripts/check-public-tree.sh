#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! -d "$1" ]]; then
  echo "usage: scripts/check-public-tree.sh EXPORTED_TREE" >&2
  exit 2
fi
tree=$1

if [[ -e "$tree/.git" ]]; then
  echo "public snapshot unexpectedly contains Git metadata" >&2
  exit 1
fi

# These fragments identify the non-synthetic agent transcripts removed from
# the current source tree. They are split so the checker itself does not place
# a forbidden literal into the exported snapshot.
forbidden_session='019d10a0-''b7b9-7fa3-b2b9-94142506ab90'
forbidden_claude='8c24dd94-''d294-460e-a5c4-008b4f4779d7'
forbidden_worktree='contextbench_''worktrees'
forbidden_commit='9476425b''9e34363c2d9ac38e9f04aa75ae54a775'
# Internal project codenames that must never appear in the public tree,
# matched case-insensitively on word boundaries so hashes and third-party
# license texts containing the letters do not false-positive.
forbidden_codenames=('gl''en' 'man''go' 'pine''apple' 'ki''wi' 'lem''on' 'cher''ry' 'pea''ch' 'li''me')

scan() {
  local message=$1
  shift
  if LC_ALL=C grep -R -I -n --exclude=check-public-tree.sh --exclude=public-snapshot-test.sh "$@" "$tree"; then
    echo "$message" >&2
    exit 1
  else
    local status=$?
    if [[ $status -ne 1 ]]; then
      echo "failed to scan public snapshot (grep exit $status)" >&2
      exit "$status"
    fi
  fi
}

for fragment in "$forbidden_session" "$forbidden_claude" "$forbidden_worktree" "$forbidden_commit"; do
  scan "public snapshot contains a forbidden historical fixture fragment" -F "$fragment"
done
# Phrases that contain a codename's letters but are not the codename: the git
# subcommand `cherry-pick` is a real command this project classifies, and
# refusing it would mean dropping a supported command to satisfy a name check.
# Each entry is removed from a candidate line before the line is judged, so a
# genuine codename sitting on the same line is still caught.
allowed_phrases=('cher''ry-pick')

scan_codename() {
  local fragment=$1
  local matches
  matches=$(LC_ALL=C grep -R -I -n -i -w -F \
    --exclude=check-public-tree.sh --exclude=public-snapshot-test.sh \
    "$fragment" "$tree" || true)
  local phrase
  for phrase in "${allowed_phrases[@]}"; do
    matches=$(printf '%s' "$matches" | LC_ALL=C sed "s/${phrase}//gI" || true)
  done
  matches=$(printf '%s' "$matches" | LC_ALL=C grep -i -w -F "$fragment" || true)
  if [[ -n $matches ]]; then
    printf '%s\n' "$matches"
    echo "public snapshot contains a forbidden internal codename" >&2
    exit 1
  fi
}

for fragment in "${forbidden_codenames[@]}"; do
  scan_codename "$fragment"
done
