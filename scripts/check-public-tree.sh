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
forbidden_codename='Gl''en'
# Internal project codenames that must never appear in the public tree.
forbidden_codenames=('man''go' 'pine''apple' 'ki''wi' 'lem''on' 'cher''ry' 'pea''ch')
for fragment in "$forbidden_session" "$forbidden_claude" "$forbidden_worktree" "$forbidden_commit" "$forbidden_codename" "${forbidden_codenames[@]}"; do
  if LC_ALL=C grep -R -I -i -n -F --exclude=check-public-tree.sh --exclude=public-snapshot-test.sh "$fragment" "$tree"; then
    echo "public snapshot contains a forbidden historical fixture fragment" >&2
    exit 1
  else
    status=$?
    if [[ $status -ne 1 ]]; then
      echo "failed to scan public snapshot (grep exit $status)" >&2
      exit "$status"
    fi
  fi
done
