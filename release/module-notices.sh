#!/usr/bin/env bash

set -euo pipefail

readonly separator='================================================================================'

while IFS=$'\t' read -r module version module_dir; do
  if [[ -z "${module_dir}" ]]; then
    continue
  fi
  while IFS= read -r notice_path; do
    printf '\n%s\nComponent: %s %s notice\nFile: %s\n\n' \
      "${separator}" \
      "${module}" \
      "${version}" \
      "$(basename "${notice_path}")"
    cat "${notice_path}"
    printf '\n'
  done < <(
    find "${module_dir}" -maxdepth 1 -type f \
      \( -iname 'NOTICE*' -o -iname 'COPYRIGHT*' \) -print | LC_ALL=C sort
  )
done < <(
  go list -deps -f \
    '{{with .Module}}{{if not .Main}}{{printf "%s\t%s\t%s" .Path .Version .Dir}}{{end}}{{end}}' \
    ./cmd/acta | LC_ALL=C sort -u
)
