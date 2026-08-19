# Release checklist

## Source and contracts

- [ ] The release commit is reviewed, merged to `main`, and exact-SHA CI is green.
- [ ] `make check`, `make publication-check`, race tests, vet, and lint pass.
- [ ] Runtime, run-record, digest, and event schemas/examples match Go structs.
- [ ] Breaking or observable changes are recorded in `CHANGELOG.md`.
- [ ] Documentation states the current tested agent CLI ranges and platform scope.
- [ ] Third-party notices regenerate without a diff.

## Public-source boundary

- [ ] The public repository was created from `scripts/public-snapshot.sh`, not
  by exposing or mirroring private history.
- [ ] The exported tree contains no `.git` directory, captured sessions,
  non-synthetic fixtures, private paths, or third-party source snapshots.
- [ ] Repository description, topics, support channel, issue forms, private
  vulnerability reporting, and branch protection are configured.

## Tag and artifacts

- [ ] The annotated tag is valid SemVer and resolves to the intended exact SHA.
- [ ] The Release workflow produces a draft, archives, checksums, SBOMs, and
  attestations before publishing the draft.
- [ ] Downloaded archives match `checksums.txt`; locally runnable binaries
  report the expected version and commit.
- [ ] Windows is labeled experimental in release notes.
- [ ] The final release notes link the changelog and call out schema changes.
