# Releasing Acta

Acta releases are built from SemVer tags by GoReleaser. The release workflow
publishes platform archives, SHA-256 checksums, per-archive SBOMs, and GitHub
build-provenance attestations. Each archive also carries the dependency license,
NOTICE, and copyright material collected in `THIRD_PARTY_NOTICES`.

The workflow creates a draft first, attests the finished artifacts, and only
then makes the release public. A failed attestation can leave a recoverable
draft but cannot leave a public release that claims missing provenance.

## Supported release targets

- Linux: amd64 and arm64
- macOS: amd64 and arm64
- Windows: amd64, experimental

## Local snapshot

Install GoReleaser v2.17.1 and Syft and ensure both executables are on `PATH`.
Then install the pinned license-report tool:

```bash
go install github.com/google/go-licenses/v2@v2.0.1
```

Then run:

```bash
make release-notices
git diff --exit-code -- THIRD_PARTY_NOTICES
make release-snapshot
```

The snapshot is written under `dist/` and is never published. Inspect every
archive, run each locally available binary, and verify that `acta version`
contains the expected snapshot version and commit.

## Publishing

1. Complete [the release checklist](release-checklist.md) from a clean clone.
2. Confirm CI and the release-snapshot job pass on the intended commit.
3. Create an annotated SemVer tag such as `v0.1.0-rc.1` or `v0.1.0`.
4. Push only that tag.
5. Wait for the Release workflow to finish.
6. Verify the downloaded archives against `checksums.txt` and verify their
   GitHub attestations before announcing the release.

Artifact attestations require the final public repository on GitHub Free,
Pro, or Team. Do not push release tags from the temporary private repository.

Never publish a release from an unreviewed commit or use a moving tag such as
`latest` as an automated dependency.

Release tags are parsed as SemVer 2.0.0 rather than checked with a permissive
regular expression. The workflow resolves an annotated tag to its exact commit,
requires that commit to be reachable from `origin/main`, and requires a
successful completed CI workflow for that exact main-branch SHA.

## First public repository snapshot

The current private Git history contains superseded captured-agent fixtures and
must not be made public. Do not push or mirror its existing refs. Export a
reviewed commit into a new, history-free tree instead:

```bash
scripts/public-snapshot.sh /absolute/path/to/acta-public <reviewed-commit>
```

The command refuses an existing destination, uses `git archive` so no `.git`
history is copied, and checks the exported bytes for known historical fixture
identifiers. Review the resulting tree, initialize a new repository inside it,
and push that new root commit to the public remote. This workflow never rewrites
the private repository's refs.

Before enabling releases, configure the public GitHub repository description
and homepage, add topics such as `golang`, `cli`, `coding-agents`, `codex`,
`claude-code`, and `observability`, enable private vulnerability reporting, and
enable Discussions if it will be the support channel named in `SUPPORT.md`.
