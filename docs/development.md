# Development

## Requirements

- the Go version declared in `go.mod` (or newer within the same compatibility
  policy)
- `make`
- `golangci-lint` for local linting

The exact development toolchain is pinned in `.tool-versions`; `go.mod` states
the minimum minor Go version.

## Common Commands

```bash
make fmt
make test
make build
make check
make release-notices-check
```

`make check` runs formatting checks, tests, and a build.

`make lint` runs `golangci-lint` if it is installed locally.

`make release-notices-check` regenerates third-party dependency notices and
fails when the committed notice file is stale. Release snapshots and tagged
publishing are documented in [Releasing Acta](releasing.md).

## Testing Strategy

Unit tests cover adapter command construction and CLI helpers.

Runner tests use fake `codex` and `claude` executables placed on `PATH`. This
lets the test suite verify subprocess capture, run bundle creation, nonzero
exits, and timeouts without requiring real agent credentials.

## CI

GitHub Actions runs:

- `gofmt` check
- `go test ./...`
- `go build ./cmd/acta`
- `golangci-lint`
- a complete, non-publishing GoReleaser snapshot with notices and SBOMs
- publication-contract checks, including SemVer parsing, runtime bundle tests,
  and a history-free public snapshot export

The full Go test suite and a binary build run on Linux, macOS, and Windows.
Windows distribution remains experimental while real-world agent/process
coverage matures; that label no longer means CI only compiles its tests.

Local `make check` should pass before opening a PR.
