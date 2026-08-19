# Contributing to acta

Thanks for digging in. This guide covers building, testing, and the
integration-level details that launchers and backend operators need.

## Building and testing

Requirements and CI details live in [docs/development.md](docs/development.md).
The short version:

```bash
make fmt      # format code
make test     # run tests
make build    # build ./acta
make check    # fmt check + tests + build — run before opening a PR
```

The test suite uses fake `codex` and `claude` executables on `PATH`, so it
verifies subprocess capture, bundle creation, exits, and timeouts without
requiring real agent credentials.

Project internals:

- [Architecture](docs/architecture.md)
- [Run Bundle format](docs/run-bundle.md)

## CLI reference for integrators

### Runtime bundles (Codex)

Run Codex with a private resolved runtime bundle:

```sh
./acta run --agent codex --cwd . --runtime-bundle /private/control/runtime-bundle.json
```

The bundle must be an absolute, private (`0600`) regular JSON file using schema
version 1 and the `codex` adapter. Acta maps its allowlisted tool and MCP
configuration to documented Codex `--config` keys, materializes managed
SKILL.md files only inside Acta's protected staging control directory, rejects
embedded secret-shaped values, and removes managed skill material after the
agent exits.
MCP endpoint URLs must be public HTTPS URLs without user information, query
parameters, or fragments; bearer credentials are referenced only through
`bearer_token_env_var`.

Runtime bundles are authoritative for the supported Codex capability keys.
Acta invokes Codex with user configuration ignored, strict configuration
validation, user/project exec-policy rules ignored, no session persistence,
explicit disabled defaults for omitted tools, an empty MCP table before
declared servers, and an explicit skill list.
Duplicate effective config keys/server slugs, blank or conflicting tool lists,
and values with the wrong per-key type are rejected. The published schema and
example live under [`schemas/`](schemas/). A bundle may contain at most 128
capabilities, and its resolved agent arguments may use at most 256 KiB; Acta
rejects either limit before starting the agent.

Because Codex loads repository `.codex/config.toml` as a separate project
layer, Acta rejects an authoritative runtime-bundle run when that file exists
between the working directory and repository root. Remove or relocate the
project config, or run without `--runtime-bundle`; Acta never silently merges
the two configuration authorities.

A runtime-bundle run must resolve a nonblank model from the bundle's `model`
field or an explicit, matching `--model`; it never falls back to an ambient
user-config model.
Current records expose `agent_config_mode`; bundle-backed records also expose
`runtime_bundle_sha256` for reproducibility without retaining the private
bundle path or contents.

### Agent-writable directories

Launchers that require an agent to write a control file outside the repository
can repeat `--agent-writable-dir <absolute-directory>`. Acta resolves and
validates each real directory, refuses any directory that overlaps the run
bundle, and maps it to the agent's native `--add-dir` option. Codex still runs
with the repository as its explicit `--cd` project root.

### Evidence budgets and exclusions

The CLI defaults to a 1 GiB combined stdout/stderr budget and a 256 MiB
`workspace.diff` budget. Crossing either limit stops/fails the run; Acta never
turns truncation into success. `--max-raw-output-bytes 0` and
`--max-workspace-diff-bytes 0` explicitly select unlimited capture. Negative
values are invalid.

Both hybrid run upload and standalone `acta upload` default to a 1 GiB total
immutable upload-snapshot budget. The limit covers the pinned event-stream
snapshot and referenced artifact snapshots as a whole. `--max-upload-bytes 0`
explicitly disables it; negative values are invalid. A limit failure happens
before remote completion and never falls back to a partial upload.

Launchers may repeat `--git-evidence-exclude <workspace-relative-path>` for
their own generated/control paths. Exclusions apply to initial dirty-state and
final diff evidence and therefore deliberately remove those paths from the
record; do not use broad directories. Acta separately excludes the exact run
and staging paths it owns, not all files under a conventional directory name.

Configured OTLP export is required unless `--otlp-best-effort` is explicitly
set. Best-effort mode records setup/flush status but allows the local execution
outcome to remain successful when export alone fails.

Use `acta doctor --agent codex` or `acta doctor --agent claude` to check Git,
the selected CLI's tested version range and required flags, the workspace, and the runs-root
parent without creating the requested workspace or runs directory.

### Task basis

Attach a local markdown/text issue body as the recorded task basis:

```bash
./acta run --agent codex --cwd . --prompt "Fix the failing test" --issue-body-file issue.md
```

### Re-digesting bundles

Re-digest an existing bundle and regenerate `acta-events.jsonl` (e.g. after a
schema change):

```bash
./acta digest .acta/runs/20260701T220000Z-codex-ab12cd34
```

The default is transactional and fail-closed: any parse, event-timing, or
live-patch-preservation error exits 1 and leaves the existing `digest.json` and
`acta-events.jsonl` unchanged. `--allow-partial` is an explicit recovery mode
that writes the degraded projection, reports a warning, and exits 0; automation
should use it only when partial evidence is acceptable.

### Build metadata

```bash
./acta version
```

## Report modes and upload

`--report-mode local` is the default and writes only the local bundle.

`--report-mode hybrid` keeps the local bundle and uploads run metadata, batched
`acta-events.jsonl` events, terminal artifact references, and completion
status to an ingest backend. Passing `--ingest-token` (or `--ingest-token-env`)
enables hybrid upload automatically. Hybrid mode validates terminal artifact
references before creating the remote run, then streams event batches from
disk instead of holding the full event stream in memory.

`--report-mode stream` is reserved for live streaming and currently exits with
an explicit unsupported-mode error.

A full run-and-upload invocation:

```bash
./acta run \
  --agent codex \
  --cwd . \
  --prompt "..." \
  --repo your-org/your-repo \
  --issue-number 123 \
  --issue-title "Fix the failing test" \
  --issue-body-file issue.md \
  --backend-url http://localhost:8080 \
  --ingest-token "$ACTA_INGEST_TOKEN"
```

Upload an existing local bundle without rerunning the agent:

```bash
./acta upload \
  --backend-url http://localhost:8080 \
  --ingest-token "$ACTA_INGEST_TOKEN" \
  .acta/runs/20260701T220000Z-codex-ab12cd34
```

### Token handling

Use `--ingest-token-env ACTA_INGEST_TOKEN` when a launcher should avoid
putting the token value in process argv. It also enables hybrid upload. Acta
reads the token for its own upload client and scrubs that named env var from
the agent subprocess environment.

Hybrid mode requires an ingest token. `--report-token` and `--report-token-env`
remain available as lower-level aliases.

### Production scoping

Production-scoped uploads must pass a stable `--run-id` plus
`--organization-id <uuid> --repository-id <uuid>`. The launcher should mint
the scoped ingest token for that same run id before launching Acta. In
production, the ingest token should be the short-lived scoped ingest token
minted for that run, not the backend's raw signing secret.

## Current scope

Included:

- noninteractive Codex runs via `codex exec --json`
- noninteractive Claude Code runs via `claude --print --output-format stream-json`
- raw stdout/stderr capture with per-line arrival timestamps
- local run metadata in `run.json`
- trajectory digestion: normalized timeline, token/tool metrics, files read
  (with line spans and safely attributable range content) and edited —
  `digest.json` + `acta digest`
- stable Acta-native replay events in `acta-events.jsonl`
- per-write unified patches with explicit capture status when write boundaries
  can be captured safely
- workspace diff capture (staged + unstaged + non-ignored untracked)
- live OTLP/HTTP trace export (GenAI semconv span model, one trace per run)
- hybrid upload of completed local bundles to an ingest backend
- basic `doctor` checks

Deferred:

- report rendering and the PR-style web UI
- live streaming upload; OTLP re-export of old bundles
- sanitization/redaction for publishing
- branch, commit, or PR operations
- Docker/runtime orchestration
- claude subagent span nesting

## Test data and security

Keep test fixtures hand-authored and synthetic. Do not commit captured agent
sessions, prompts, model reasoning, credentials, customer data, absolute user
paths, or third-party source snapshots as fixtures.

Report suspected vulnerabilities privately through the process in
[SECURITY.md](SECURITY.md), not through a public issue.

## Contribution license and conduct

Acta uses the inbound-equals-outbound model: by submitting a contribution,
you represent that you have the right to submit it and license it under the
repository's MIT License. No separate contributor license agreement is
required. All participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
General support requests follow [SUPPORT.md](SUPPORT.md); maintainer ownership
and release authority are documented in [MAINTAINERS.md](MAINTAINERS.md).
