# acta

**Run coding agents. Keep the whole story.**

Coding agents write code fast. Trusting that code is now the slow part.

A diff tells you *what changed*. It doesn't tell you what the agent read, what
it assumed, what it tried and abandoned, or what it never looked at. For
agent-authored changes, that is exactly what a reviewer needs, and today it
evaporates the moment the terminal scrolls past.

Acta keeps it. It runs Codex or Claude Code noninteractively, streams the
output live, and records the entire run as a portable local bundle: the raw
agent stream, a normalized trajectory of what the agent did, the workspace
diff, and per-write patches with explicit capture status. Review the run, not
just the result.

Acta is plumbing, not porcelain. It works fine by hand, but it is built to
run headless underneath other software: an issue-resolving orchestrator, a CI
pipeline, an eval harness, an agent platform. The launcher decides what runs
and why, hands Acta that context (repository, issue, task title), and Acta
stamps it into the evidence at capture time. One invocation, one run, one
bundle; nothing interactive. Acta disables agent session persistence, while
the completed run bundle is intentionally durable local state.

## Installation

Tagged releases provide prebuilt archives for Linux and macOS on amd64 and
arm64, plus an experimental Windows amd64 build. Download the archive for your
platform from [GitHub Releases](https://github.com/Nobbettt/acta/releases)
and verify it against the published `checksums.txt` file before installing the
`acta` binary on your `PATH`.

Developers with the Go toolchain can install an exact release from source:

```bash
go install github.com/nobbettt/acta/cmd/acta@v0.1.0
```

Automated environments should pin an exact version rather than `@latest`.

Acta probes the selected agent before every run. The current tested ranges are
Codex CLI `>=0.147.0,<0.148.0` and Claude Code `>=2.1.235,<2.2.0`;
prerelease versions are rejected. Acta fails closed outside these ranges until
the command flags and provider event contract are requalified. The normalized
agent version is recorded in every current run record and projection.

Codex sessions are always ephemeral. When a runtime bundle is supplied, Acta
also ignores user config, enables strict config validation, and explicitly
resolves every supported bundle capability. Claude sessions are not persisted
and load project settings (including project instructions) but not user or
local settings. Runtime bundles currently support Codex only.

## Quick start

```bash
make build                  # build the ./acta binary
./acta doctor --agent codex # check Git, paths, and the selected CLI/version
./acta run --agent codex --cwd . --prompt "Summarize this repository"
```

Claude Code works the same way:

```bash
./acta run --agent claude --cwd . --prompt "Summarize this repository"
```

Or pipe a prompt in:

```bash
cat task.md | ./acta run --agent codex --cwd .
```

## What you get

Every run lands in a self-contained bundle under `.acta/runs`:

```text
.acta/runs/20260701T220000Z-codex-ab12cd34/
  run.json            # run metadata (incl. trace_id when OTLP export is on)
  codex-events.jsonl  # raw agent stream (claude-output.jsonl for claude)
  codex.stderr.log
  event-times.jsonl   # arrival timestamp per raw line (the streams carry none)
  workspace.diff      # staged+unstaged+non-ignored-untracked diff, when non-empty
  digest.json         # normalized timeline, metrics, files touched
  acta-events.jsonl  # stable product/replay events derived from the digest
  projection.json     # digest/event hashes after an acta digest re-projection
```

The digest is the heart of it: a normalized timeline with token and tool
metrics, the files the agent read (down to line spans) and edited, independent
of which agent produced the run. See [Run Bundle](docs/run-bundle.md) for the
full format.

## Don't Codex and Claude Code already do this?

They do export telemetry: Claude Code can emit OTel metrics, events, and
optional traces; Codex has an opt-in `[otel]` exporter; both keep local
session logs. If usage dashboards are all you need (cost, tokens, tool
counts), use that and skip Acta.

Acta exists for the moment *after* the run: review, audit, replay. The native
exporters describe a run in counts, durations, names, and decisions. A bundle
holds the data that never reaches them:

- **The raw stream, with arrival times.** The CLI retains up to 1 GiB combined
  stdout/stderr by default (or every byte with an explicit
  `--max-raw-output-bytes 0`). Within that budget Acta retains every byte
  the agent emitted on stdout *and* stderr, not a curated event vocabulary, plus a
  per-line arrival timestamp for the stdout event stream (the streams
  themselves carry none). A launcher may set an explicit raw-output budget;
  exceeding it fails and stops the run rather than silently truncating success.
- **Full tool-call arguments and outputs plus surfaced messages.** Provider
  reasoning/thinking channels are treated differently from assistant text
  deliberately surfaced to the user. Private reasoning stays local-only in
  raw and normalized streams, is excluded from OTLP, `digest.json`, and
  evaluation-facing summaries, and can be removed from bundles entirely with
  `--redact-reasoning`.
- **The workspace diff** (staged + unstaged + non-ignored untracked): the net uncommitted
  change the run left in the workspace. Commits made during the run show up as
  base-to-head commit movement in the run metadata instead. Line counters
  exist natively; the actual diff does not.
- **Per-write patches when capture succeeds.** What each individual write
  changed between its write boundaries, with explicit unavailable/partial
  status when size, file type, timing, or capture errors prevent exact evidence.
- **Files read, down to line spans**, with the exact text returned to the
  agent when it can be safely attributed. What the agent looked at, and what
  it never looked at, is precisely what a reviewer needs.
- **The task basis.** Repository, issue, and prompt provenance, declared by
  the launcher and stamped into the bundle at capture time. Telemetry is keyed
  to a session id; a bundle is keyed to the work item.
- **The invocation and outcome, recorded from outside.** The exact command
  Acta ran (prompt redacted), working directory, the git context (base
  commit, branch, and dirty state at start; head commit at completion), timing, exit code,
  timeout, termination reason. Self-reported telemetry ends when the process dies;
  Acta is the thing that stopped the platform process container and knows why. Process
  environment variables are deliberately *not* captured: they are a secret
  minefield, and Acta scrubs its own token variable from the agent's
  environment.
- **The awkward events.** Permission denials, rate limits, subagent tasks,
  todo updates, orphaned tool results, and unknown provider events preserved
  as `agent.event.unsupported` instead of silently dropped. Within the tested
  agent-version range, an unsupported event makes the run degraded/non-successful
  until Acta's parser explicitly supports it.

And the *how* matters as much as the *what*: native session logs live in
agent-writable directories, so an agent can rewrite its own transcript. Acta
records from outside the process, stages output beyond the agent's writable
roots, and publishes the bundle after platform cleanup. Windows uses a Job
Object. POSIX uses a process group; a child that creates a new session or
process group is outside the portable guarantee.
Both agents' events are digested into one normalized timeline. By default the
raw streams are preserved byte-identical so old runs can be re-digested with
better parsers (`acta digest`); `--redact-reasoning` instead rewrites the raw
stdout stream to remove private reasoning text. A span the exporter dropped is
gone; a bundle can be re-projected from its raw evidence. Live-only per-write
patches are preserved from the prior digest and regeneration fails explicitly
when that evidence cannot be validated.

## Watch runs live

Stream any run as OpenTelemetry traces to Jaeger, Grafana Tempo, or any other
OTLP/HTTP backend you already have (`OTEL_EXPORTER_OTLP_*` env vars are
honored too):

```bash
./acta run --agent codex --prompt "..." --otlp-endpoint http://localhost:4318
```

Configured OTLP export is best-effort by default: setup or flush failure is
recorded without changing the agent outcome. Use
`--otlp-export-failure-policy required` when delivery is an operational
requirement. Required mode still finishes and preserves the bundle and its
semantic result before Acta exits with the documented telemetry-only code 86.
Launchers must validate the successful Acta-owned `run.json` as well as the
code before treating it as an operational warning. Required mode rejects
startup configurations that make delivery impossible, including a missing
endpoint, `OTEL_SDK_DISABLED=true`, `OTEL_TRACES_EXPORTER=none`, and an
unconditionally disabled sampler.
The deprecated `--otlp-best-effort` alias still selects best-effort with a
warning. Combining it with `--otlp-export-failure-policy required` is a startup
error because those flags request conflicting delivery policies.

When `TRACEPARENT` contains valid W3C Trace Context, the `invoke_agent` span
joins that trace as a child of the supplied remote parent; valid `TRACESTATE`
is carried with it. Missing or malformed parent context is ignored and Acta
starts a standalone root trace as before. Pass `--otlp-force-root` to ignore
both variables even when the parent is valid. Run IDs remain opaque and are
never used to derive trace context.

Hybrid and standalone upload pin an immutable bundle snapshot before sending
it. Remote snapshots remove provider-private reasoning by default while the
local bundle remains full fidelity. The explicit
`--allow-unredacted-remote-reasoning` flag opts a remote upload back into that
content. Artifact labels are content-derived in this mode: detected reasoning
or content that cannot be verified is `unredacted`, while verified-clean
artifacts are `not_required`. Declared structured artifacts (Acta events,
digests, and provider streams) use their schema-specific privacy passes.
Opaque text is handled only line by line: standalone JSON lines are redacted,
but an unparseable brace/bracket-opening line or multiline JSON continuation
makes the artifact `unverified` and local-only for the default upload. The
uploaded terminal artifact manifest retains that reference with
`status: withheld`, a machine-readable reason, and
`redaction_state: unverified`, so remote completeness checks can distinguish
privacy withholding from a missing upload. The
explicit unredacted opt-in uploads such an artifact as `unredacted`. Ordinary
plain-text diagnostics still upload. The total snapshot budget defaults to 1
GiB; use
`--max-upload-bytes 0` only when an explicit unlimited upload is intended.
Reasoning redaction bounds each JSONL record to 8 MiB by default; use
`--max-redaction-line-bytes` to set a different explicit bound.

By default spans carry only structural metadata (tool names, ids, exit codes,
tokens, timing). Content that can hold secrets or local paths stays out of the
export unless you opt in with `--otlp-include-output`. That opt-in applies to
surfaced messages and tool content, never provider reasoning/thinking text.
Without `--redact-reasoning`, private reasoning is retained only in local raw
streams and `agent.reasoning` normalized events; `run.json` records
`reasoning_redaction_state: retained_local`. Redact mode removes its text from
both persisted streams and records `reasoning_redaction_state: redacted`. If
redaction fails before replacement, Acta retains the completed unredacted
bundle locally and records `reasoning_redaction_state: failed`. An ambiguous
post-replacement commit is hash-checked and recorded as `partial` unless the
original bytes are verified unchanged. Both states refuse default remote
upload. Remote upload redaction is independent and never rewrites local files.

Current writers emit run-record schema v3. It adds the `not_sampled` OTLP
status without changing the closed v2 enum; readers accept both versions and
reject `not_sampled` when a record still declares v2.

## Where it's headed

Acta is the recording layer for a larger idea: agent-authored changes deserve
a review surface built on evidence (the issue, the trajectory, and what was
verified), not just a diff. Report rendering and the PR-style review UI are on
the roadmap; today Acta focuses on capturing everything they will need,
with explicit evidence and projection limits at run time.

## Contributing

Want to build from source, run the tests, or integrate Acta into a launcher?
Start with the [contributors guide](CONTRIBUTING.md), then dig into
[Architecture](docs/architecture.md) and [Development](docs/development.md).
Security reports follow the private process in [SECURITY.md](SECURITY.md).
Maintainers can follow the [release process](docs/releasing.md) when preparing
versioned distribution artifacts.

## License

Acta is available under the [MIT License](LICENSE).
