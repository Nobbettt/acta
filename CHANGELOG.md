# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and Semantic Versioning. Dates use ISO 8601.

## Unreleased

## v0.2.0 - 2026-09-05

### Added

- Digest timeline entries and shell-command event payloads carry `categories`
  and `targets` derived from the command text, and from its output only when
  the command is a single segment.
- `file.deleted` and `file.moved` events record workspace
  changes proven by a shell command rather than by an edit tool.
- `digest.FromRunDirWithOptions` re-digests a bundle under the control-plane
  directory the run declared, so `control.access` reproduces offline.
- Shell commands are parsed with a real shell grammar rather than scanned for
  redirection characters, so a descriptor-qualified redirection, a here-document
  delimiter and a here-string are each understood for what they are, and a word
  containing an expansion is never published as a path.
- Acta observes the workspace around a shell command and records what actually
  changed as `observed_effects`, with `observation_status` distinguishing "the
  filesystem was examined and nothing changed" from "nothing was examined".
  A change the command text implied but the filesystem did not show no longer
  publishes a path or a mutation. The observation is recorded rather than
  recomputed, so re-digesting a bundle reproduces the original run.

### Changed

- Run-record, digest, and Acta-event writers now emit schema v3, which adds
  `not_sampled` to their closed `otlp_status` enums, adds explicit reasoning
  and withheld-artifact state, and records the regenerating producer separately
  from the immutable run producer. Readers continue to accept v2 while
  rejecting these v3-only fields and values in v2 artifacts.
- Required OTLP export now rejects statically unsampleable root configurations
  at startup and returns an operational telemetry failure if a root is still
  sampled out at runtime, after preserving the complete run bundle.
- Remote event manifests explicitly mark privacy-withheld artifacts instead
  of leaving references indistinguishable from missing uploads.

## v0.1.0 - 2026-08-21

Initial public release.

### Added

- Versioned JSON Schemas and representative examples for runtime bundles, run
  records, digests, and Acta replay events.
- Deterministic agent configuration and fail-closed tested CLI version ranges.
- History-free public snapshot and atomic draft-release publication checks.

### Changed

- Current Acta-owned output contracts use schema version 2 and include Acta
  producer identity.
- Runtime-bundle tool values are typed and conflicting effective configuration
  is rejected.

### Removed

- Reader support for schema versions below the published contract versions.
  The versions listed in docs/data-contracts.md are the first public versions;
  nothing older exists.
