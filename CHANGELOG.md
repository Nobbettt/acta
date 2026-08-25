# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and Semantic Versioning. Dates use ISO 8601.

## Unreleased

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
