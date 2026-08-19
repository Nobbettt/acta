# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and Semantic Versioning. Dates use ISO 8601.

## Unreleased

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

Breaking changes for the first public release are collected here until a
versioned release section is cut.
