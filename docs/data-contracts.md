# Data contracts

Acta publishes five machine-readable contracts under [`schemas/`](../schemas/):

- `runtime-bundle.schema.json` — launcher input, schema version 1
- `run-record.schema.json` — `run.json`, schema version 3; the frozen v2
  contract is `run-record.v2.schema.json`
- `digest.schema.json` — `digest.json`, schema version 3; the frozen v2
  contract is `digest.v2.schema.json`
- `acta-event.schema.json` — each `acta-events.jsonl` line, schema version 3
  (the frozen v2 contract is `acta-event.v2.schema.json`)
- `projection.schema.json` — the transactional re-projection completion
  manifest, schema version 3 (readers also accept v2)

Representative files are in [`schemas/examples/`](../schemas/examples/). JSONL
is validated one object per line.

Every Acta-owned output carries `schema_version` and producer identity. A
producer has `name`, release/development `version`, source `commit`, and build
`date`; name and version are required in current schemas. Raw provider streams
are vendor evidence and do not use Acta schema versions.

## Compatibility rules

- Version 2 is the first published run-record, digest, and Acta-event contract;
  v3 extends their closed `otlp_status` enums with `not_sampled` and `pending`, adds run
  redaction/publication state and withheld-artifact metadata, and lets events
  identify a regenerating producer separately. Readers accept both, but reject
  these v3-only fields and values in a v2 artifact. The versions listed for the
  other contracts are their first published versions, and readers reject lower
  versions outright.
- Projection manifest v3 hash-pins `run.json` in addition to the digest and
  event stream; v2 manifests pin only the derived pair.
- Adding an optional field without changing existing meaning is compatible
  and may retain the current schema version.
- Removing or renaming a field, changing a field's type or semantics, changing
  event ordering invariants, or making an optional field required is breaking
  and requires a schema-version increment.
- Writers emit only the current version. Readers may support documented older
  versions, normalize them in memory, and must reject unknown future versions.
- Re-running `acta digest` writes the current digest/event schemas. Regenerated
  events preserve the immutable run-record identity in `producer` and record
  the projecting binary in `regenerated_by`; the digest and projection manifest
  use the projecting producer. Re-digestion never rewrites raw vendor evidence.
- Consumers must validate the event envelope and sequence, not infer a schema
  from filenames or producer versions.

The published schemas are the compatibility source of truth. CI diffs the v2
and v3 schemas to derive every v3-only property path and requires the shared Go
validation/version-stamping registry to match exactly. It also compiles every
schema as Draft 2020-12 with format assertions and local external-reference
resolution, validates every JSON/JSONL example and current Go-produced
artifact, and checks that every exported top-level Go JSON field exists in its
schema. A release that changes a contract must update its schema, example,
changelog, and compatibility notes in the same pull request.

Some cross-entry runtime invariants are intentionally enforced by the loader
because portable JSON Schema cannot compare arbitrary sibling-array values:
capability IDs, effective Codex config keys, and MCP server slugs must be
unique, and an MCP tool cannot appear in both enabled and disabled sets. Schema
validation never replaces `runtimebundle.Prepare` validation before execution.
