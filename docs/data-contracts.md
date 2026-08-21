# Data contracts

Acta publishes five machine-readable contracts under [`schemas/`](../schemas/):

- `runtime-bundle.schema.json` — launcher input, schema version 1
- `run-record.schema.json` — `run.json`, schema version 2
- `digest.schema.json` — `digest.json`, schema version 2
- `acta-event.schema.json` — each `acta-events.jsonl` line, schema version 2
- `projection.schema.json` — the transactional re-projection completion
  manifest, schema version 2

Representative files are in [`schemas/examples/`](../schemas/examples/). JSONL
is validated one object per line.

Every Acta-owned output carries `schema_version` and producer identity. A
producer has `name`, release/development `version`, source `commit`, and build
`date`; name and version are required in current schemas. Raw provider streams
are vendor evidence and do not use Acta schema versions.

## Compatibility rules

- The schema versions listed above are the first published versions of each
  contract. Nothing older exists publicly, and readers reject lower versions
  outright.
- Adding an optional field without changing existing meaning is compatible
  and may retain the current schema version.
- Removing or renaming a field, changing a field's type or semantics, changing
  event ordering invariants, or making an optional field required is breaking
  and requires a schema-version increment.
- Writers emit only the current version. Readers may support documented older
  versions, normalize them in memory, and must reject unknown future versions.
- Re-running `acta digest` writes the current digest/event schemas and records
  the Acta producer that performed the projection. It never rewrites raw
  vendor evidence.
- Consumers must validate the event envelope and sequence, not infer a schema
  from filenames or producer versions.

The Go structs are the implementation source of truth. CI compiles every schema
as Draft 2020-12 with format assertions and local external-reference
resolution, validates every JSON/JSONL example, validates current Go-produced
artifacts, and checks that every exported top-level Go JSON field exists in its
schema. A release that changes a contract must update its schema, example,
changelog, and compatibility notes in the same pull request.

Some cross-entry runtime invariants are intentionally enforced by the loader
because portable JSON Schema cannot compare arbitrary sibling-array values:
capability IDs, effective Codex config keys, and MCP server slugs must be
unique, and an MCP tool cannot appear in both enabled and disabled sets. Schema
validation never replaces `runtimebundle.Prepare` validation before execution.
