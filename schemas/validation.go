// Package schemas exposes validation at runtime for Acta's published JSON
// contracts. The schema documents are embedded so installed binaries enforce
// the same payload contracts as the repository examples and contract tests.
package schemas

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

const schemaBase = "https://github.com/Nobbettt/acta/schemas/"

//go:embed acta-event.v2.schema.json acta-event.schema.json run-record.v2.schema.json run-record.schema.json
var eventSchemaFiles embed.FS

var loadEventSchemas = sync.OnceValues(func() (map[int]*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	names := []string{
		"run-record.v2.schema.json",
		"run-record.schema.json",
		"acta-event.v2.schema.json",
		"acta-event.schema.json",
	}
	for _, name := range names {
		payload, err := eventSchemaFiles.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("read embedded schema %s: %w", name, err)
		}
		var document any
		if err := json.Unmarshal(payload, &document); err != nil {
			return nil, fmt.Errorf("parse embedded schema %s: %w", name, err)
		}
		if err := compiler.AddResource(schemaBase+name, document); err != nil {
			return nil, fmt.Errorf("add embedded schema %s: %w", name, err)
		}
	}

	result := make(map[int]*jsonschema.Schema, 2)
	for version, name := range map[int]string{
		2: "acta-event.v2.schema.json",
		3: "acta-event.schema.json",
	} {
		schema, err := compiler.Compile(schemaBase + name)
		if err != nil {
			return nil, fmt.Errorf("compile embedded schema %s: %w", name, err)
		}
		result[version] = schema
	}
	return result, nil
})

// ValidateEventPayload validates payload against the closed per-type payload
// contract selected by schemaVersion and eventType. Stable placeholder envelope
// fields let the published event schema own the type-to-payload mapping while
// callers continue to validate the real envelope and stream ordering separately.
func ValidateEventPayload(schemaVersion int, eventType string, payload []byte) error {
	schemaByVersion, err := loadEventSchemas()
	if err != nil {
		return err
	}
	schema, ok := schemaByVersion[schemaVersion]
	if !ok {
		return fmt.Errorf("unsupported event schema_version %d", schemaVersion)
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode payload: multiple JSON values")
		}
		return fmt.Errorf("decode payload: %w", err)
	}

	event := map[string]any{
		"schema_version": schemaVersion,
		"producer":       map[string]any{"name": "acta", "version": "payload-validation"},
		"run_id":         "payload-validation",
		"sequence":       1,
		"timestamp":      "2000-01-01T00:00:00Z",
		"source":         "acta",
		"type":           eventType,
		"payload":        decoded,
	}
	if err := schema.Validate(event); err != nil {
		return fmt.Errorf("schema-v%d %s payload does not match the published schema: %w", schemaVersion, eventType, err)
	}
	return nil
}
