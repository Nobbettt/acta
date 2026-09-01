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

// ValidateEvent validates a complete event envelope against the published
// schema selected by schemaVersion.
func ValidateEvent(schemaVersion int, encoded []byte) error {
	event, err := decodeDocument(encoded, "event")
	if err != nil {
		return err
	}
	if err := validateEventDocument(schemaVersion, event); err != nil {
		return fmt.Errorf("schema-v%d event does not match the published schema: %w", schemaVersion, err)
	}
	return nil
}

func validateEventDocument(schemaVersion int, event any) error {
	schemaByVersion, err := loadEventSchemas()
	if err != nil {
		return err
	}
	schema, ok := schemaByVersion[schemaVersion]
	if !ok {
		return fmt.Errorf("unsupported event schema_version %d", schemaVersion)
	}
	if err := schema.Validate(event); err != nil {
		return err
	}
	return nil
}

func decodeDocument(encoded []byte, name string) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode %s: multiple JSON values", name)
		}
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}
	return decoded, nil
}
