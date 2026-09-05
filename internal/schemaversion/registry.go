// Package schemaversion owns the field-level compatibility boundary between
// Acta's published v2 and v3 JSON documents.
package schemaversion

import (
	"encoding/json"
	"slices"
	"sort"
	"strings"
)

// DocumentType identifies one independently versioned Acta document.
type DocumentType string

const (
	RunRecord DocumentType = "run-record"
	Digest    DocumentType = "digest"
	Event     DocumentType = "acta-event"
)

// Field identifies a v3-only property by document type and JSON-pointer-like
// path. A * segment matches every element of an array.
type Field struct {
	Document DocumentType
	Path     string
}

// v3OnlyFields is the single production registry consumed by every v2 field
// validator and by remote-rewrite version stamping. Its completeness is
// checked against the published v2 and v3 schemas in schemas/contracts_test.go.
var v3OnlyFields = []Field{
	{Document: RunRecord, Path: "/published_bundle"},
	{Document: RunRecord, Path: "/reasoning_redaction_state"},
	{Document: Digest, Path: "/timeline/*/categories"},
	{Document: Digest, Path: "/timeline/*/redacted"},
	{Document: Digest, Path: "/timeline/*/observation_status"},
	{Document: Digest, Path: "/timeline/*/observed_effects"},
	{Document: Digest, Path: "/timeline/*/shell_mutations"},
	{Document: Digest, Path: "/timeline/*/targets"},
	{Document: Digest, Path: "/timeline/*/text_chars"},
	{Document: Digest, Path: "/timeline/*/text_truncated"},
	{Document: Event, Path: "/artifact_refs/*/reason"},
	{Document: Event, Path: "/artifact_refs/*/redaction_state"},
	{Document: Event, Path: "/artifact_refs/*/status"},
	{Document: Event, Path: "/payload/categories"},
	{Document: Event, Path: "/payload/file_patch_errors"},
	{Document: Event, Path: "/payload/reasoning_redaction_state"},
	{Document: Event, Path: "/payload/redacted"},
	{Document: Event, Path: "/payload/targets"},
	{Document: Event, Path: "/payload/text_chars"},
	{Document: Event, Path: "/payload/text_truncated"},
	{Document: Event, Path: "/regenerated_by"},
}

// V3OnlyFields returns a copy of the registry for schema-completeness checks.
func V3OnlyFields() []Field {
	fields := make([]Field, len(v3OnlyFields))
	copy(fields, v3OnlyFields)
	return fields
}

// PresentV3OnlyFieldsJSON reports v3-only fields present in an encoded
// document. Presence, rather than the decoded Go zero value, is significant:
// false, zero, and null still name a field unavailable in schema v2.
func PresentV3OnlyFieldsJSON(documentType DocumentType, data []byte) ([]string, error) {
	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	return presentV3OnlyFields(documentType, document), nil
}

// PresentV3OnlyFields reports v3-only fields represented by value's JSON
// encoding.
func PresentV3OnlyFields(documentType DocumentType, value any) ([]string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return PresentV3OnlyFieldsJSON(documentType, data)
}

// FirstPresentV3OnlyField combines fields visible in the current Go value with
// fields remembered while decoding. The latter preserves explicit zero-valued
// properties hidden by omitempty when a v2 document is validated.
func FirstPresentV3OnlyField(documentType DocumentType, value any, decodedFields []string) (string, bool, error) {
	present, err := PresentV3OnlyFields(documentType, value)
	if err != nil {
		return "", false, err
	}
	paths := append(present, decodedFields...)
	if len(paths) == 0 {
		return "", false, nil
	}
	return slices.Min(paths), true, nil
}

func presentV3OnlyFields(documentType DocumentType, document any) []string {
	var present []string
	for _, field := range v3OnlyFields {
		if field.Document == documentType && pathPresent(document, splitPath(field.Path)) {
			present = append(present, field.Path)
		}
	}
	sort.Strings(present)
	return present
}

func splitPath(path string) []string {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i := range parts {
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(parts[i], "~1", "/"), "~0", "~")
	}
	return parts
}

func pathPresent(value any, path []string) bool {
	if len(path) == 0 {
		return true
	}
	if path[0] == "*" {
		items, ok := value.([]any)
		if !ok {
			return false
		}
		for _, item := range items {
			if pathPresent(item, path[1:]) {
				return true
			}
		}
		return false
	}
	object, ok := value.(map[string]any)
	if !ok {
		return false
	}
	next, ok := object[path[0]]
	return ok && pathPresent(next, path[1:])
}
