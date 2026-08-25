package schemas_test

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/nobbettt/acta/internal/schemaversion"
)

func TestV3OnlyFieldRegistryMatchesPublishedSchemaDiff(t *testing.T) {
	tests := []struct {
		document schemaversion.DocumentType
		v2       string
		v3       string
	}{
		{document: schemaversion.RunRecord, v2: "run-record.v2.schema.json", v3: "run-record.schema.json"},
		{document: schemaversion.Digest, v2: "digest.v2.schema.json", v3: "digest.schema.json"},
		{document: schemaversion.Event, v2: "acta-event.v2.schema.json", v3: "acta-event.schema.json"},
	}

	var derived []schemaversion.Field
	for _, test := range tests {
		v2 := readSchemaDocument(t, test.v2)
		v3 := readSchemaDocument(t, test.v3)
		for _, path := range deriveV3OnlyFieldPaths(v2, v3) {
			derived = append(derived, schemaversion.Field{Document: test.document, Path: path})
		}
	}
	sortFields(derived)
	registered := schemaversion.V3OnlyFields()
	sortFields(registered)
	if !reflect.DeepEqual(registered, derived) {
		t.Fatalf("v3-only field registry does not match published schema diff\nregistry: %#v\nderived:  %#v", registered, derived)
	}
}

func readSchemaDocument(t *testing.T, path string) map[string]any {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return document
}

func deriveV3OnlyFieldPaths(v2, v3 map[string]any) []string {
	paths := make(map[string]struct{})
	diffSchemaProperties(v2, v3, v2, v3, "", paths)
	result := make([]string, 0, len(paths))
	for path := range paths {
		result = append(result, path)
	}
	sort.Strings(result)
	return result
}

func diffSchemaProperties(v2Root, v3Root map[string]any, v2Node, v3Node any, path string, paths map[string]struct{}) {
	v2Object, _ := resolveLocalSchemaRef(v2Root, v2Node).(map[string]any)
	v3Object, ok := resolveLocalSchemaRef(v3Root, v3Node).(map[string]any)
	if !ok {
		return
	}

	v2Properties, _ := v2Object["properties"].(map[string]any)
	v3Properties, _ := v3Object["properties"].(map[string]any)
	for name, v3Property := range v3Properties {
		fieldPath := path + "/" + escapeJSONPointer(name)
		v2Property, exists := v2Properties[name]
		if !exists {
			paths[fieldPath] = struct{}{}
			continue
		}
		diffSchemaProperties(v2Root, v3Root, v2Property, v3Property, fieldPath, paths)
	}

	if v3Items, exists := v3Object["items"]; exists {
		if v2Items, ok := v2Object["items"]; ok {
			diffSchemaProperties(v2Root, v3Root, v2Items, v3Items, path+"/*", paths)
		}
	}

	v2Branches := schemaBranchesByCondition(v2Object["allOf"])
	for condition, v3Branch := range schemaBranchesByCondition(v3Object["allOf"]) {
		v2Branch := v2Branches[condition]
		diffSchemaProperties(v2Root, v3Root, schemaThen(v2Branch), schemaThen(v3Branch), path, paths)
	}
}

func resolveLocalSchemaRef(root map[string]any, node any) any {
	for {
		object, ok := node.(map[string]any)
		if !ok {
			return node
		}
		ref, _ := object["$ref"].(string)
		if !strings.HasPrefix(ref, "#/") {
			return node
		}
		resolved := any(root)
		for _, segment := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			part := strings.ReplaceAll(strings.ReplaceAll(segment, "~1", "/"), "~0", "~")
			container, ok := resolved.(map[string]any)
			if !ok {
				return node
			}
			resolved, ok = container[part]
			if !ok {
				return node
			}
		}
		node = resolved
	}
}

func schemaBranchesByCondition(value any) map[string]map[string]any {
	result := make(map[string]map[string]any)
	branches, _ := value.([]any)
	for index, value := range branches {
		branch, ok := value.(map[string]any)
		if !ok {
			continue
		}
		condition, err := json.Marshal(branch["if"])
		if err != nil {
			condition = []byte(fmt.Sprintf("index:%d", index))
		}
		result[string(condition)] = branch
	}
	return result
}

func schemaThen(branch map[string]any) any {
	if branch == nil {
		return map[string]any{}
	}
	return branch["then"]
}

func escapeJSONPointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func sortFields(fields []schemaversion.Field) {
	sort.Slice(fields, func(i, j int) bool {
		if fields[i].Document != fields[j].Document {
			return fields[i].Document < fields[j].Document
		}
		return fields[i].Path < fields[j].Path
	})
}
