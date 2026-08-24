package schemas_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/nobbettt/acta/internal/actaevents"
	"github.com/nobbettt/acta/internal/digest"
	"github.com/nobbettt/acta/internal/runrecord"
	"github.com/nobbettt/acta/internal/runtimebundle"
)

const schemaBase = "https://github.com/Nobbettt/acta/schemas/"

func TestPublishedExamplesValidateAgainstDraft202012Schemas(t *testing.T) {
	schemas := compileSchemas(t)
	tests := []struct {
		path   string
		schema string
		jsonl  bool
	}{
		{path: "runtime-bundle.v1.json", schema: "runtime-bundle.schema.json"},
		{path: "run-record.v3.json", schema: "run-record.schema.json"},
		{path: "digest.v2.json", schema: "digest.schema.json"},
		{path: "acta-events.v2.jsonl", schema: "acta-event.schema.json", jsonl: true},
		{path: "projection.v2.json", schema: "projection.schema.json"},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			validateFile(t, schemas[test.schema], filepath.Join("examples", test.path), test.jsonl)
		})
	}
}

func TestPublishedRunRecordVersionsRemainCompatible(t *testing.T) {
	tests := []struct {
		path       string
		version    int
		otlpStatus string
	}{
		{path: "run-record.v2.json", version: 2, otlpStatus: "not_configured"},
		{path: "run-record.v3.json", version: 3, otlpStatus: "not_sampled"},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join("examples", test.path))
			if err != nil {
				t.Fatal(err)
			}
			var record runrecord.Record
			if err := json.Unmarshal(payload, &record); err != nil {
				t.Fatal(err)
			}
			if record.SchemaVersion != test.version || record.OTLPStatus != test.otlpStatus {
				t.Fatalf("record version/status = %d/%q", record.SchemaVersion, record.OTLPStatus)
			}
			if err := record.Validate(); err != nil {
				t.Fatalf("published record did not parse: %v", err)
			}
		})
	}

	payload, err := os.ReadFile(filepath.Join("examples", "run-record.v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var incompatible runrecord.Record
	if err := json.Unmarshal(payload, &incompatible); err != nil {
		t.Fatal(err)
	}
	incompatible.OTLPStatus = "not_sampled"
	if err := incompatible.Validate(); err == nil {
		t.Fatal("v2 run record accepted the v3 not_sampled status")
	}
}

func TestWithheldArtifactManifestValidatesForReplayAndSchema(t *testing.T) {
	event := actaevents.Event{
		SchemaVersion: actaevents.SchemaVersion,
		Producer:      runrecord.Producer{Name: "acta", Version: "test"},
		RunID:         "run-1",
		Sequence:      1,
		Timestamp:     time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC),
		Source:        actaevents.Source,
		Type:          actaevents.TypeRunCompleted,
		Payload:       json.RawMessage(`{"status":"ok","ok":true,"timeout":false,"duration_ms":1}`),
		ArtifactRefs: []actaevents.ArtifactRef{{
			Kind: "raw_stderr", Path: "agent.stderr.log",
			Status: actaevents.ArtifactStatusWithheld, Reason: "reasoning_redaction_unverified",
			RedactionState: actaevents.ArtifactRedactionStateUnverified,
		}},
	}
	if err := actaevents.ValidateEvent(event, "run-1", 1); err != nil {
		t.Fatalf("replay validator rejected withheld artifact manifest: %v", err)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	validateJSON(t, compileSchemas(t)["acta-event.schema.json"], encoded)
}

func TestGoProducedCurrentArtifactsValidateAgainstPublishedSchemas(t *testing.T) {
	schemas := compileSchemas(t)
	producer := runrecord.Producer{Name: "acta", Version: "v0.1.0", Commit: "abc", Date: "2026-08-19T10:00:00Z"}
	now := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	exit := 0

	artifacts := []struct {
		name   string
		schema string
		value  any
	}{
		{
			name: "runtime bundle", schema: "runtime-bundle.schema.json",
			value: runtimebundle.Bundle{SchemaVersion: 1, Adapter: "codex", Model: "gpt-example", Capabilities: []runtimebundle.Capability{}},
		},
		{
			name: "run record", schema: "run-record.schema.json",
			value: runrecord.Record{
				SchemaVersion: runrecord.SchemaVersion, Producer: producer, ID: "run-example", Agent: "codex", AgentVersion: "0.147.0",
				CWD: "/workspace", RunDir: "/workspace/.acta/runs/run-example", Command: []string{"codex", "exec"},
				StartedAt: now, CompletedAt: now.Add(time.Second), DurationMillis: 1000, ExitCode: &exit, OK: true, Timeout: false,
				TerminationReason: "completed", RawStdoutPath: "/workspace/.acta/runs/run-example/codex-events.jsonl",
				RawStderrPath: "/workspace/.acta/runs/run-example/codex.stderr.log", RawStdoutArtifact: "codex-events.jsonl",
				RawStderrArtifact: "codex.stderr.log", PromptSource: "flag", OTLPStatus: "not_sampled",
				ProcessContainment: "posix_process_group", AgentConfigMode: "ambient_ephemeral",
			},
		},
		{
			name: "digest", schema: "digest.schema.json",
			value: digest.Digest{
				SchemaVersion: digest.SchemaVersion, Producer: producer, RunID: "run-example", Agent: "codex", AgentVersion: "0.147.0",
				Status: digest.StatusOK, Timeline: []digest.Event{}, Metrics: digest.Metrics{}, Files: []digest.FileTouch{}, HasWorkspaceDiff: false,
			},
		},
		{
			name: "Acta event", schema: "acta-event.schema.json",
			value: actaevents.Event{
				SchemaVersion: actaevents.SchemaVersion, Producer: producer, RunID: "run-example", Sequence: 1,
				Timestamp: now, Source: actaevents.Source, Type: actaevents.TypeRunStarted,
				Payload: json.RawMessage(`{"agent":"codex","agent_version":"0.147.0","cwd":"/workspace","run_dir":"/workspace/.acta/runs/run-example","prompt_source":"flag","otlp_status":"not_configured"}`),
			},
		},
	}
	for _, artifact := range artifacts {
		t.Run(artifact.name, func(t *testing.T) {
			encoded, err := json.Marshal(artifact.value)
			if err != nil {
				t.Fatal(err)
			}
			validateJSON(t, schemas[artifact.schema], encoded)
		})
	}
}

func TestTopLevelSchemasCoverEveryPublishedGoField(t *testing.T) {
	tests := []struct {
		schema string
		typeOf reflect.Type
	}{
		{schema: "runtime-bundle.schema.json", typeOf: reflect.TypeOf(runtimebundle.Bundle{})},
		{schema: "run-record.schema.json", typeOf: reflect.TypeOf(runrecord.Record{})},
		{schema: "digest.schema.json", typeOf: reflect.TypeOf(digest.Digest{})},
		{schema: "acta-event.schema.json", typeOf: reflect.TypeOf(actaevents.Event{})},
	}
	for _, test := range tests {
		t.Run(test.schema, func(t *testing.T) {
			payload, err := os.ReadFile(test.schema)
			if err != nil {
				t.Fatal(err)
			}
			var document struct {
				Properties map[string]any `json:"properties"`
			}
			if err := json.Unmarshal(payload, &document); err != nil {
				t.Fatal(err)
			}
			for index := 0; index < test.typeOf.NumField(); index++ {
				field := test.typeOf.Field(index)
				if !field.IsExported() {
					continue
				}
				name := strings.Split(field.Tag.Get("json"), ",")[0]
				if name == "" || name == "-" {
					continue
				}
				if _, exists := document.Properties[name]; !exists {
					t.Errorf("Go field %s (%s) is absent from schema properties", field.Name, name)
				}
			}
		})
	}
}

func TestPublishedBundleArtifactIDSchemaAndGoValidatorAgree(t *testing.T) {
	schema := compileSchemas(t)["run-record.schema.json"]
	schemaPayload, err := os.ReadFile("run-record.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Defs struct {
			PublishedBundle struct {
				Properties struct {
					ArtifactID struct {
						Pattern string `json:"pattern"`
					} `json:"artifact_id"`
				} `json:"properties"`
			} `json:"published_bundle"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(schemaPayload, &document); err != nil {
		t.Fatal(err)
	}
	if got := document.Defs.PublishedBundle.Properties.ArtifactID.Pattern; got != runrecord.PublishedBundleArtifactIDPattern {
		t.Fatalf("schema artifact_id pattern = %q, Go pattern = %q", got, runrecord.PublishedBundleArtifactIDPattern)
	}

	basePayload, err := os.ReadFile(filepath.Join("examples", "run-record.v3.json"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		artifactID string
		wantValid  bool
	}{
		{name: "single character", artifactID: "a", wantValid: true},
		{name: "machine ID", artifactID: "Bundle_2026.08-24", wantValid: true},
		{name: "maximum length", artifactID: "a" + strings.Repeat("-", 127), wantValid: true},
		{name: "empty", artifactID: ""},
		{name: "leading dot", artifactID: ".artifact"},
		{name: "leading hyphen", artifactID: "-artifact"},
		{name: "embedded space", artifactID: "artifact id"},
		{name: "NBSP", artifactID: "artifact\u00a0id"},
		{name: "vertical tab", artifactID: "artifact\vid"},
		{name: "slash", artifactID: "artifact/id"},
		{name: "non-ASCII", artifactID: "artifáct"},
		{name: "too long", artifactID: "a" + strings.Repeat("-", 128)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var schemaRecord map[string]any
			if err := json.Unmarshal(basePayload, &schemaRecord); err != nil {
				t.Fatal(err)
			}
			schemaRecord["published_bundle"] = map[string]any{
				"artifact_id": test.artifactID,
				"sha256":      strings.Repeat("a", 64),
			}
			schemaValid := schema.Validate(schemaRecord) == nil

			var goRecord runrecord.Record
			if err := json.Unmarshal(basePayload, &goRecord); err != nil {
				t.Fatal(err)
			}
			goRecord.PublishedBundle = &runrecord.PublishedBundle{
				ArtifactID: test.artifactID,
				SHA256:     strings.Repeat("a", 64),
			}
			goValid := goRecord.Validate() == nil
			if schemaValid != goValid || schemaValid != test.wantValid {
				t.Fatalf("artifact ID %q: schema valid=%v, Go valid=%v, want valid=%v", test.artifactID, schemaValid, goValid, test.wantValid)
			}
		})
	}
}

func TestGoBuiltActaEventStreamValidatesPayloadContracts(t *testing.T) {
	schema := compileSchemas(t)["acta-event.schema.json"]
	now := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	producer := runrecord.Producer{Name: "acta", Version: "v0.1.0", Commit: "abc", Date: "2026-08-19T10:00:00Z"}
	exit := 0
	record := &runrecord.Record{
		SchemaVersion: runrecord.SchemaVersion, Producer: producer, ID: "run-example", Agent: "codex", AgentVersion: "0.147.0",
		CWD: "/workspace", RunDir: "/workspace/.acta/runs/run-example",
		Command: []string{"codex", "exec"}, StartedAt: now, CompletedAt: now.Add(time.Second), DurationMillis: 1000, ExitCode: &exit,
		OK: true, Timeout: false, TerminationReason: "completed", RawStdoutPath: "/workspace/.acta/runs/run-example/codex-events.jsonl",
		RawStderrPath: "/workspace/.acta/runs/run-example/codex.stderr.log", RawStdoutArtifact: "codex-events.jsonl",
		RawStderrArtifact: "codex.stderr.log", PromptSource: "flag", OTLPStatus: "exported", TraceID: "0123456789abcdef0123456789abcdef", RawOutputLimitBytes: 1 << 30,
		WorkspaceDiffLimitBytes: 256 << 20, ProcessContainment: "posix_process_group", AgentConfigMode: "authoritative_bundle",
		RuntimeBundleSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	d := &digest.Digest{
		SchemaVersion: digest.SchemaVersion, Producer: producer, RunID: record.ID, Agent: record.Agent, AgentVersion: record.AgentVersion,
		Status: digest.StatusOK, Timeline: []digest.Event{}, Metrics: digest.Metrics{}, Files: []digest.FileTouch{},
		Termination: digest.Termination{Outcome: digest.OutcomeCompleted, RunnerReason: digest.OutcomeCompleted},
	}
	events, err := actaevents.BuildForBundle("", record, d, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		validateJSON(t, schema, encoded)
	}
}

func compileSchemas(t *testing.T) map[string]*jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	names := []string{"runtime-bundle.schema.json", "run-record.schema.json", "digest.schema.json", "acta-event.schema.json", "projection.schema.json"}
	for _, name := range names {
		payload, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var document any
		if err := json.Unmarshal(payload, &document); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		if err := compiler.AddResource(schemaBase+name, document); err != nil {
			t.Fatalf("add %s: %v", name, err)
		}
	}
	result := make(map[string]*jsonschema.Schema, len(names))
	for _, name := range names {
		schema, err := compiler.Compile(schemaBase + name)
		if err != nil {
			t.Fatalf("compile %s: %v", name, err)
		}
		result[name] = schema
	}
	return result
}

func validateFile(t *testing.T, schema *jsonschema.Schema, path string, jsonl bool) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if !jsonl {
		var value any
		decoder := json.NewDecoder(file)
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(value); err != nil {
			t.Fatalf("validate %s: %v", path, err)
		}
		return
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 16<<20)
	line := 0
	for scanner.Scan() {
		line++
		validateJSON(t, schema, scanner.Bytes())
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if line == 0 {
		t.Fatal("JSONL example is empty")
	}
}

func validateJSON(t *testing.T, schema *jsonschema.Schema, payload []byte) {
	t.Helper()
	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatalf("schema validation: %v\nJSON: %s", err, payload)
	}
}
