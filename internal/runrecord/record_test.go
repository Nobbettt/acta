package runrecord

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func validRecord() Record {
	exit := 0
	started := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	return Record{
		SchemaVersion:      SchemaVersion,
		Producer:           Producer{Name: "acta", Version: "v0.1.0", Commit: "abc", Date: started.Format(time.RFC3339)},
		ID:                 "run-1",
		Agent:              "codex",
		AgentVersion:       "0.147.0",
		CWD:                "/workspace",
		RunDir:             "/workspace/.acta/runs/run-1",
		Command:            []string{"codex", "exec"},
		StartedAt:          started,
		CompletedAt:        started.Add(time.Second),
		DurationMillis:     1000,
		ExitCode:           &exit,
		OK:                 true,
		TerminationReason:  "completed",
		RawStdoutPath:      "/workspace/.acta/runs/run-1/codex-events.jsonl",
		RawStderrPath:      "/workspace/.acta/runs/run-1/codex.stderr.log",
		RawStdoutArtifact:  "codex-events.jsonl",
		RawStderrArtifact:  "codex.stderr.log",
		PromptSource:       "flag",
		OTLPStatus:         "not_configured",
		ProcessContainment: "posix_process_group",
		AgentConfigMode:    "ambient_ephemeral",
	}
}

func TestParseVersionedOTLPStatus(t *testing.T) {
	tests := []struct {
		name          string
		schemaVersion int
		otlpStatus    string
		wantError     bool
	}{
		{name: "v2 record", schemaVersion: 2, otlpStatus: "not_configured"},
		{name: "v3 not sampled", schemaVersion: 3, otlpStatus: "not_sampled"},
		{name: "v3 pending", schemaVersion: 3, otlpStatus: "pending"},
		{name: "v2 rejects not sampled", schemaVersion: 2, otlpStatus: "not_sampled", wantError: true},
		{name: "v2 rejects pending", schemaVersion: 2, otlpStatus: "pending", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := validRecord()
			record.SchemaVersion = test.schemaVersion
			record.OTLPStatus = test.otlpStatus
			if test.otlpStatus == "pending" {
				record.TraceID = "0123456789abcdef0123456789abcdef"
			}
			payload, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			var parsed Record
			if err := json.Unmarshal(payload, &parsed); err != nil {
				t.Fatal(err)
			}
			err = parsed.Validate()
			if test.wantError && err == nil {
				t.Fatal("versioned parser accepted incompatible OTLP status")
			}
			if !test.wantError && err != nil {
				t.Fatalf("versioned parser rejected record: %v", err)
			}
		})
	}
}

func TestValidateVersionGatesV3Fields(t *testing.T) {
	tests := []struct {
		name  string
		field string
		edit  func(*Record)
	}{
		{
			name:  "reasoning redaction state",
			field: "reasoning_redaction_state",
			edit:  func(record *Record) { record.ReasoningRedactionState = "redacted" },
		},
		{
			name:  "artifact redaction states",
			field: "artifact_redaction_states",
			edit:  func(record *Record) { record.ArtifactRedactionStates = ArtifactRedactionStatesFor(true) },
		},
		{
			name:  "published bundle",
			field: "published_bundle",
			edit: func(record *Record) {
				record.PublishedBundle = &PublishedBundle{ArtifactID: "bundle-1", SHA256: strings.Repeat("a", 64)}
			},
		},
	}
	for _, test := range tests {
		for _, schemaVersion := range []int{2, 3} {
			t.Run(fmt.Sprintf("%s/v%d", test.name, schemaVersion), func(t *testing.T) {
				record := validRecord()
				record.SchemaVersion = schemaVersion
				test.edit(&record)
				err := record.Validate()
				if schemaVersion == 2 {
					if err == nil || !strings.Contains(err.Error(), test.field) {
						t.Fatalf("Validate() error = %v, want unsupported %s", err, test.field)
					}
					return
				}
				if err != nil {
					t.Fatalf("Validate() rejected v3 %s: %v", test.field, err)
				}
			})
		}
	}
}

func TestValidateCurrentRecord(t *testing.T) {
	record := validRecord()
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCurrentRecordInvariants(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Record)
		want string
	}{
		{"agent version", func(r *Record) { r.AgentVersion = "" }, "agent_version"},
		{"termination", func(r *Record) { r.TerminationReason = "future" }, "termination_reason"},
		{"successful exit", func(r *Record) { value := 2; r.ExitCode = &value }, "exit_code 0"},
		{"OTLP trace", func(r *Record) { r.TraceID = "dangling" }, "trace_id"},
		{"containment", func(r *Record) { r.ProcessContainment = "" }, "process_containment"},
		{"config mode", func(r *Record) { r.AgentConfigMode = "" }, "agent_config_mode"},
		{"bundle hash missing", func(r *Record) { r.AgentConfigMode = "authoritative_bundle" }, "runtime_bundle_sha256"},
		{"unexpected bundle hash", func(r *Record) { r.RuntimeBundleSHA256 = strings.Repeat("a", 64) }, "runtime_bundle_sha256"},
		{"successful recovery", func(r *Record) { r.RecoveryDir = "/recovery" }, "recovery_dir"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := validRecord()
			test.edit(&record)
			if err := record.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateRejectsMissingSchemaVersion(t *testing.T) {
	record := Record{ID: "no-version"}
	err := record.Validate()
	if err == nil || !strings.Contains(err.Error(), "unsupported run record schema_version") {
		t.Fatalf("Validate() error = %v, want unsupported schema_version", err)
	}
}

func TestArtifactRedactionStatesForAttestsOnlyAnExistingWorkspaceDiff(t *testing.T) {
	if got := ArtifactRedactionStatesFor(false); got != nil {
		t.Fatalf("ArtifactRedactionStatesFor(false) = %v, want nil", got)
	}
	got := ArtifactRedactionStatesFor(true)
	if len(got) != 1 || got["workspace_diff"] != "not_required" {
		t.Fatalf("ArtifactRedactionStatesFor(true) = %v, want only workspace_diff not_required", got)
	}
}

func TestArtifactRedactionStatesRoundTrip(t *testing.T) {
	for _, hasDiff := range []bool{true, false} {
		t.Run(fmt.Sprintf("diff=%v", hasDiff), func(t *testing.T) {
			record := validRecord()
			record.ArtifactRedactionStates = ArtifactRedactionStatesFor(hasDiff)
			payload, err := MarshalFile(&record)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(payload), "artifact_redaction_states") != hasDiff {
				t.Fatalf("artifact_redaction_states presence != %v in:\n%s", hasDiff, payload)
			}
			var parsed Record
			if err := json.Unmarshal(payload, &parsed); err != nil {
				t.Fatal(err)
			}
			if err := parsed.Validate(); err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(parsed.ArtifactRedactionStates) != fmt.Sprint(record.ArtifactRedactionStates) {
				t.Fatalf("round trip = %v, want %v", parsed.ArtifactRedactionStates, record.ArtifactRedactionStates)
			}
		})
	}
}

func TestValidateRejectsAttestationsBeyondTheWorkspaceDiff(t *testing.T) {
	for _, states := range []map[string]string{
		{"raw_stderr": "not_required"},
		{"raw_stdout": "redacted"},
		{"workspace_diff": "redacted"},
		{"workspace_diff": ""},
	} {
		record := validRecord()
		record.ArtifactRedactionStates = states
		if err := record.Validate(); err == nil || !strings.Contains(err.Error(), "artifact_redaction_states") {
			t.Fatalf("Validate(%v) error = %v, want artifact_redaction_states rejection", states, err)
		}
	}
}
