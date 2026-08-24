package runrecord

import (
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

func TestValidateAllowsNotSampledWithoutTraceID(t *testing.T) {
	record := validRecord()
	record.OTLPStatus = "not_sampled"
	record.TraceID = ""
	if err := record.Validate(); err != nil {
		t.Fatalf("Validate() rejected not_sampled record: %v", err)
	}
}

func TestValidateCurrentRecord(t *testing.T) {
	record := validRecord()
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePublishedBundleArtifactIDUsesMachineIDPattern(t *testing.T) {
	sha256 := strings.Repeat("a", 64)
	tests := []struct {
		name       string
		artifactID string
		wantError  bool
	}{
		{name: "plain", artifactID: "artifact-01"},
		{name: "allowed punctuation", artifactID: "A._-9"},
		{name: "maximum length", artifactID: "a" + strings.Repeat("-", 127)},
		{name: "embedded space", artifactID: "artifact id", wantError: true},
		{name: "Unicode NBSP", artifactID: "artifact\u00a0id", wantError: true},
		{name: "vertical tab", artifactID: "artifact\vid", wantError: true},
		{name: "leading dot", artifactID: ".artifact", wantError: true},
		{name: "leading hyphen", artifactID: "-artifact", wantError: true},
		{name: "too long", artifactID: "a" + strings.Repeat("-", 128), wantError: true},
		{name: "empty", artifactID: "", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := validRecord()
			record.PublishedBundle = &PublishedBundle{ArtifactID: test.artifactID, SHA256: sha256}
			err := record.Validate()
			if test.wantError && err == nil {
				t.Fatal("Validate() accepted invalid artifact ID")
			}
			if !test.wantError && err != nil {
				t.Fatalf("Validate() rejected schema-valid artifact ID: %v", err)
			}
		})
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
