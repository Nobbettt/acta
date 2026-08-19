package digest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nobbettt/acta/internal/runrecord"
)

func TestFromRunDirUsesRecordRawPath(t *testing.T) {
	dir := t.TempDir()
	rawName := "codex-events.jsonl"
	raw := `{"type":"thread.started","thread_id":"t-1"}` + "\n" +
		`{"type":"turn.started"}` + "\n" +
		`{"type":"item.completed","item":{"id":"i1","type":"command_execution","command":"ls","status":"completed","exit_code":0}}` + "\n" +
		`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, rawName), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := runrecord.Record{ID: "r1", Agent: "codex", CWD: dir, RunDir: dir, RawStdoutPath: filepath.Join(dir, rawName)}
	writeRecord(t, dir, rec)

	d, err := FromRunDir(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Metrics.Commands != 1 {
		t.Fatalf("commands = %d, want 1 (raw stream read via record path)", d.Metrics.Commands)
	}

	// A record with no raw stdout path is a hard error rather than a guess.
	rec.RawStdoutPath = ""
	writeRecord(t, dir, rec)
	if _, err := FromRunDir(dir, ""); err == nil {
		t.Fatal("expected an error when the record has no raw stdout path")
	}
}

func TestFromRunDirAttributesProjectionToCurrentProducer(t *testing.T) {
	dir := t.TempDir()
	rawName := "codex-events.jsonl"
	stderrName := "codex.stderr.log"
	raw := strings.Join([]string{
		`{"type":"thread.started","thread_id":"t-1"}`,
		`{"type":"turn.started"}`,
		`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, rawName), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, stderrName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	exit := 0
	started := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	rec := runrecord.Record{
		SchemaVersion:      runrecord.SchemaVersion,
		Producer:           runrecord.Producer{Name: "acta", Version: "v0.0.1", Commit: "old"},
		ID:                 "r-current-producer",
		Agent:              "codex",
		AgentVersion:       "0.147.0",
		CWD:                dir,
		RunDir:             dir,
		Command:            []string{"codex", "exec"},
		StartedAt:          started,
		CompletedAt:        started.Add(time.Second),
		DurationMillis:     1000,
		ExitCode:           &exit,
		OK:                 true,
		TerminationReason:  "completed",
		RawStdoutPath:      filepath.Join(dir, rawName),
		RawStderrPath:      filepath.Join(dir, stderrName),
		RawStdoutArtifact:  rawName,
		RawStderrArtifact:  stderrName,
		PromptSource:       "flag",
		OTLPStatus:         "not_configured",
		ProcessContainment: "posix_process_group",
		AgentConfigMode:    "ambient_ephemeral",
	}
	writeRecord(t, dir, rec)

	d, err := FromRunDir(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Producer.Name != "acta" || d.Producer.Version == "v0.0.1" || d.Producer.Commit == "old" {
		t.Fatalf("projection producer = %+v, historical producer = %+v", d.Producer, rec.Producer)
	}
}

func writeRecord(t *testing.T, dir string, rec runrecord.Record) {
	t.Helper()
	payload, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run.json"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
}
