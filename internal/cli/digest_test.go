package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nobbettt/acta/internal/runrecord"
)

func writeBundle(t *testing.T, dir string) {
	t.Helper()
	raw := strings.Join([]string{
		`{"type":"thread.started","thread_id":"thread-test"}`,
		`{"type":"turn.started"}`,
		`{"type":"item.completed","item":{"id":"i1","type":"command_execution","command":"ls","status":"completed","exit_code":0}}`,
		`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "codex-events.jsonl"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	exit := 0
	rec := runrecord.Record{
		SchemaVersion:      runrecord.SchemaVersion,
		Producer:           runrecord.Producer{Name: "acta", Version: "test"},
		ID:                 "r1",
		Agent:              "codex",
		AgentVersion:       "test",
		CWD:                dir,
		RunDir:             dir,
		Command:            []string{"codex", "exec"},
		StartedAt:          time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC),
		CompletedAt:        time.Date(2026, 7, 3, 12, 0, 1, 0, time.UTC),
		DurationMillis:     1000,
		ExitCode:           &exit,
		OK:                 true,
		TerminationReason:  "completed",
		RawStdoutPath:      filepath.Join(dir, "codex-events.jsonl"),
		RawStderrPath:      filepath.Join(dir, "codex.stderr.log"),
		RawStdoutArtifact:  "codex-events.jsonl",
		RawStderrArtifact:  "codex.stderr.log",
		PromptSource:       "test",
		OTLPStatus:         "not_configured",
		ProcessContainment: "direct_process",
		AgentConfigMode:    "ambient_ephemeral",
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run.json"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestExecuteDigest(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir)

	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), []string{"digest", dir}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "digest.json")); err != nil {
		t.Fatalf("digest.json not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "acta-events.jsonl")); err != nil {
		t.Fatalf("acta-events.jsonl not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "projection.json")); err != nil {
		t.Fatalf("projection.json not written: %v", err)
	}
	assertProjectionManifest(t, dir)
	assertContainsFile(t, filepath.Join(dir, "acta-events.jsonl"), `"type":"shell.command.completed"`)
	if !strings.Contains(stdout.String(), "digest.json") {
		t.Errorf("stdout = %q, want the written path", stdout.String())
	}
}

func TestExecuteDigestOutsideWorkspacePathIsWarning(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir)
	raw := strings.Join([]string{
		`{"type":"thread.started","thread_id":"thread-test"}`,
		`{"type":"turn.started"}`,
		`{"type":"item.completed","item":{"id":"i1","type":"file_change","status":"completed","changes":[{"path":"/etc/hosts","kind":"update"}]}}`,
		`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "codex-events.jsonl"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := Execute(context.Background(), []string{"digest", dir}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}
	if got := stderr.String(); !strings.Contains(got, "capture warning: file_change dropped 1 path(s)") ||
		!strings.Contains(got, "raw_event_lines=[3]") || strings.Contains(got, "--allow-partial") {
		t.Fatalf("stderr = %q", got)
	}
	assertContainsFile(t, filepath.Join(dir, "digest.json"), `"status": "ok"`)
	assertContainsFile(t, filepath.Join(dir, "digest.json"), `capture warning: file_change dropped 1 path(s)`)
}

func TestExecuteDigestRequiresExplicitPartialReplacement(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir)
	rawPath := filepath.Join(dir, "codex-events.jsonl")
	raw, err := os.ReadFile(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rawPath, append(raw, []byte("not-json\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	oldDigest := []byte("preserve prior digest\n")
	oldEvents := []byte("preserve prior events\n")
	if err := os.WriteFile(filepath.Join(dir, "digest.json"), oldDigest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "acta-events.jsonl"), oldEvents, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := Execute(context.Background(), []string{"digest", dir}, strings.NewReader(""), &stdout, &stderr); code != 1 {
		t.Fatalf("default partial digest exit = %d, stderr = %q", code, stderr.String())
	}
	for path, want := range map[string][]byte{
		filepath.Join(dir, "digest.json"):       oldDigest,
		filepath.Join(dir, "acta-events.jsonl"): oldEvents,
	} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s changed without --allow-partial: got %q err=%v", path, got, err)
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := Execute(context.Background(), []string{"digest", "--allow-partial", dir}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("allowed partial digest exit = %d, stderr = %q", code, stderr.String())
	}
	assertContainsFile(t, filepath.Join(dir, "digest.json"), `"status": "degraded"`)
	if _, err := os.Stat(filepath.Join(dir, "projection.json")); err != nil {
		t.Fatalf("partial projection manifest missing: %v", err)
	}
	assertProjectionManifest(t, dir)
}

func assertProjectionManifest(t *testing.T, dir string) {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(dir, "projection.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		SchemaVersion int    `json:"schema_version"`
		RunSHA256     string `json:"run_sha256"`
		DigestSHA256  string `json:"digest_sha256"`
		EventsSHA256  string `json:"events_sha256"`
	}
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != 3 {
		t.Fatalf("projection schema_version = %d, want 3", manifest.SchemaVersion)
	}
	for name, want := range map[string]string{
		"run.json":          manifest.RunSHA256,
		"digest.json":       manifest.DigestSHA256,
		"acta-events.jsonl": manifest.EventsSHA256,
	} {
		artifact, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(artifact)); got != want {
			t.Fatalf("%s hash = %s, manifest = %s", name, got, want)
		}
	}
}

func TestExecuteDigestNoRunDir(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), []string{"digest"}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("missing run-dir arg should exit 2, got %d", code)
	}
}

func TestExecuteDigestMissingBundle(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), []string{"digest", filepath.Join(t.TempDir(), "nope")}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("missing bundle should exit 1, got %d (stderr %q)", code, stderr.String())
	}
}

func assertContainsFile(t *testing.T, path string, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), want) {
		t.Fatalf("%s does not contain %q; contents:\n%s", path, want, data)
	}
}
