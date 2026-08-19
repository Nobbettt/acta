package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nobbettt/acta/internal/runrecord"
)

func TestExecuteRunWithUploadAliases(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	bin := t.TempDir()
	script := fakeCodexScript(
		"cat >/dev/null\n" +
			`printf '{"type":"turn.completed","usage":{"input_tokens":5,"output_tokens":2}}\n'` + "\n")
	if err := os.WriteFile(filepath.Join(bin, "codex"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	var paths []string
	var sawAuth bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("Authorization") == "Bearer dev-token" {
			sawAuth = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cwd := t.TempDir()
	runsDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), []string{
		"run",
		"--agent", "codex",
		"--cwd", cwd,
		"--runs-dir", runsDir,
		"--stream=false",
		"--prompt", "Fix the failing test",
		"--repo", "example-org/example-repo",
		"--issue-number", "123",
		"--issue-title", "Fix the failing test",
		"--backend-url", server.URL,
		"--ingest-token", "dev-token",
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}
	if !sawAuth {
		t.Fatal("Authorization bearer token was not sent")
	}
	if len(paths) < 4 || paths[0] != "/api/ingest/runs" || !strings.HasSuffix(paths[len(paths)-1], "/complete") {
		t.Fatalf("upload paths = %v, want create/events/artifacts/complete", paths)
	}

	runFiles, err := filepath.Glob(filepath.Join(runsDir, "*", "run.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(runFiles) != 1 {
		t.Fatalf("run files = %v, want one run.json", runFiles)
	}
	assertContainsFile(t, runFiles[0], `"repository": "example-org/example-repo"`)
	assertContainsFile(t, runFiles[0], `"issue_number": 123`)
}

func TestExecuteUploadCommandUploadsExistingBundle(t *testing.T) {
	runDir := writeUploadBundle(t)

	var paths []string
	var sawAuth bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("Authorization") == "Bearer upload-token" {
			sawAuth = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), []string{
		"upload",
		"--backend-url", server.URL,
		"--ingest-token", "upload-token",
		runDir,
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Uploaded Acta run run-1") {
		t.Fatalf("stdout = %q, want uploaded message", stdout.String())
	}
	if !sawAuth {
		t.Fatal("Authorization bearer token was not sent")
	}
	want := []string{
		"/api/ingest/runs",
		"/api/ingest/runs/run-1/events",
		"/api/ingest/runs/run-1/artifacts",
		"/api/ingest/runs/run-1/artifacts",
		"/api/ingest/runs/run-1/artifacts",
		"/api/ingest/runs/run-1/complete",
	}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
}

func writeUploadBundle(t *testing.T) string {
	t.Helper()
	runDir := t.TempDir()
	exitCode := 0
	record := runrecord.Record{
		ID:             "run-1",
		Agent:          "codex",
		CWD:            runDir,
		RunDir:         runDir,
		Repository:     "example-org/example-repo",
		IssueNumber:    42,
		IssueTitle:     "Upload existing bundle",
		TaskTitle:      "Upload existing bundle",
		StartedAt:      time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC),
		CompletedAt:    time.Date(2026, 7, 6, 12, 0, 1, 0, time.UTC),
		DurationMillis: 1000,
		ExitCode:       &exitCode,
		OK:             true,
		PromptSource:   "test",
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "run.json"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "digest.json"), []byte(`{"run_id":"run-1"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	events := strings.Join([]string{
		`{"schema_version":1,"run_id":"run-1","sequence":1,"timestamp":"2026-07-06T12:00:00Z","source":"acta","type":"run.started","payload":{}}`,
		`{"schema_version":1,"run_id":"run-1","sequence":2,"timestamp":"2026-07-06T12:00:01Z","source":"acta","type":"run.completed","payload":{"status":"ok"},"artifact_refs":[{"kind":"run_record","path":"run.json"},{"kind":"digest","path":"digest.json"},{"kind":"event_stream","path":"acta-events.jsonl"}]}`,
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(runDir, "acta-events.jsonl"), []byte(events), 0o644); err != nil {
		t.Fatal(err)
	}
	return runDir
}
