package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/nobbettt/acta/internal/runner"
)

func fakeCodexScript(body string) string {
	return "#!/bin/sh\n" +
		`if [ "${1:-}" = "--version" ]; then printf 'codex-cli 0.147.0\n'; exit 0; fi` + "\n" +
		`printf '{"type":"thread.started","thread_id":"thread-test"}\n'` + "\n" +
		`printf '{"type":"turn.started"}\n'` + "\n" +
		body
}

// End-to-end through the CLI layer: `acta run` with a fake codex agent on PATH
// must produce a complete bundle (run.json + raw stream + digest.json) and exit
// 0. Table-driven over the three prompt sources so runCommand's prompt
// resolution (flag / trailing args / piped stdin) is all exercised.
func TestExecuteRunEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	bin := t.TempDir()
	script := fakeCodexScript(
		"cat >/dev/null\n" +
			`printf '{"type":"item.completed","item":{"id":"i1","type":"command_execution","command":"ls","status":"completed","exit_code":0}}\n'` + "\n" +
			`printf '{"type":"turn.completed","usage":{"input_tokens":5,"output_tokens":2}}\n'` + "\n")
	if err := os.WriteFile(filepath.Join(bin, "codex"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	cases := []struct {
		name       string
		args       []string
		stdin      string
		wantPrompt string
	}{
		{"prompt flag", []string{"--prompt", "do it"}, "", "do it"},
		{"prompt args", []string{"do", "it"}, "", "do it"},
		{"prompt stdin", nil, "do it from stdin\n", "do it from stdin\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cwd := t.TempDir()
			runsDir := t.TempDir()
			writableDir := t.TempDir()
			args := append([]string{"run", "--agent", "codex", "--cwd", cwd, "--runs-dir", runsDir, "--stream=false", "--capture-prompt", "--agent-writable-dir", writableDir}, c.args...)

			var stdout, stderr bytes.Buffer
			code := Execute(context.Background(), args, strings.NewReader(c.stdin), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
			}

			digests, _ := filepath.Glob(filepath.Join(runsDir, "*", "digest.json"))
			if len(digests) != 1 {
				t.Fatalf("expected one digest.json under %s, got %v (stderr %q)", runsDir, digests, stderr.String())
			}
			data, err := os.ReadFile(digests[0])
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), `"commands": 1`) {
				t.Errorf("digest.json missing the command:\n%s", data)
			}
			events := filepath.Join(filepath.Dir(digests[0]), "acta-events.jsonl")
			eventData, err := os.ReadFile(events)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(eventData), `"type":"shell.command.completed"`) {
				t.Errorf("acta-events.jsonl missing command event:\n%s", eventData)
			}
			lines := strings.Split(strings.TrimSpace(string(eventData)), "\n")
			var promptEvent struct {
				Type    string `json:"type"`
				Payload struct {
					Text string `json:"text"`
				} `json:"payload"`
			}
			if err := json.Unmarshal([]byte(lines[0]), &promptEvent); err != nil {
				t.Fatal(err)
			}
			if promptEvent.Type != "agent.prompt" || promptEvent.Payload.Text != c.wantPrompt {
				t.Errorf("first event = %#v, want captured prompt %q", promptEvent, c.wantPrompt)
			}
		})
	}
}

func TestExecuteRunUsesDistinctTelemetryOnlyExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agent requires /bin/sh")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "codex"), []byte(fakeCodexScript(
		`printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'`+"\n",
	)), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	runsDir := filepath.Join(t.TempDir(), "runs")
	var stderr bytes.Buffer
	code := Execute(context.Background(), []string{
		"run", "--agent", "codex", "--prompt", "test", "--runs-dir", runsDir,
		"--otlp-endpoint", "http://127.0.0.1:1/v1/traces",
		"--otlp-export-failure-policy", "required",
	}, strings.NewReader(""), io.Discard, &stderr)
	if code != runner.TelemetryOnlyFailureExitCode {
		t.Fatalf("exit code = %d, want %d; stderr=%q", code, runner.TelemetryOnlyFailureExitCode, stderr.String())
	}
	records, err := filepath.Glob(filepath.Join(runsDir, "*", "run.json"))
	if err != nil || len(records) != 1 {
		t.Fatalf("run records = %#v, err=%v", records, err)
	}
	var record struct {
		OK         bool   `json:"ok"`
		OTLPStatus string `json:"otlp_status"`
	}
	payload, err := os.ReadFile(records[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, &record); err != nil {
		t.Fatal(err)
	}
	if !record.OK || record.OTLPStatus != "failed" {
		t.Fatalf("run record = %#v, want successful outcome plus OTLP failure", record)
	}
}

func TestExecuteRunRejectsConflictingOTLPPolicyFlagsAtStartup(t *testing.T) {
	var stderr bytes.Buffer
	code := Execute(context.Background(), []string{
		"run", "--otlp-best-effort", "--otlp-export-failure-policy", "required",
	}, strings.NewReader(""), io.Discard, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "--otlp-best-effort") || !strings.Contains(stderr.String(), "--otlp-export-failure-policy") {
		t.Fatalf("exit = %d, stderr = %q; want startup conflict naming both flags", code, stderr.String())
	}
}

func TestExecuteRunRejectsInvalidOTLPPolicyDespiteDeprecatedBestEffort(t *testing.T) {
	var stderr bytes.Buffer
	code := Execute(context.Background(), []string{
		"run", "--agent", "codex", "--prompt", "test", "--cwd", t.TempDir(),
		"--otlp-best-effort", "--otlp-export-failure-policy", "garbage",
	}, strings.NewReader(""), io.Discard, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "--otlp-export-failure-policy must be") {
		t.Fatalf("exit = %d, stderr = %q; want invalid policy error", code, stderr.String())
	}
}

func TestExecuteRunDeprecatedOTLPBestEffortWarnsAndRuns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agent requires /bin/sh")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "codex"), []byte(fakeCodexScript(
		`printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'`+"\n",
	)), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	var stderr bytes.Buffer
	code := Execute(context.Background(), []string{
		"run", "--agent", "codex", "--prompt", "test", "--cwd", t.TempDir(),
		"--runs-dir", t.TempDir(), "--stream=false", "--otlp-best-effort",
	}, strings.NewReader(""), io.Discard, &stderr)
	if code != 0 || !strings.Contains(stderr.String(), "--otlp-best-effort is deprecated") {
		t.Fatalf("exit = %d, stderr = %q; want successful run with deprecation warning", code, stderr.String())
	}
}

func TestExecuteRunReadsIssueBodyFile(t *testing.T) {
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

	issueBody := "# Issue basis\n\nUse this text.\n"
	issueBodyFile := filepath.Join(t.TempDir(), "issue.md")
	if err := os.WriteFile(issueBodyFile, []byte(issueBody), 0o644); err != nil {
		t.Fatal(err)
	}

	cwd := t.TempDir()
	runsDir := t.TempDir()
	prompt := "prompt text must not become issue metadata"
	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), []string{
		"run",
		"--agent", "codex",
		"--cwd", cwd,
		"--runs-dir", runsDir,
		"--stream=false",
		"--prompt", prompt,
		"--title", "separate task title",
		"--issue-body-file", issueBodyFile,
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}

	runFiles, err := filepath.Glob(filepath.Join(runsDir, "*", "run.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(runFiles) != 1 {
		t.Fatalf("run files = %v, want one run.json", runFiles)
	}
	data, err := os.ReadFile(runFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		IssueBody *string `json:"issue_body"`
	}
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if record.IssueBody == nil || *record.IssueBody != issueBody {
		t.Fatalf("issue_body = %#v, want %q", record.IssueBody, issueBody)
	}
	if strings.Contains(string(data), prompt) {
		t.Fatalf("run.json stored prompt text:\n%s", data)
	}
}

func TestExecuteRunReadsIssueBodyFileBeforeAgentStarts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "agent-started")
	script := "#!/bin/sh\n" +
		`touch "$ACTA_FAKE_AGENT_MARKER"` + "\n" +
		"cat >/dev/null\n"
	if err := os.WriteFile(filepath.Join(bin, "codex"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ACTA_FAKE_AGENT_MARKER", marker)

	cwd := t.TempDir()
	runsDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), []string{
		"run",
		"--agent", "codex",
		"--cwd", cwd,
		"--runs-dir", runsDir,
		"--stream=false",
		"--prompt", "do it",
		"--issue-body-file", filepath.Join(t.TempDir(), "missing.md"),
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "read issue body file") {
		t.Fatalf("stderr = %q, want issue-body-file read error", stderr.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("agent marker stat err = %v, want not exist", err)
	}
	runFiles, err := filepath.Glob(filepath.Join(runsDir, "*", "run.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(runFiles) != 0 {
		t.Fatalf("run files = %v, want none", runFiles)
	}
}

func TestReadIssueBodyFileRejectsOversizedContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issue.md")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", int(runner.MaxIssueBodyBytes)+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readIssueBodyFile(path); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("readIssueBodyFile() error = %v, want byte-limit rejection", err)
	}
}

func TestExecuteRunScrubsIngestTokenEnvFromAgent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	bin := t.TempDir()
	script := fakeCodexScript(
		`if [ "${ACTA_TEST_INGEST_TOKEN+x}" = x ]; then echo "ingest token env leaked to agent" >&2; exit 23; fi` + "\n" +
			"cat >/dev/null\n" +
			`printf '{"type":"turn.completed","usage":{"input_tokens":5,"output_tokens":2}}\n'` + "\n")
	if err := os.WriteFile(filepath.Join(bin, "codex"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ACTA_TEST_INGEST_TOKEN", "token-1")

	var mu sync.Mutex
	var paths []string
	var authFailures []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		if auth := r.Header.Get("Authorization"); auth != "Bearer token-1" {
			authFailures = append(authFailures, auth)
		}
		mu.Unlock()
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
		"--prompt", "do it",
		"--backend-url", server.URL,
		"--ingest-token-env", "ACTA_TEST_INGEST_TOKEN",
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(paths) == 0 {
		t.Fatal("expected hybrid upload requests")
	}
	if len(authFailures) != 0 {
		t.Fatalf("upload auth headers = %q, want bearer token", authFailures)
	}
}
