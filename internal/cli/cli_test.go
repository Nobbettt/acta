package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/nobbettt/acta/internal/runner"
)

func TestReadPromptFromStdin(t *testing.T) {
	got, err := readPromptFromStdin(strings.NewReader("  hello from stdin\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "  hello from stdin\n" {
		t.Fatalf("prompt = %q", got)
	}
}

func TestReadPromptFromStdinRejectsOversizedPrompt(t *testing.T) {
	_, err := readPromptFromStdin(strings.NewReader(strings.Repeat("x", int(runner.MaxPromptBytes)+1)))
	if err == nil || !strings.Contains(err.Error(), "prompt exceeds") {
		t.Fatalf("error = %v, want prompt size error", err)
	}
}

func TestExecuteRunRejectsOversizedFlagPrompt(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), []string{
		"run", "--agent", "codex", "--prompt", strings.Repeat("x", int(runner.MaxPromptBytes)+1),
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "prompt exceeds") {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
}

func TestExecuteRejectsNegativeTimeouts(t *testing.T) {
	for _, args := range [][]string{
		{"run", "--agent", "codex", "--prompt", "x", "--timeout", "-1s"},
		{"upload", "--run-dir", "run", "--backend-url", "http://localhost", "--ingest-token", "x", "--timeout", "-1s"},
		{"upload", "--run-dir", "run", "--backend-url", "http://localhost", "--ingest-token", "x", "--max-upload-bytes", "-1"},
	} {
		var stdout, stderr bytes.Buffer
		if code := Execute(context.Background(), args, strings.NewReader(""), &stdout, &stderr); code != 2 {
			t.Fatalf("Execute(%v) = %d, stderr = %q; want 2", args, code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "must not be negative") {
			t.Fatalf("Execute(%v) stderr = %q", args, stderr.String())
		}
	}
}

func TestExecuteRunRejectsNegativeCaptureLimits(t *testing.T) {
	for _, testCase := range []struct {
		flagName string
		value    string
	}{
		{"--max-raw-output-bytes", "-1"},
		{"--max-workspace-diff-bytes", "-1"},
		{"--upload-timeout", "-1s"},
		{"--max-upload-bytes", "-1"},
	} {
		var stdout, stderr bytes.Buffer
		code := Execute(context.Background(), []string{
			"run", "--agent", "codex", "--prompt", "x", testCase.flagName, testCase.value,
		}, strings.NewReader(""), &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "must not be negative") {
			t.Fatalf("%s: code = %d, stderr = %q", testCase.flagName, code, stderr.String())
		}
	}
}

func TestExecuteVersion(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Execute(context.Background(), []string{"version"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "commit=") {
		t.Fatalf("version output = %q", stdout.String())
	}
}

func TestExecuteRunRejectsStreamReportMode(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Execute(context.Background(), []string{
		"run",
		"--agent", "codex",
		"--prompt", "x",
		"--report-mode", "stream",
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "stream is not implemented") {
		t.Fatalf("stderr = %q, want stream error", stderr.String())
	}
}

func TestExecuteRunRejectsBackendURLInLocalMode(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Execute(context.Background(), []string{
		"run",
		"--agent", "codex",
		"--prompt", "x",
		"--backend-url", "http://backend.test",
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "requires --report-mode hybrid") {
		t.Fatalf("stderr = %q, want backend-url mode error", stderr.String())
	}
}

func TestExecuteRunRejectsHybridReportModeWithoutToken(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Execute(context.Background(), []string{
		"run",
		"--agent", "codex",
		"--prompt", "x",
		"--report-mode", "hybrid",
		"--backend-url", "http://backend.test",
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--report-token or --report-token-env is required") {
		t.Fatalf("stderr = %q, want report-token mode error", stderr.String())
	}
}

func TestExecuteRunRejectsPartialHybridScope(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Execute(context.Background(), []string{
		"run",
		"--agent", "codex",
		"--prompt", "x",
		"--report-mode", "hybrid",
		"--backend-url", "http://backend.test",
		"--report-token", "secret",
		"--organization-id", "11111111-1111-1111-1111-111111111111",
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "must be provided together") {
		t.Fatalf("stderr = %q, want partial scope error", stderr.String())
	}
}

func TestExecuteRunRejectsScopedHybridWithoutRunID(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Execute(context.Background(), []string{
		"run",
		"--agent", "codex",
		"--prompt", "x",
		"--report-mode", "hybrid",
		"--backend-url", "http://backend.test",
		"--report-token", "secret",
		"--organization-id", "11111111-1111-1111-1111-111111111111",
		"--repository-id", "22222222-2222-2222-2222-222222222222",
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--run-id is required") {
		t.Fatalf("stderr = %q, want run-id scope error", stderr.String())
	}
}

func TestApplyUploadAliasesAcceptsIngestTokenEnv(t *testing.T) {
	reportToken := ""
	reportTokenEnv := ""
	reportMode := "local"

	err := applyUploadAliases(&reportToken, "", &reportTokenEnv, "ACTA_INGEST_TOKEN", &reportMode)
	if err != nil {
		t.Fatal(err)
	}
	if reportTokenEnv != "ACTA_INGEST_TOKEN" {
		t.Fatalf("reportTokenEnv = %q, want alias env", reportTokenEnv)
	}
	if reportMode != "hybrid" {
		t.Fatalf("reportMode = %q, want hybrid", reportMode)
	}
}

func TestApplyUploadAliasesRejectsConflictingTokenEnvAliases(t *testing.T) {
	reportToken := ""
	reportTokenEnv := "FIRST_TOKEN"

	err := applyUploadAliases(&reportToken, "", &reportTokenEnv, "SECOND_TOKEN", nil)
	if err == nil {
		t.Fatal("error = nil, want token env conflict")
	}
	if !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("error = %v, want disagree", err)
	}
}

func TestApplyTokenFromEnvReadsToken(t *testing.T) {
	t.Setenv("ACTA_INGEST_TOKEN", "  secret-token\n")
	reportToken := ""

	if err := applyTokenFromEnv(&reportToken, "ACTA_INGEST_TOKEN"); err != nil {
		t.Fatal(err)
	}
	if reportToken != "secret-token" {
		t.Fatalf("reportToken = %q, want trimmed token", reportToken)
	}
}

func TestApplyTokenFromEnvRejectsDirectTokenAndEnv(t *testing.T) {
	t.Setenv("ACTA_INGEST_TOKEN", "secret-token")
	reportToken := "direct-token"

	err := applyTokenFromEnv(&reportToken, "ACTA_INGEST_TOKEN")
	if err == nil {
		t.Fatal("error = nil, want direct/env conflict")
	}
	if !strings.Contains(err.Error(), "cannot both be provided") {
		t.Fatalf("error = %v, want conflict", err)
	}
}

func TestApplyTokenFromEnvRejectsMissingEnv(t *testing.T) {
	reportToken := ""

	err := applyTokenFromEnv(&reportToken, "ACTA_MISSING_TOKEN")
	if err == nil {
		t.Fatal("error = nil, want missing env")
	}
	if !strings.Contains(err.Error(), "is not set") {
		t.Fatalf("error = %v, want missing env", err)
	}
}

func TestApplyTokenFromEnvRejectsEmptyEnv(t *testing.T) {
	t.Setenv("ACTA_EMPTY_TOKEN", " \n")
	reportToken := ""

	err := applyTokenFromEnv(&reportToken, "ACTA_EMPTY_TOKEN")
	if err == nil {
		t.Fatal("error = nil, want empty env")
	}
	if !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("error = %v, want empty env", err)
	}
}
