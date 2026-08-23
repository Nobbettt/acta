package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nobbettt/acta/internal/actaevents"
	"github.com/nobbettt/acta/internal/agents"
	"github.com/nobbettt/acta/internal/reporting"
	"github.com/nobbettt/acta/internal/runrecord"
)

func TestRunWritesBundleForFakeCodex(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	cwd := t.TempDir()
	writableDir := t.TempDir()
	agentArgsPath := filepath.Join(t.TempDir(), "agent-args.txt")
	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", `#!/bin/sh
if [ -n "$(ls -A "$ACTA_TEST_RUNS_DIR")" ]; then
  echo "final run bundle was visible while agent was running" >&2
  exit 24
fi
printf '%s\n' "$@" > "$ACTA_TEST_AGENT_ARGS"
cat >/dev/null
printf '{"type":"thread.started"}\n'
printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}\n'
printf 'codex stderr\n' >&2
`)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ACTA_TEST_AGENT_ARGS", agentArgsPath)
	t.Setenv("ACTA_TEST_RUNS_DIR", filepath.Join(cwd, ".acta", "runs"))

	record, err := runForTest(context.Background(), Options{
		Agent:             "codex",
		CWD:               cwd,
		Prompt:            "summarize",
		PromptSource:      "test",
		CapturePrompt:     true,
		Repository:        "example-org/example-repo",
		IssueNumber:       101,
		IssueTitle:        "Record task metadata",
		AgentWritableDirs: []string{writableDir},
		Stream:            false,
	}, bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !record.OK {
		t.Fatalf("record.OK = false, record = %#v", record)
	}
	if record.Agent != "codex" {
		t.Fatalf("agent = %q", record.Agent)
	}
	if record.SchemaVersion != runrecord.SchemaVersion || record.Producer.Name != "acta" || record.Producer.Version == "" {
		t.Fatalf("producer/schema provenance missing: %+v", record)
	}
	if record.AgentVersion != "0.147.0" || record.AgentConfigMode != "ambient_ephemeral" {
		t.Fatalf("agent provenance = version %q config mode %q", record.AgentVersion, record.AgentConfigMode)
	}
	if record.ProcessContainment != processContainmentName() {
		t.Fatalf("process containment = %q, want %q", record.ProcessContainment, processContainmentName())
	}
	if record.RawStdoutArtifact != "codex-events.jsonl" || record.RawStderrArtifact != "codex.stderr.log" {
		t.Fatalf("portable raw artifacts missing: %+v", record)
	}
	if !record.PromptCaptured {
		t.Fatal("record did not mark the prompt as captured")
	}
	if record.Repository != "example-org/example-repo" || record.IssueNumber != 101 || record.IssueTitle != "Record task metadata" || record.TaskTitle != "Record task metadata" {
		t.Fatalf("task metadata not recorded: %#v", record)
	}

	assertFileContains(t, record.RawStdoutPath, `"type":"thread.started"`)
	assertFileContains(t, record.RawStderrPath, "codex stderr")
	assertJSONFile(t, filepath.Join(record.RunDir, "run.json"))
	assertFileContains(t, filepath.Join(record.RunDir, "run.json"), `"repository": "example-org/example-repo"`)
	assertFileContains(t, filepath.Join(record.RunDir, "acta-events.jsonl"), `"type":"run.started"`)
	assertFileContains(t, filepath.Join(record.RunDir, "acta-events.jsonl"), `"type":"agent.prompt"`)
	assertFileContains(t, filepath.Join(record.RunDir, "acta-events.jsonl"), `"text":"summarize"`)
	assertFileContains(t, filepath.Join(record.RunDir, "acta-events.jsonl"), `"type":"tokens.reported"`)
	assertFileContains(t, filepath.Join(record.RunDir, "acta-events.jsonl"), `"type":"run.completed"`)
	runRecord := readFile(t, filepath.Join(record.RunDir, "run.json"))
	if strings.Contains(runRecord, "summarize") {
		t.Fatalf("run.json duplicated the captured prompt:\n%s", runRecord)
	}
	if runtime.GOOS != "windows" {
		assertMode(t, filepath.Join(cwd, ".acta", "runs"), 0o700)
		assertMode(t, record.RunDir, 0o700)
		for _, path := range []string{
			record.RawStdoutPath,
			record.RawStderrPath,
			filepath.Join(record.RunDir, "event-times.jsonl"),
			filepath.Join(record.RunDir, "run.json"),
			filepath.Join(record.RunDir, "digest.json"),
			filepath.Join(record.RunDir, "acta-events.jsonl"),
		} {
			assertMode(t, path, 0o600)
		}
	}
	resolvedWritableDir, err := filepath.EvalSymlinks(writableDir)
	if err != nil {
		t.Fatal(err)
	}
	agentArgs := strings.Split(strings.TrimSpace(readFile(t, agentArgsPath)), "\n")
	if !containsAdjacent(agentArgs, "--cd", cwd) || !containsAdjacent(agentArgs, "--add-dir", resolvedWritableDir) {
		t.Fatalf("agent args = %#v, want explicit project and writable directory", agentArgs)
	}
}

func TestRunKeepsManagedSkillsOutsideAgentWritableDirs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agent requires /bin/sh")
	}
	cwd := t.TempDir()
	stageControlDir := t.TempDir()
	bundlePath := filepath.Join(stageControlDir, "runtime-bundle.json")
	bundle := map[string]any{
		"schema_version": 1,
		"adapter":        "codex",
		"capabilities": []any{map[string]any{
			"id": "review-guide", "name": "Review guide", "kind": "skill",
			"description": "Review safely.",
			"configuration": map[string]any{
				"description": "Review changes safely.", "instructions": "Inspect the diff.",
			},
		}},
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	agentArgsPath := filepath.Join(t.TempDir(), "agent-args.txt")
	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", `#!/bin/sh
printf '%s\n' "$@" > "$ACTA_TEST_AGENT_ARGS"
cat >/dev/null
printf '{"type":"thread.started"}\n'
printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}\n'
`)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ACTA_TEST_AGENT_ARGS", agentArgsPath)

	record, err := runForTest(context.Background(), Options{
		Agent:             "codex",
		Model:             "test-model",
		CWD:               cwd,
		Prompt:            "review",
		PromptSource:      "test",
		RuntimeBundlePath: bundlePath,
		AgentWritableDirs: []string{stageControlDir},
		Stream:            false,
	}, bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	if err != nil {
		t.Fatal(err)
	}
	if record.AgentConfigMode != "authoritative_bundle" || len(record.RuntimeBundleSHA256) != 64 {
		t.Fatalf("runtime bundle provenance = mode %q sha %q", record.AgentConfigMode, record.RuntimeBundleSHA256)
	}

	var skillConfig string
	for _, arg := range strings.Split(strings.TrimSpace(readFile(t, agentArgsPath)), "\n") {
		if strings.Contains(arg, "skills.config=") {
			skillConfig = arg
			break
		}
	}
	if skillConfig == "" {
		t.Fatal("agent args do not contain managed skill configuration")
	}
	if strings.Contains(skillConfig, stageControlDir) {
		t.Fatalf("managed skill was materialized under agent-writable stage control: %s", skillConfig)
	}
	if _, err := os.Stat(filepath.Join(stageControlDir, "managed-skills")); !os.IsNotExist(err) {
		t.Fatalf("agent-writable stage control contains managed skills: %v", err)
	}
}

func TestValidateRetainedContentBoundsReplayableMetadata(t *testing.T) {
	issueBody := strings.Repeat("x", int(MaxIssueBodyBytes)+1)
	tests := []struct {
		name string
		opts Options
	}{
		{"issue body", Options{IssueBody: &issueBody}},
		{"captured prompt", Options{CapturePrompt: true, Prompt: strings.Repeat("x", maxCapturedPromptBytes+1)}},
		{"all prompt sources", Options{Prompt: strings.Repeat("x", int(MaxPromptBytes)+1)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateRetainedContent(test.opts); err == nil || !strings.Contains(err.Error(), "byte limit") {
				t.Fatalf("validateRetainedContent() error = %v, want byte-limit rejection", err)
			}
		})
	}

	exactIssueBody := strings.Repeat("x", int(MaxIssueBodyBytes))
	if err := validateRetainedContent(Options{IssueBody: &exactIssueBody}); err != nil {
		t.Fatalf("exact-limit issue body rejected: %v", err)
	}
	if err := validateRetainedContent(Options{CapturePrompt: true, Prompt: strings.Repeat("x", maxCapturedPromptBytes)}); err != nil {
		t.Fatalf("exact-limit captured prompt rejected: %v", err)
	}
}

// validRunnerTestRecord returns the smallest record that passes
// current-schema validation, for tests whose subject is not record validity.
func validRunnerTestRecord(runDir string) *runrecord.Record {
	exit := 0
	started := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	return &runrecord.Record{
		SchemaVersion:      runrecord.SchemaVersion,
		Producer:           runrecord.Producer{Name: "acta", Version: "test"},
		ID:                 "r1",
		Agent:              "codex",
		AgentVersion:       "test",
		CWD:                runDir,
		RunDir:             runDir,
		Command:            []string{"codex", "exec"},
		StartedAt:          started,
		CompletedAt:        started.Add(time.Second),
		DurationMillis:     1000,
		ExitCode:           &exit,
		OK:                 true,
		TerminationReason:  "completed",
		RawStdoutPath:      filepath.Join(runDir, "codex-events.jsonl"),
		RawStderrPath:      filepath.Join(runDir, "codex.stderr.log"),
		RawStdoutArtifact:  "codex-events.jsonl",
		RawStderrArtifact:  "codex.stderr.log",
		PromptSource:       "test",
		OTLPStatus:         "not_configured",
		ProcessContainment: "direct_process",
		AgentConfigMode:    "ambient_ephemeral",
	}
}

func TestWriteRecordRejectsUnreadableSize(t *testing.T) {
	issueBody := strings.Repeat("x", int(runrecord.MaxRecordBytes))
	record := validRunnerTestRecord(t.TempDir())
	record.IssueBody = &issueBody
	err := WriteRecord(record.RunDir, record)
	if err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("WriteRecord() error = %v, want byte-limit rejection", err)
	}
}

func TestRunRejectsWritableCustomRunsDirBeforeAgentStarts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX runs-root policy does not apply on Windows")
	}
	cwd := t.TempDir()
	runsDir := t.TempDir()
	if err := os.Chmod(runsDir, 0o777); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "agent-started")
	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", "#!/bin/sh\ntouch \"$ACTA_TEST_AGENT_MARKER\"\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ACTA_TEST_AGENT_MARKER", marker)

	_, err := runForTest(context.Background(), Options{
		Agent: "codex", CWD: cwd, RunsDir: runsDir, Prompt: "x", PromptSource: "test", Stream: false,
	}, bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	if err == nil || !strings.Contains(err.Error(), "runs directory is group/world writable") {
		t.Fatalf("Run() error = %v, want writable runs-root rejection", err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("agent started before runs-root rejection; marker stat error = %v", statErr)
	}
	assertMode(t, runsDir, 0o777)
}

func TestValidateAgentWritableDirsRejectsRunBundleOverlap(t *testing.T) {
	runsRoot := t.TempDir()
	runDir := filepath.Join(runsRoot, "run-1")
	if err := os.Mkdir(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{runsRoot, runDir} {
		if _, err := validateAgentWritableDirs([]string{candidate}, runDir); err == nil || !strings.Contains(err.Error(), "run bundle") {
			t.Fatalf("validateAgentWritableDirs(%q) error = %v, want run bundle overlap rejection", candidate, err)
		}
	}
}

func TestVerifyRunsDirDetectsReplacement(t *testing.T) {
	parent := t.TempDir()
	runsDir := filepath.Join(parent, "runs")
	expected, err := prepareRunsDir(runsDir, false)
	if err != nil {
		t.Fatal(err)
	}
	replaced := filepath.Join(parent, "runs-replaced")
	if err := os.Rename(runsDir, replaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(runsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyRunsDir(runsDir, expected); err == nil {
		t.Fatal("replaced runs directory was accepted")
	}
}

func TestPrepareRunsDirRejectsSymlink(t *testing.T) {
	target := t.TempDir()
	path := filepath.Join(t.TempDir(), "runs")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := prepareRunsDir(path, false); err == nil {
		t.Fatal("symlink runs directory was accepted")
	}
}

func TestBundleStagingRejectsTemporaryDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cache")
	if stage, err := createBundleStagingAt(root, t.TempDir(), nil); err == nil {
		_ = os.RemoveAll(stage)
		t.Fatal("temporary staging root was accepted")
	}
}

func TestValidateAgentWritableDirsRejectsSymlink(t *testing.T) {
	runDir := t.TempDir()
	target := t.TempDir()
	symlink := filepath.Join(t.TempDir(), "writable")
	if err := os.Symlink(target, symlink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := validateAgentWritableDirs([]string{symlink}, runDir); err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("validateAgentWritableDirs() error = %v, want symlink rejection", err)
	}
}

func TestValidateAgentWritableDirsResolvesAndDeduplicates(t *testing.T) {
	runDir := t.TempDir()
	writableDir := t.TempDir()
	resolved, err := filepath.EvalSymlinks(writableDir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := validateAgentWritableDirs([]string{writableDir, writableDir}, runDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != resolved {
		t.Fatalf("writable dirs = %#v, want [%q]", got, resolved)
	}
}

func TestRunStoresIssueBodyOnlyWhenProvided(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	cwd := t.TempDir()
	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", `#!/bin/sh
cat >/dev/null
printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'
`)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	issueBody := "# Issue basis\n\nUse this text.\n"
	record, err := runForTest(context.Background(), Options{
		Agent:        "codex",
		CWD:          cwd,
		Prompt:       "prompt text must not be copied into metadata",
		PromptSource: "test",
		IssueBody:    &issueBody,
		TaskTitle:    "separate task title",
		Stream:       false,
	}, bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	if err != nil {
		t.Fatal(err)
	}
	if record.IssueBody == nil || *record.IssueBody != issueBody {
		t.Fatalf("record issue body = %#v, want %q", record.IssueBody, issueBody)
	}

	data, err := os.ReadFile(filepath.Join(record.RunDir, "run.json"))
	if err != nil {
		t.Fatal(err)
	}
	var persisted struct {
		IssueBody *string `json:"issue_body"`
	}
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.IssueBody == nil || *persisted.IssueBody != issueBody {
		t.Fatalf("persisted issue body = %#v, want %q", persisted.IssueBody, issueBody)
	}
	if strings.Contains(string(data), "prompt text must not be copied into metadata") {
		t.Fatalf("run.json stored prompt text:\n%s", data)
	}

	noBodyRecord, err := runForTest(context.Background(), Options{
		Agent:        "codex",
		CWD:          cwd,
		Prompt:       "another prompt that must stay out of run.json",
		PromptSource: "test",
		TaskTitle:    "another task title",
		Stream:       false,
	}, bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	if err != nil {
		t.Fatal(err)
	}
	noBodyData, err := os.ReadFile(filepath.Join(noBodyRecord.RunDir, "run.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(noBodyData), `"issue_body"`) {
		t.Fatalf("run.json stored issue_body without an explicit issue body:\n%s", noBodyData)
	}
	if strings.Contains(string(noBodyData), "another prompt that must stay out of run.json") {
		t.Fatalf("run.json stored prompt text:\n%s", noBodyData)
	}
}

func TestRunHybridReportUploadsCompletedBundle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	cwd := t.TempDir()
	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", `#!/bin/sh
cat >/dev/null
printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}\n'
`)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer token-1" {
			t.Fatalf("Authorization header = %q, want bearer token", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	record, err := runForTest(context.Background(), Options{
		Agent:        "codex",
		CWD:          cwd,
		Prompt:       "summarize",
		PromptSource: "test",
		Stream:       false,
		ReportMode:   "hybrid",
		BackendURL:   server.URL,
		ReportToken:  "token-1",
	}, bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !record.OK {
		t.Fatalf("record.OK = false, record = %#v", record)
	}

	if len(paths) < 4 {
		t.Fatalf("paths = %v, want run, events, at least one artifact, complete", paths)
	}
	if paths[0] != "/api/ingest/runs" {
		t.Fatalf("first path = %q, want create run", paths[0])
	}
	if paths[1] != "/api/ingest/runs/"+record.ID+"/events" {
		t.Fatalf("second path = %q, want events", paths[1])
	}
	if paths[len(paths)-1] != "/api/ingest/runs/"+record.ID+"/complete" {
		t.Fatalf("last path = %q, want complete", paths[len(paths)-1])
	}
	for _, path := range paths[2 : len(paths)-1] {
		if path != "/api/ingest/runs/"+record.ID+"/artifacts" {
			t.Fatalf("middle path = %q, want artifact upload", path)
		}
	}
}

func TestRunHybridUploadFailureDoesNotRewriteExecutionOutcome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	cwd := t.TempDir()
	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", `#!/bin/sh
cat >/dev/null
printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":2}}\n'
`)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	record, err := runForTest(context.Background(), Options{
		Agent:        "codex",
		CWD:          cwd,
		Prompt:       "summarize",
		PromptSource: "test",
		Stream:       false,
		ReportMode:   "hybrid",
		BackendURL:   server.URL,
		ReportToken:  "token-1",
	}, bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	if err == nil || !strings.Contains(err.Error(), "upload report") {
		t.Fatalf("Run() error = %v, want upload failure", err)
	}
	if record == nil || !record.OK {
		t.Fatalf("successful execution was poisoned by upload failure: %#v", record)
	}
	assertFileContains(t, filepath.Join(record.RunDir, "run.json"), `"ok": true`)
	assertFileContains(t, filepath.Join(record.RunDir, "acta-events.jsonl"), `"type":"run.completed"`)
}

func TestRunScrubsReportTokenEnvFromAgent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	cwd := t.TempDir()
	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", `#!/bin/sh
if [ "${ACTA_TEST_REPORT_TOKEN+x}" = x ]; then
  echo "report token env leaked to agent" >&2
  exit 23
fi
cat >/dev/null
printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}\n'
`)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ACTA_TEST_REPORT_TOKEN", "token-1")

	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer token-1" {
			t.Fatalf("Authorization header = %q, want bearer token", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	record, err := runForTest(context.Background(), Options{
		Agent:          "codex",
		CWD:            cwd,
		Prompt:         "summarize",
		PromptSource:   "test",
		Stream:         false,
		ReportMode:     "hybrid",
		BackendURL:     server.URL,
		ReportToken:    "token-1",
		ReportTokenEnv: "ACTA_TEST_REPORT_TOKEN",
	}, bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !record.OK {
		t.Fatalf("record.OK = false, record = %#v", record)
	}
	if len(paths) == 0 {
		t.Fatal("expected hybrid upload requests")
	}
}

func TestRunFlushesUnterminatedJSONLLine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	cwd := t.TempDir()
	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", `#!/bin/sh
cat >/dev/null
printf '{"type":"item.completed","item":{"id":"i1","type":"command_execution","command":"ls","status":"completed","exit_code":0}}\n'
printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}'
`)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	record, err := runForTest(context.Background(), Options{
		Agent:        "codex",
		CWD:          cwd,
		Prompt:       "summarize",
		PromptSource: "test",
		Stream:       false,
	}, bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	if err != nil {
		t.Fatal(err)
	}

	assertFileContains(t, filepath.Join(record.RunDir, "event-times.jsonl"), `"line":1`)
	assertFileContains(t, filepath.Join(record.RunDir, "digest.json"), `"observed_at"`)
	assertFileContains(t, filepath.Join(record.RunDir, "acta-events.jsonl"), `"type":"shell.command.completed"`)
}

func TestRunWritesBundleForFakeClaude(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	cwd := t.TempDir()
	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "claude", `#!/bin/sh
printf '{"type":"system","subtype":"init"}\n'
printf '{"type":"result","result":"done"}\n'
printf 'claude stderr\n' >&2
`)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	record, err := runForTest(context.Background(), Options{
		Agent:        "claude",
		CWD:          cwd,
		Prompt:       "summarize",
		PromptSource: "test",
		Stream:       false,
	}, bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !record.OK {
		t.Fatalf("record.OK = false, record = %#v", record)
	}

	assertFileContains(t, record.RawStdoutPath, `"type":"result"`)
	assertFileContains(t, record.RawStderrPath, "claude stderr")
	assertJSONFile(t, filepath.Join(record.RunDir, "run.json"))
}

func TestRunRecordsNonZeroExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	cwd := t.TempDir()
	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", `#!/bin/sh
printf 'failed\n' >&2
exit 7
`)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	record, err := runForTest(context.Background(), Options{
		Agent:        "codex",
		CWD:          cwd,
		Prompt:       "fail",
		PromptSource: "test",
		Stream:       false,
	}, bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	if err == nil {
		t.Fatal("expected error")
	}
	if record == nil {
		t.Fatal("expected record")
		return
	}
	if record.OK {
		t.Fatal("record.OK = true, want false")
	}
	if record.ExitCode == nil || *record.ExitCode != 7 {
		t.Fatalf("exit code = %#v, want 7", record.ExitCode)
	}
	assertFileContains(t, filepath.Join(record.RunDir, "run.json"), `"exit_code": 7`)
}

func TestRunMarksLocalArtifactFailureInRecordAndEvents(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	cwd := t.TempDir()
	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", `#!/bin/sh
cat >/dev/null
printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'
`)
	writeFakeAgent(t, fakeBin, "git", `#!/bin/sh
case "$1" in
	status)
		printf '# branch.oid (initial)\n# branch.head main\n'
		exit 0
		;;
  rev-parse)
    printf '.git\n'
    exit 0
    ;;
  ls-files)
    exit 0
    ;;
  diff)
    printf 'forced diff failure\n' >&2
    exit 2
    ;;
esac
printf 'unexpected git command: %s\n' "$1" >&2
exit 1
`)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	record, err := runForTest(context.Background(), Options{
		Agent:        "codex",
		CWD:          cwd,
		Prompt:       "summarize",
		PromptSource: "test",
		Stream:       false,
	}, bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	if err == nil {
		t.Fatal("expected local artifact failure")
	}
	if record == nil {
		t.Fatal("expected record")
		return
	}
	if record.OK {
		t.Fatal("record.OK = true, want false")
	}

	assertFileContains(t, filepath.Join(record.RunDir, "run.json"), `"ok": false`)
	assertFileContains(t, filepath.Join(record.RunDir, "run.json"), "workspace diff")
	assertFileContains(t, filepath.Join(record.RunDir, "acta-events.jsonl"), `"type":"run.failed"`)
	assertFileContains(t, filepath.Join(record.RunDir, "acta-events.jsonl"), `"status":"error"`)
	assertFileContains(t, filepath.Join(record.RunDir, "acta-events.jsonl"), "workspace diff")
}

func TestRunRecordsTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	cwd := t.TempDir()
	marker := filepath.Join(t.TempDir(), "grandchild-survived")
	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", `#!/bin/sh
	(sleep 0.3; printf survived > "$ACTA_TEST_GRANDCHILD_MARKER") &
	sleep 2
`)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ACTA_TEST_GRANDCHILD_MARKER", marker)

	record, err := runForTest(context.Background(), Options{
		Agent:        "codex",
		CWD:          cwd,
		Prompt:       "timeout",
		PromptSource: "test",
		Timeout:      20 * time.Millisecond,
		Stream:       false,
	}, bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if record == nil {
		t.Fatal("expected record")
		return
	}
	if !record.Timeout {
		t.Fatalf("record.Timeout = false, record = %#v", record)
	}
	if record.OK {
		t.Fatal("record.OK = true, want false")
	}
	assertFileContains(t, filepath.Join(record.RunDir, "run.json"), `"timeout": true`)
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("agent grandchild survived timeout; marker stat error = %v", err)
	}
}

// A run in a git workspace must capture staged+unstaged+untracked changes into
// workspace.diff and flag it in the digest, while keeping its own bundle
// (under .acta) out of the diff. Exercises gitdiff + the live digester's
// has_workspace_diff end-to-end.
func TestRunCapturesWorkspaceDiff(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	cwd := t.TempDir()
	gitCmd(t, cwd, "init", "-q")
	if err := os.WriteFile(filepath.Join(cwd, "tracked.txt"), []byte("orig\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, cwd, "add", ".")
	gitCmd(t, cwd, "commit", "-qm", "init")

	// Simulate the agent's workspace changes (decoupled from the fake's cwd).
	if err := os.WriteFile(filepath.Join(cwd, "tracked.txt"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "untracked.txt"), []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", "#!/bin/sh\ncat >/dev/null\n"+
		`printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'`+"\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	record, err := runForTest(context.Background(), Options{
		Agent:        "codex",
		CWD:          cwd,
		Prompt:       "x",
		PromptSource: "test",
		Stream:       false,
	}, bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	if err != nil {
		t.Fatal(err)
	}

	diffPath := filepath.Join(record.RunDir, "workspace.diff")
	assertFileContains(t, diffPath, "tracked.txt")
	assertFileContains(t, diffPath, "+changed")
	assertFileContains(t, diffPath, "untracked.txt")
	// The run bundle lives under .acta and must not appear in its own diff.
	if data, err := os.ReadFile(diffPath); err == nil && strings.Contains(string(data), ".acta") {
		t.Errorf(".acta bundle leaked into workspace.diff:\n%s", data)
	}
	assertFileContains(t, filepath.Join(record.RunDir, "digest.json"), `"has_workspace_diff": true`)
	assertFileContains(t, filepath.Join(record.RunDir, "acta-events.jsonl"), `"type":"diff.generated"`)

	// The bundle must record which git base the diff applies to.
	if !isCommitSHA(record.BaseCommitSHA) || record.BaseDirty == nil || !*record.BaseDirty {
		t.Fatalf("base context = %q dirty=%v, want commit SHA and dirty workspace", record.BaseCommitSHA, record.BaseDirty)
	}
	if record.HeadCommitSHA != record.BaseCommitSHA {
		t.Fatalf("head = %q, want unchanged base %q (agent made no commits)", record.HeadCommitSHA, record.BaseCommitSHA)
	}
	assertFileContains(t, filepath.Join(record.RunDir, "run.json"), `"base_commit_sha": "`+record.BaseCommitSHA+`"`)
	assertFileContains(t, filepath.Join(record.RunDir, "run.json"), `"base_dirty": true`)
	assertFileContains(t, filepath.Join(record.RunDir, "acta-events.jsonl"), `"base_commit_sha":"`+record.BaseCommitSHA+`"`)
}

// Commits created by the agent must be visible as base -> head movement in
// the record and event stream, even though workspace.diff cannot contain them.
func TestRunRecordsHeadCommitAfterAgentCommit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	setGitIdentity(t)
	cwd := t.TempDir()
	gitCmd(t, cwd, "init", "-q")
	gitCmd(t, cwd, "commit", "-q", "--allow-empty", "-m", "init")

	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", "#!/bin/sh\ncat >/dev/null\n"+
		"git -C \""+cwd+"\" commit -q --allow-empty -m agent\n"+
		`printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'`+"\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	record, err := runForTest(context.Background(), Options{
		Agent: "codex", CWD: cwd, Prompt: "x", PromptSource: "test", Stream: false,
	}, bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !isCommitSHA(record.HeadCommitSHA) || record.HeadCommitSHA == record.BaseCommitSHA {
		t.Fatalf("head = %q base = %q, want a new head commit", record.HeadCommitSHA, record.BaseCommitSHA)
	}
	assertFileContains(t, filepath.Join(record.RunDir, "acta-events.jsonl"), `"head_commit_sha":"`+record.HeadCommitSHA+`"`)
}

// A workspace with an unborn HEAD at run start (fresh git init) has no base
// commit, but the head commit the agent creates must still be captured.
func TestRunRecordsHeadCommitFromUnbornHead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	setGitIdentity(t)
	cwd := t.TempDir()
	gitCmd(t, cwd, "init", "-q", "-b", "main")

	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", "#!/bin/sh\ncat >/dev/null\n"+
		"git -C \""+cwd+"\" commit -q --allow-empty -m first\n"+
		`printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'`+"\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	record, err := runForTest(context.Background(), Options{
		Agent: "codex", CWD: cwd, Prompt: "x", PromptSource: "test", Stream: false,
	}, bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	if err != nil {
		t.Fatal(err)
	}
	if record.BaseCommitSHA != "" || record.BaseBranch != "main" || record.BaseDirty == nil || *record.BaseDirty {
		t.Fatalf("base context = %+v, want clean unborn HEAD on main", record)
	}
	if !isCommitSHA(record.HeadCommitSHA) {
		t.Fatalf("head = %q, want the agent's first commit captured", record.HeadCommitSHA)
	}
}

func TestRunExcludesBundleWhenRunsDirIsWorkspaceRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	cwd := t.TempDir()
	gitCmd(t, cwd, "init", "-q")
	gitCmd(t, cwd, "commit", "-q", "--allow-empty", "-m", "init")
	if err := os.WriteFile(filepath.Join(cwd, "real.txt"), []byte("work\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", "#!/bin/sh\ncat >/dev/null\n"+
		`printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'`+"\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	record, err := runForTest(context.Background(), Options{
		Agent: "codex", CWD: cwd, RunsDir: ".", Prompt: "x", PromptSource: "test", Stream: false,
	}, bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	if err != nil {
		t.Fatal(err)
	}
	diff := readFile(t, filepath.Join(record.RunDir, "workspace.diff"))
	if !strings.Contains(diff, "real.txt") {
		t.Fatalf("real workspace change missing from diff:\n%s", diff)
	}
	if strings.Contains(diff, record.ID) || strings.Contains(diff, "codex-events.jsonl") || strings.Contains(diff, "run.json") {
		t.Fatalf("run bundle leaked into its own workspace diff:\n%s", diff)
	}
}

// Every registered agent must run end-to-end and produce a digest — this
// exercises agents.Get, BuildCommand, and the StreamDigester parser for each,
// so a new agent that forgets a parser fails here (unknown-agent error) instead
// of at runtime.
func TestEveryAgentDigestsARun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	for _, a := range agents.All() {
		t.Run(a.Name(), func(t *testing.T) {
			cwd := t.TempDir()
			fakeBin := t.TempDir()
			body := "#!/bin/sh\ncat >/dev/null\n"
			if a.Name() == "codex" {
				body += `printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'` + "\n"
			}
			writeFakeAgent(t, fakeBin, a.Name(), body)
			t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

			record, err := runForTest(context.Background(), Options{
				Agent:        a.Name(),
				CWD:          cwd,
				Prompt:       "x",
				PromptSource: "test",
				Stream:       false,
			}, bytes.NewBuffer(nil), bytes.NewBuffer(nil))
			if err != nil {
				t.Fatalf("agent %q: %v", a.Name(), err)
			}
			assertJSONFile(t, filepath.Join(record.RunDir, "digest.json"))
		})
	}
}

// setGitIdentity puts a commit identity in the test process env so fake
// agents that run `git commit` inherit it through the agent environment.
func setGitIdentity(t *testing.T) {
	t.Helper()
	t.Setenv("GIT_AUTHOR_NAME", "t")
	t.Setenv("GIT_AUTHOR_EMAIL", "t@t")
	t.Setenv("GIT_COMMITTER_NAME", "t")
	t.Setenv("GIT_COMMITTER_EMAIL", "t@t")
}

// isCommitSHA accepts both sha1 (40) and sha256 (64) object formats.
func isCommitSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func gitCmd(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

// Required telemetry is an operational requirement: export failure exits
// non-zero only after the successful agent outcome and bundle are durable.
func TestRunRequiredOTLPExportFailurePreservesOutcomeAndBundle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	cwd := t.TempDir()
	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", "#!/bin/sh\ncat >/dev/null\n"+
		`printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'`+"\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	record, err := runForTest(context.Background(), Options{
		Agent:                   "codex",
		CWD:                     cwd,
		Prompt:                  "x",
		PromptSource:            "test",
		Stream:                  false,
		OTLPEndpoint:            "http://127.0.0.1:1/v1/traces", // refused
		OTLPExportFailurePolicy: OTLPExportFailurePolicyRequired,
	}, bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	if err == nil || !errors.Is(err, ErrTelemetryOnlyFailure) || !strings.Contains(err.Error(), "required OTLP export failed") {
		t.Fatal("expected the failed OTLP export to fail the run")
	}
	if record == nil {
		t.Fatal("expected the bundle to still be recorded")
		return
	}
	assertJSONFile(t, filepath.Join(record.RunDir, "run.json"))
	if !record.OK || record.TerminationReason != "completed" || record.OTLPStatus != "failed" {
		t.Fatalf("record outcome changed by telemetry failure: %#v", record)
	}
}

func TestRunBestEffortOTLPExportFailureIsDefault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	cwd := t.TempDir()
	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", "#!/bin/sh\ncat >/dev/null\n"+
		`printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'`+"\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	record, err := runForTest(context.Background(), Options{
		Agent: "codex", CWD: cwd, Prompt: "x", PromptSource: "test",
		OTLPEndpoint: "http://127.0.0.1:1/v1/traces",
	}, io.Discard, io.Discard)
	if err != nil || record == nil || !record.OK || record.OTLPStatus != "failed" {
		t.Fatalf("default best-effort run = record %#v, err %v", record, err)
	}
}

func TestRunKeepsOTLPCredentialsOutOfAgentEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	requests := make(chan string, 1)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests <- request.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	cwd := t.TempDir()
	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", `#!/bin/sh
if env | grep -q '^OTEL_EXPORTER_OTLP_TRACES_HEADERS='; then
  echo 'OTLP header leaked to coding agent' >&2
  exit 23
fi
cat >/dev/null
printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'
`)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS", "Authorization=Bearer secret-otlp-token")

	record, err := runForTest(context.Background(), Options{
		Agent: "codex", CWD: cwd, Prompt: "x", PromptSource: "test", OTLPEndpoint: collector.URL,
	}, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !record.OK || record.OTLPStatus != "exported" || record.TraceID == "" {
		t.Fatalf("record = %#v, want successful exported trace", record)
	}
	select {
	case authorization := <-requests:
		if authorization != "Bearer secret-otlp-token" {
			t.Fatalf("collector Authorization = %q, want Acta exporter credential", authorization)
		}
	case <-time.After(time.Second):
		t.Fatal("Acta exporter did not reach collector")
	}
}

func TestRunRedactReasoningRemovesTextFromEntireBundle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	const secretReasoning = "private-chain-of-thought-7419"
	cwd := t.TempDir()
	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", "#!/bin/sh\ncat >/dev/null\n"+
		`printf '{"type":"item.completed","item":{"id":"reason-1","type":"reasoning","text":"`+secretReasoning+`"}}\n'`+"\n"+
		`printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'`+"\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	record, err := runForTest(context.Background(), Options{
		Agent: "codex", CWD: cwd, Prompt: "x", PromptSource: "test", RedactReasoning: true,
	}, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if record.ReasoningRedactionState != "redacted" {
		t.Fatalf("reasoning redaction state = %q", record.ReasoningRedactionState)
	}
	err = filepath.Walk(record.RunDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return walkErr
		}
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(payload), secretReasoning) {
			return fmt.Errorf("reasoning text leaked into %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRunRedactionFailurePublishesUnredactedEvidenceAndRefusesDefaultUpload(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	const malformed = "malformed-private-evidence-not-json"
	cwd := t.TempDir()
	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", "#!/bin/sh\ncat >/dev/null\n"+
		`printf '`+malformed+`\n'`+"\n"+
		`printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'`+"\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	record, err := runForTest(context.Background(), Options{
		Agent: "codex", CWD: cwd, Prompt: "x", PromptSource: "test", RedactReasoning: true,
	}, io.Discard, io.Discard)
	if err == nil || record == nil || !strings.Contains(err.Error(), "reasoning redaction failed") {
		t.Fatalf("record=%+v error=%v, want a clear retained-bundle redaction failure", record, err)
	}
	if record.ReasoningRedactionState != "failed" || record.RunDir == "" || record.RecoveryDir != "" {
		t.Fatalf("redaction-failure record = %+v", record)
	}
	if err := verifyCompleteBundle(record.RunDir, record); err != nil {
		t.Fatalf("published redaction-failure bundle is incomplete: %v", err)
	}
	wantRaw := strings.Join([]string{
		`{"type":"thread.started","thread_id":"thread-test"}`,
		`{"type":"turn.started"}`,
		malformed,
		`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`,
		"",
	}, "\n")
	if got := readFile(t, filepath.Join(record.RunDir, record.RawStdoutArtifact)); got != wantRaw {
		t.Fatalf("retained raw evidence = %q, want byte-identical %q", got, wantRaw)
	}
	saved, readErr := ReadRecord(record.RunDir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if saved.ReasoningRedactionState != "failed" || !strings.Contains(saved.Error, "reasoning redaction failed") {
		t.Fatalf("saved redaction-failure record = %+v", saved)
	}
	assertFileContains(t, filepath.Join(record.RunDir, actaevents.Filename), `"type":"run.failed"`)

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	uploadErr := reporting.UploadRun(context.Background(), reporting.Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
	}, saved)
	if uploadErr == nil || !strings.Contains(uploadErr.Error(), "remote upload refused") || requests != 0 {
		t.Fatalf("default failed-redaction upload error=%v requests=%d", uploadErr, requests)
	}
}

// Run ids must be unique — the timestamp is only second-granular, so uniqueness
// rests on the random suffix. A collision would let one run overwrite another's
// bundle (guarded belt-and-suspenders by os.Mkdir on the run dir).
func TestNewRunIDUnique(t *testing.T) {
	seen := make(map[string]bool, 2000)
	for i := 0; i < 2000; i++ {
		id, err := newRunID("codex")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(id, "2") || !strings.Contains(id, "-codex-") {
			t.Fatalf("malformed run id: %q", id)
		}
		if seen[id] {
			t.Fatalf("duplicate run id: %q", id)
		}
		seen[id] = true
	}
}

func TestTaskTitleNeverRetainsPromptImplicitly(t *testing.T) {
	if got := taskTitle(Options{Prompt: "private prompt first line"}); got != "" {
		t.Fatalf("task title = %q, want empty without explicit title or issue title", got)
	}
	if got := taskTitle(Options{Prompt: "private", IssueTitle: "Issue basis"}); got != "Issue basis" {
		t.Fatalf("task title = %q, want issue title", got)
	}
}

func TestValidateRunIDPortableGrammar(t *testing.T) {
	for _, invalid := range []string{".hidden", "trailing.", "contains space", "unicode-å", "CON", "com1.txt", strings.Repeat("a", 129)} {
		if err := validateRunID(invalid); err == nil {
			t.Errorf("validateRunID(%q) succeeded", invalid)
		}
	}
	for _, valid := range []string{"run-1", "20260819T120000Z-codex-deadbeef", "a.b_c-d"} {
		if err := validateRunID(valid); err != nil {
			t.Errorf("validateRunID(%q) = %v", valid, err)
		}
	}
}

func TestFinalizeRecordOutcomeMarksLateActaFailure(t *testing.T) {
	record := &runrecord.Record{OK: true, TerminationReason: "completed"}
	FinalizeRecordOutcome(record, errors.New("artifact failed"))
	if record.OK || record.TerminationReason != "acta_error" || !strings.Contains(record.Error, "artifact failed") {
		t.Fatalf("late failure outcome = %+v", record)
	}
	record.TerminationReason = "provider_error"
	FinalizeRecordOutcome(record, errors.New("later failure"))
	if record.TerminationReason != "provider_error" {
		t.Fatalf("stronger termination reason overwritten: %+v", record)
	}
}

func TestRewriteRecoveryArtifactsSurfacesWriteFailure(t *testing.T) {
	record := &runrecord.Record{
		SchemaVersion: runrecord.SchemaVersion,
		Producer:      runrecord.Producer{Name: "acta", Version: "test"},
		ID:            "recovery-test",
	}
	missing := filepath.Join(t.TempDir(), "missing", "bundle")
	err := rewriteRecoveryArtifacts(missing, record, nil, "", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "rewrite recovery run record") {
		t.Fatalf("rewrite error = %v, want surfaced record failure", err)
	}
}

func TestRunRejectsNegativeResourceOptions(t *testing.T) {
	for _, opts := range []Options{
		{Timeout: -time.Second},
		{UploadTimeout: -time.Second},
		{MaxRawOutputBytes: -1},
		{MaxWorkspaceDiffBytes: -1},
		{MaxUploadBytes: -1},
		{MaxRedactionLineBytes: -1},
	} {
		if _, err := Run(context.Background(), opts, io.Discard, io.Discard); err == nil {
			t.Fatalf("Run(%+v) accepted a negative resource option", opts)
		}
	}
}

func TestRunFailsWhenCombinedRawOutputLimitIsExceeded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	cwd := t.TempDir()
	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", `#!/bin/sh
cat >/dev/null
printf '%0200d' 1
printf '%0200d' 2 >&2
`)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	record, err := runForTest(context.Background(), Options{
		Agent: "codex", CWD: cwd, Prompt: "bounded", PromptSource: "test",
		MaxRawOutputBytes: 128,
	}, io.Discard, io.Discard)
	if err == nil || record == nil {
		t.Fatalf("limited run record=%+v err=%v", record, err)
	}
	if !record.RawOutputLimitExceeded || record.OK || !strings.Contains(record.Error, "raw output byte limit") {
		t.Fatalf("limited run outcome = %+v", record)
	}
	stdoutInfo, stdoutErr := os.Stat(record.RawStdoutPath)
	stderrInfo, stderrErr := os.Stat(record.RawStderrPath)
	if stdoutErr != nil || stderrErr != nil || stdoutInfo.Size()+stderrInfo.Size() > 128 {
		t.Fatalf("raw artifact sizes stdout=%v stderr=%v errors=(%v,%v)", stdoutInfo, stderrInfo, stdoutErr, stderrErr)
	}
}

func TestRunFailsClosedWhenRepositoryDisappears(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell agents require /bin/sh")
	}
	cwd := t.TempDir()
	gitCmd(t, cwd, "init", "-q")
	gitCmd(t, cwd, "commit", "-q", "--allow-empty", "-m", "initial")
	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", `#!/bin/sh
cat >/dev/null
rm -rf "$PWD/.git"
printf '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'
`)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	record, err := runForTest(context.Background(), Options{
		Agent: "codex", CWD: cwd, Prompt: "remove git", PromptSource: "test",
	}, io.Discard, io.Discard)
	if err == nil || record == nil || record.OK {
		t.Fatalf("repository disappearance record=%+v err=%v", record, err)
	}
	if !strings.Contains(record.Error, "not a repository at completion") || record.TerminationReason != "acta_error" {
		t.Fatalf("repository disappearance outcome = %+v", record)
	}
}

func TestRunFailsClosedWhenInitialGitEvidenceFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell commands require /bin/sh")
	}
	cwd := t.TempDir()
	marker := filepath.Join(t.TempDir(), "agent-started")
	fakeBin := t.TempDir()
	writeFakeAgent(t, fakeBin, "codex", "#!/bin/sh\ntouch \"$ACTA_AGENT_STARTED\"\n")
	writeFakeAgent(t, fakeBin, "git", "#!/bin/sh\necho 'injected git failure' >&2\nexit 3\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ACTA_AGENT_STARTED", marker)
	record, err := runForTest(context.Background(), Options{
		Agent: "codex", CWD: cwd, Prompt: "must not run", PromptSource: "test",
	}, io.Discard, io.Discard)
	if err == nil || record != nil || !strings.Contains(err.Error(), "capture initial git context") {
		t.Fatalf("initial git failure record=%+v err=%v", record, err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("agent started despite failed initial evidence: %v", err)
	}
}

func TestRunRejectsUnsupportedAgentVersionBeforeExecution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell commands require /bin/sh")
	}
	cwd := t.TempDir()
	marker := filepath.Join(t.TempDir(), "agent-started")
	fakeBin := t.TempDir()
	path := filepath.Join(fakeBin, "codex")
	script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'codex-cli 0.146.9'; exit 0; fi\ntouch \"$ACTA_AGENT_STARTED\"\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ACTA_AGENT_STARTED", marker)
	record, err := runForTest(context.Background(), Options{
		Agent: "codex", CWD: cwd, Prompt: "must not run", PromptSource: "test",
	}, io.Discard, io.Discard)
	if err == nil || record != nil || !strings.Contains(err.Error(), "minimum supported version") {
		t.Fatalf("unsupported version record=%+v err=%v", record, err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("agent started despite unsupported version: %v", err)
	}
}

func TestRejectProjectCodexConfig(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "nested", "workspace")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := rejectProjectCodexConfig(nested); err != nil {
		t.Fatalf("clean project rejected: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, ".codex", "config.toml")
	if err := os.WriteFile(configPath, []byte("model = \"ambient\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rejectProjectCodexConfig(nested); err == nil || !strings.Contains(err.Error(), configPath) {
		t.Fatalf("project config error = %v", err)
	}
}

func TestRunsDirExcludeCoversWholeRunsRoot(t *testing.T) {
	cwd := t.TempDir()
	runDir := filepath.Join(cwd, ".acta", "runs", "run-2")
	got := runsDirExclude(cwd, runDir)
	if len(got) != 1 || got[0] != ".acta/runs" {
		t.Fatalf("runsDirExclude() = %v, want the runs root", got)
	}
	// A runs root at the workspace itself falls back to the exact bundle path
	// so the exclusion never blanks all evidence.
	direct := runsDirExclude(cwd, filepath.Join(cwd, "run-3"))
	if len(direct) != 1 || direct[0] != "run-3" {
		t.Fatalf("runsDirExclude(workspace-root) = %v, want the bundle path", direct)
	}
	if out := runsDirExclude(cwd, filepath.Join(t.TempDir(), "elsewhere", "run-4")); out != nil {
		t.Fatalf("runsDirExclude(outside workspace) = %v, want nil", out)
	}
}

func TestVerifyCompleteBundleRejectsMissingArtifact(t *testing.T) {
	dir := t.TempDir()
	record := &runrecord.Record{RawStdoutArtifact: "stdout.jsonl", RawStderrArtifact: "stderr.log"}
	for _, name := range []string{"run.json", "stdout.jsonl", "stderr.log", "event-times.jsonl", "digest.json", actaevents.Filename} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := verifyCompleteBundle(dir, record); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "digest.json")); err != nil {
		t.Fatal(err)
	}
	if err := verifyCompleteBundle(dir, record); err == nil || !strings.Contains(err.Error(), "digest.json") {
		t.Fatalf("missing artifact error = %v", err)
	}
}

func writeFakeAgent(t *testing.T, dir string, name string, script string) {
	t.Helper()
	version := ""
	switch name {
	case "codex":
		version = "codex-cli 0.147.0"
	case "claude":
		version = "2.1.235 (Claude Code)"
	}
	if version != "" {
		header := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo '" + version + "'; exit 0; fi\n"
		if name == "codex" {
			header += "printf '{\"type\":\"thread.started\",\"thread_id\":\"thread-test\"}\\n'\nprintf '{\"type\":\"turn.started\"}\\n'\n"
			script = strings.ReplaceAll(script, `{"type":"thread.started"}`, `{"type":"thread.started","thread_id":"thread-test"}`)
		} else {
			header += "printf '{\"type\":\"system\",\"subtype\":\"init\",\"session_id\":\"session-test\"}\\n'\ntrap \"printf '{\\\"type\\\":\\\"result\\\",\\\"subtype\\\":\\\"success\\\",\\\"session_id\\\":\\\"session-test\\\",\\\"is_error\\\":false}\\\\n'\" EXIT\n"
			script = strings.ReplaceAll(script, `{"type":"result","is_error":false`, `{"type":"result","subtype":"success","is_error":false`)
		}
		script = strings.Replace(script, "#!/bin/sh\n", header, 1)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func runForTest(ctx context.Context, opts Options, stdout, stderr io.Writer) (*runrecord.Record, error) {
	if opts.Agent == "codex" && opts.CodexSandbox == "" {
		opts.CodexSandbox = "workspace-write"
	}
	if opts.Agent == "claude" && opts.ClaudePermissionMode == "" {
		opts.ClaudePermissionMode = "acceptEdits"
	}
	return Run(ctx, opts, stdout, stderr)
}

func assertFileContains(t *testing.T, path string, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), want) {
		t.Fatalf("%s does not contain %q; contents:\n%s", path, want, string(data))
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func containsAdjacent(values []string, first string, second string) bool {
	for index := 0; index+1 < len(values); index++ {
		if values[index] == first && values[index+1] == second {
			return true
		}
	}
	return false
}

func assertJSONFile(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("invalid JSON in %s: %v", path, err)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %04o, want %04o", path, got, want)
	}
}
