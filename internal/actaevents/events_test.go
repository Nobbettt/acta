package actaevents

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nobbettt/acta/internal/digest"
	"github.com/nobbettt/acta/internal/runrecord"
)

func TestBuildMapsDigestToProductEvents(t *testing.T) {
	started := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	completed := started.Add(2 * time.Second)
	commandAt := started.Add(500 * time.Millisecond)
	commandCompletedAt := started.Add(1500 * time.Millisecond)
	exit := 0
	record := &runrecord.Record{
		ID:             "run-1",
		Agent:          "codex",
		CWD:            "/repo",
		BaseCommitSHA:  "1111222233334444555566667777888899990000",
		BaseBranch:     "main",
		BaseDirty:      boolPtr(true),
		HeadCommitSHA:  "aaaa222233334444555566667777888899990000",
		Repository:     "example-org/example-repo",
		IssueNumber:    42,
		IssueTitle:     "Fix the flaky test",
		IssueBody:      stringPtr("## Issue\n\nThe test is flaky.\n"),
		TaskTitle:      "Fix the flaky test",
		RunDir:         "/repo/.acta/runs/run-1",
		Command:        []string{"codex", "exec", "--json", "-"},
		StartedAt:      started,
		CompletedAt:    completed,
		DurationMillis: 2000,
		ExitCode:       &exit,
		OK:             true,
		RawStdoutPath:  "/repo/.acta/runs/run-1/codex-events.jsonl",
		RawStderrPath:  "/repo/.acta/runs/run-1/codex.stderr.log",
		PromptSource:   "flag",
	}
	d := &digest.Digest{
		SchemaVersion:    digest.SchemaVersion,
		RunID:            "run-1",
		Agent:            "codex",
		Status:           "ok",
		HasWorkspaceDiff: true,
		Timeline: []digest.Event{
			{
				Kind:        digest.KindCommand,
				ObservedAt:  &commandAt,
				CompletedAt: &commandCompletedAt,
				Command:     "sed -n '1,5p' main.go",
				ExitCode:    &exit,
				Output:      "1\tpackage main\n",
				OutputChars: 15,
				Files:       []string{"main.go"},
				Spans:       map[string][]digest.Span{"main.go": {{Start: 1, End: 1}}},
				ReadRanges:  map[string][]digest.ReadRange{"main.go": {{Start: 1, End: 1, Content: "package main"}}},
			},
			{
				Kind:  digest.KindMessage,
				Text:  "done",
				Files: nil,
			},
		},
		Metrics: digest.Metrics{
			DurationMillis: 2000,
			Commands:       1,
			Tokens: digest.TokenUsage{
				Input:  10,
				Output: 5,
				Total:  15,
			},
		},
	}

	events, err := Build(record, d)
	if err != nil {
		t.Fatal(err)
	}
	wantTypes := []string{
		TypeRunStarted,
		TypeShellCommandComplete,
		TypeFileRead,
		TypeAgentMessage,
		TypeDiffGenerated,
		TypeTokensReported,
		TypeRunCompleted,
	}
	if len(events) != len(wantTypes) {
		t.Fatalf("events = %d, want %d: %#v", len(events), len(wantTypes), events)
	}
	for i, want := range wantTypes {
		if events[i].Sequence != i+1 {
			t.Fatalf("event %d sequence = %d, want %d", i, events[i].Sequence, i+1)
		}
		if events[i].Type != want {
			t.Fatalf("event %d type = %q, want %q", i, events[i].Type, want)
		}
		if events[i].SchemaVersion != SchemaVersion || events[i].RunID != "run-1" || events[i].Source != Source {
			t.Fatalf("event %d has bad envelope: %+v", i, events[i])
		}
	}
	if !events[1].Timestamp.Equal(commandCompletedAt) {
		t.Fatalf("command event timestamp = %v, want completion time %v", events[1].Timestamp, commandCompletedAt)
	}
	if !events[2].Timestamp.Equal(commandCompletedAt) {
		t.Fatalf("file.read event timestamp = %v, want parent completion time %v", events[2].Timestamp, commandCompletedAt)
	}

	var runStarted struct {
		Repository    string  `json:"repository"`
		IssueNumber   int     `json:"issue_number"`
		IssueTitle    string  `json:"issue_title"`
		IssueBody     *string `json:"issue_body"`
		TaskTitle     string  `json:"task_title"`
		BaseCommitSHA string  `json:"base_commit_sha"`
		BaseBranch    string  `json:"base_branch"`
		BaseDirty     *bool   `json:"base_dirty"`
	}
	if err := json.Unmarshal(events[0].Payload, &runStarted); err != nil {
		t.Fatal(err)
	}
	if runStarted.Repository != "example-org/example-repo" || runStarted.IssueNumber != 42 || runStarted.IssueTitle != "Fix the flaky test" || runStarted.TaskTitle != "Fix the flaky test" {
		t.Fatalf("bad run.started task metadata: %+v", runStarted)
	}
	if runStarted.BaseCommitSHA != "1111222233334444555566667777888899990000" || runStarted.BaseBranch != "main" || runStarted.BaseDirty == nil || !*runStarted.BaseDirty {
		t.Fatalf("bad run.started git base context: %+v", runStarted)
	}
	if runStarted.IssueBody == nil || *runStarted.IssueBody != "## Issue\n\nThe test is flaky.\n" {
		t.Fatalf("bad run.started issue body: %#v", runStarted.IssueBody)
	}
	var runCompleted struct {
		HeadCommitSHA string `json:"head_commit_sha"`
	}
	if err := json.Unmarshal(events[6].Payload, &runCompleted); err != nil {
		t.Fatal(err)
	}
	if runCompleted.HeadCommitSHA != "aaaa222233334444555566667777888899990000" {
		t.Fatalf("run.completed head_commit_sha = %q, want record's head", runCompleted.HeadCommitSHA)
	}

	var fileRead struct {
		Path                string             `json:"path"`
		Spans               []digest.Span      `json:"spans"`
		Ranges              []digest.ReadRange `json:"ranges"`
		SourceEventSequence int                `json:"source_event_sequence"`
		Command             string             `json:"command"`
	}
	if err := json.Unmarshal(events[2].Payload, &fileRead); err != nil {
		t.Fatal(err)
	}
	if fileRead.Path != "main.go" || fileRead.SourceEventSequence != 2 || fileRead.Command == "" {
		t.Fatalf("bad file.read payload: %+v", fileRead)
	}
	if len(fileRead.Ranges) != 1 || fileRead.Ranges[0].Start != 1 || fileRead.Ranges[0].End != 1 || fileRead.Ranges[0].Content != "package main" {
		t.Fatalf("bad file.read ranges: %+v", fileRead.Ranges)
	}
	var command struct {
		StartedAt   time.Time `json:"started_at"`
		CompletedAt time.Time `json:"completed_at"`
	}
	if err := json.Unmarshal(events[1].Payload, &command); err != nil {
		t.Fatal(err)
	}
	if !command.StartedAt.Equal(commandAt) || !command.CompletedAt.Equal(commandCompletedAt) {
		t.Fatalf("bad command timing payload: %+v", command)
	}

	if len(events[len(events)-1].ArtifactRefs) == 0 {
		t.Fatal("run completion event should reference bundle artifacts")
	}
}

func TestBuildCarriesPerWritePatches(t *testing.T) {
	started := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	record := &runrecord.Record{ID: "write-run", Agent: "codex", StartedAt: started, CompletedAt: started, OK: true}
	d := &digest.Digest{Status: "ok", Timeline: []digest.Event{{
		Kind: digest.KindFileEdit, ProviderEvent: "file_change", ID: "write-1", Status: "completed",
		Files:       []string{"src/clock.ts"},
		FilePatches: []digest.FilePatch{{Path: "src/clock.ts", Patch: "diff --git a/src/clock.ts b/src/clock.ts\n"}},
	}}}
	events, err := Build(record, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 2 || events[1].Type != TypeFileWritten {
		t.Fatalf("events = %#v", events)
	}
	var payload struct {
		Patches []digest.FilePatch `json:"patches"`
	}
	if err := json.Unmarshal(events[1].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Patches) != 1 || payload.Patches[0].Path != "src/clock.ts" {
		t.Fatalf("file patches missing from write payload: %+v", payload.Patches)
	}
}

func TestBuildWithPromptPlacesCapturedPromptFirst(t *testing.T) {
	started := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	record := &runrecord.Record{
		ID:             "run-with-prompt",
		Agent:          "codex",
		StartedAt:      started,
		CompletedAt:    started,
		PromptSource:   "stdin",
		PromptCaptured: true,
		OK:             true,
	}
	events, err := BuildWithPrompt(record, &digest.Digest{Status: "ok"}, "Implement the requested change.\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 2 || events[0].Type != TypeAgentPrompt || events[1].Type != TypeRunStarted {
		t.Fatalf("event order = %#v, want agent.prompt then run.started", events)
	}
	var prompt struct {
		Text   string `json:"text"`
		Source string `json:"source"`
	}
	if err := json.Unmarshal(events[0].Payload, &prompt); err != nil {
		t.Fatal(err)
	}
	if prompt.Text != "Implement the requested change.\n" || prompt.Source != "stdin" {
		t.Fatalf("prompt payload = %#v", prompt)
	}
	if events[0].Sequence != 1 || !events[0].Timestamp.Equal(started) {
		t.Fatalf("prompt envelope = %#v", events[0])
	}
}

func TestBuildTruncatesMultiMiBReasoningWithStructuralMarker(t *testing.T) {
	const reasoningBytes = 9 << 20
	reasoning := strings.Repeat("r", reasoningBytes)
	item, err := json.Marshal(map[string]any{
		"type": "item.completed",
		"item": map[string]any{"id": "reason-1", "type": "reasoning", "text": reasoning},
	})
	if err != nil {
		t.Fatal(err)
	}

	started := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	digester, err := digest.NewStreamDigesterWithOptions("codex", t.TempDir(), digest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	digester.Line([]byte(`{"type":"thread.started","thread_id":"thread-large"}`), started)
	digester.Line([]byte(`{"type":"turn.started"}`), started)
	digester.Line(item, started)
	digester.Line([]byte(`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`), started)
	record := &runrecord.Record{
		ID: "large-reasoning", Agent: "codex", StartedAt: started, CompletedAt: started, OK: true,
	}
	d := digester.Finalize(record, "")

	events, err := Build(record, d)
	if err != nil {
		t.Fatalf("Build() rejected an otherwise successful run with oversized reasoning: %v", err)
	}
	for _, event := range events {
		if event.Type != TypeAgentReasoning {
			continue
		}
		var payload struct {
			Text          string `json:"text"`
			TextChars     int    `json:"text_chars"`
			TextTruncated bool   `json:"text_truncated"`
		}
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if len(payload.Text) != digest.MaxEventTextBytes || payload.TextChars != reasoningBytes || !payload.TextTruncated {
			t.Fatalf("reasoning payload text bytes=%d chars=%d truncated=%v", len(payload.Text), payload.TextChars, payload.TextTruncated)
		}
		return
	}
	t.Fatal("normalized stream omitted the reasoning event")
}

func TestTimelineTypeMapping(t *testing.T) {
	cases := map[string]string{
		digest.KindCommand:    TypeShellCommandComplete,
		digest.KindToolCall:   TypeToolCallCompleted,
		digest.KindMessage:    TypeAgentMessage,
		digest.KindReasoning:  TypeAgentReasoning,
		digest.KindFileEdit:   TypeFileWritten,
		digest.KindTodo:       TypeAgentTodo,
		"unknown-future-kind": TypeAgentEventUnsupported, // fail visible instead of pretending it was a tool
	}
	for kind, want := range cases {
		if got := timelineType(digest.Event{Kind: kind}); got != want {
			t.Errorf("timelineType(%q) = %q, want %q", kind, got, want)
		}
	}
}

func TestBuildCarriesLifecycleTerminationAndRawEvidence(t *testing.T) {
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "codex-events.jsonl")
	writeFile(t, rawPath, "{}\n{}\n")
	started := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	record := &runrecord.Record{
		ID: "run-rich", Agent: "codex", RunDir: dir, RawStdoutPath: rawPath,
		StartedAt: started, CompletedAt: started.Add(time.Second), OK: false,
		TerminationReason: "process_error",
	}
	d := &digest.Digest{
		Status:      "error",
		Termination: digest.Termination{Outcome: "failed", ProviderReason: "turn_failed", ErrorMessage: "quota exceeded"},
		Metrics:     digest.Metrics{UnsupportedEvents: map[string]int{"item.future": 1}, IncompleteToolCalls: 1, OrphanedToolResults: 2},
		Timeline: []digest.Event{{
			Kind: digest.KindWebSearch, ProviderEvent: "web_search", ID: "web-1",
			Status: "completed", Query: "event schema", Action: json.RawMessage(`{"type":"search"}`),
			RawEventLines: []int{1, 2},
		}},
	}

	events, err := Build(record, d)
	if err != nil {
		t.Fatal(err)
	}
	if events[1].Type != TypeWebSearchCompleted {
		t.Fatalf("timeline type = %q", events[1].Type)
	}
	if len(events[1].ArtifactRefs) != 1 || len(events[1].ArtifactRefs[0].Lines) != 2 {
		t.Fatalf("raw evidence refs = %+v", events[1].ArtifactRefs)
	}
	var terminal struct {
		Termination digest.Termination `json:"termination"`
		Unsupported map[string]int     `json:"unsupported_events"`
		Incomplete  int                `json:"incomplete_tool_calls"`
		Orphaned    int                `json:"orphaned_tool_results"`
	}
	if err := json.Unmarshal(events[len(events)-1].Payload, &terminal); err != nil {
		t.Fatal(err)
	}
	if terminal.Termination.ProviderReason != "turn_failed" || terminal.Unsupported["item.future"] != 1 || terminal.Incomplete != 1 || terminal.Orphaned != 2 {
		t.Fatalf("terminal payload = %+v", terminal)
	}
}

// A file_edit event becomes file.written and must NOT spawn file.read events;
// a tool_call's reads fan out into one sorted file.read event per path.
func TestBuildFileEditAndMultiFileReads(t *testing.T) {
	started := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	rec := &runrecord.Record{ID: "r", Agent: "claude", RunDir: t.TempDir(), StartedAt: started, CompletedAt: started, OK: true}
	d := &digest.Digest{
		Status: "ok",
		Timeline: []digest.Event{
			{Kind: digest.KindFileEdit, Files: []string{"a.go", "b.go"}},
			{Kind: digest.KindToolCall, Tool: "Read", Files: []string{"z.go", "a.go"}},
		},
	}
	events, err := Build(rec, d)
	if err != nil {
		t.Fatal(err)
	}
	written := 0
	var readPaths []string
	for _, e := range events {
		switch e.Type {
		case TypeFileWritten:
			written++
		case TypeFileRead:
			var p struct {
				Path string `json:"path"`
			}
			if err := json.Unmarshal(e.Payload, &p); err != nil {
				t.Fatal(err)
			}
			readPaths = append(readPaths, p.Path)
		}
	}
	if written != 1 {
		t.Fatalf("file.written events = %d, want 1", written)
	}
	if len(readPaths) != 2 || readPaths[0] != "a.go" || readPaths[1] != "z.go" {
		t.Fatalf("file.read paths = %v, want [a.go z.go] (sorted; none from file_edit)", readPaths)
	}
}

// WriteForRecord is the production entrypoint the runner calls. Its terminal
// event must reference exactly the bundle artifacts present on disk.
func TestWriteForRecordRoundTrip(t *testing.T) {
	dir := t.TempDir()
	started := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	writeFile(t, filepath.Join(dir, "run.json"), "{}")
	writeFile(t, filepath.Join(dir, "digest.json"), "{}")
	// deliberately absent: event-times.jsonl, raw stdout/stderr, workspace.diff

	rec := &runrecord.Record{
		ID: "r1", Agent: "codex", RunDir: dir,
		StartedAt: started, CompletedAt: started.Add(time.Second), OK: false,
		RawStdoutPath: filepath.Join(dir, "codex-events.jsonl"), // not on disk
	}
	d := &digest.Digest{Status: "error", Timeline: []digest.Event{{Kind: digest.KindMessage, Text: "hi"}}}
	if err := WriteForRecord(dir, rec, d); err != nil {
		t.Fatal(err)
	}

	events := readEvents(t, filepath.Join(dir, Filename))
	if events[0].Type != TypeRunStarted {
		t.Fatalf("first event = %q, want %q", events[0].Type, TypeRunStarted)
	}
	last := events[len(events)-1]
	if last.Type != TypeRunFailed { // record.OK == false
		t.Fatalf("last event = %q, want %q", last.Type, TypeRunFailed)
	}
	kinds := map[string]bool{}
	for _, ref := range last.ArtifactRefs {
		kinds[ref.Kind] = true
	}
	if !kinds["run_record"] || !kinds["digest"] || !kinds["event_stream"] {
		t.Fatalf("missing expected artifact refs, got %v", kinds)
	}
	if kinds["raw_stdout"] || kinds["event_times"] || kinds["workspace_diff"] {
		t.Fatalf("referenced artifacts not on disk, got %v", kinds)
	}
}

// WriteForRunDir reads run.json itself; a missing record is a hard error, not a
// silent empty stream.
func TestWriteForRunDir(t *testing.T) {
	dir := t.TempDir()
	rec := runrecord.Record{ID: "r7", Agent: "codex", RunDir: dir, StartedAt: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC), OK: true}
	payload, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "run.json"), string(payload))

	d := &digest.Digest{Status: "ok"}
	if err := WriteForRunDir(dir, d); err != nil {
		t.Fatal(err)
	}
	events := readEvents(t, filepath.Join(dir, Filename))
	if len(events) == 0 || events[0].RunID != "r7" {
		t.Fatalf("WriteForRunDir did not use run.json: %+v", events)
	}
	if err := WriteForRunDir(t.TempDir(), d); err == nil {
		t.Fatal("expected an error when run.json is absent")
	}
}

func TestWriteForRunDirPreservesCapturedPrompt(t *testing.T) {
	dir := t.TempDir()
	started := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	record := &runrecord.Record{
		ID:             "run-with-prompt",
		Agent:          "codex",
		RunDir:         dir,
		StartedAt:      started,
		CompletedAt:    started,
		PromptSource:   "stdin",
		PromptCaptured: true,
		OK:             true,
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "run.json"), string(payload))
	d := &digest.Digest{Status: "ok"}
	if err := WriteForRecordWithPrompt(dir, record, d, "retained prompt"); err != nil {
		t.Fatal(err)
	}
	if err := WriteForRunDir(dir, d); err != nil {
		t.Fatal(err)
	}
	events := readEvents(t, filepath.Join(dir, Filename))
	if len(events) == 0 || events[0].Type != TypeAgentPrompt {
		t.Fatalf("regenerated events lost prompt: %#v", events)
	}
	var prompt agentPromptPayload
	if err := json.Unmarshal(events[0].Payload, &prompt); err != nil {
		t.Fatal(err)
	}
	if prompt.Text != "retained prompt" {
		t.Fatalf("regenerated prompt = %q", prompt.Text)
	}
}

func TestWriteForRunDirRejectsPromptFromAnotherRun(t *testing.T) {
	dir := t.TempDir()
	started := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	record := &runrecord.Record{
		ID: "expected-run", Agent: "codex", RunDir: dir, StartedAt: started,
		CompletedAt: started, PromptCaptured: true, OK: true,
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "run.json"), string(payload))
	other := *record
	other.ID = "other-run"
	if err := WriteForRecordWithPrompt(dir, &other, &digest.Digest{Status: "ok"}, "foreign prompt"); err != nil {
		t.Fatal(err)
	}

	err = WriteForRunDir(dir, &digest.Digest{Status: "ok"})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("WriteForRunDir() error = %v, want run-id mismatch", err)
	}
}

func TestConcurrentProjectionCommitsSerializeGenerations(t *testing.T) {
	runDir := t.TempDir()
	firstFinals, firstPayloads := projectionCommitFixture(t, "100", "first digest\n", "first events\n")
	secondFinals, secondPayloads := projectionCommitFixture(t, "200", "second digest\n", "second events\n")

	firstLocked := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- commitProjection(runDir, "100", firstFinals, firstPayloads, func() error {
			close(firstLocked)
			<-releaseFirst
			return nil
		})
	}()
	<-firstLocked

	secondLocked := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- commitProjection(runDir, "200", secondFinals, secondPayloads, func() error {
			close(secondLocked)
			return nil
		})
	}()
	select {
	case <-secondLocked:
		t.Fatal("second projection commit acquired the per-bundle lock before the first released it")
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatalf("first projection commit: %v", err)
	}
	select {
	case <-secondLocked:
	case <-time.After(5 * time.Second):
		t.Fatal("second projection commit did not acquire the released lock")
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second projection commit: %v", err)
	}
	assertProjectionGeneration(t, runDir, secondPayloads)
}

func TestProjectionCommitsForDifferentBundlesDoNotSerialize(t *testing.T) {
	firstRunDir := t.TempDir()
	secondRunDir := t.TempDir()
	firstFinals, firstPayloads := projectionCommitFixture(t, "100", "first digest\n", "first events\n")
	secondFinals, secondPayloads := projectionCommitFixture(t, "200", "second digest\n", "second events\n")

	firstLocked := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- commitProjection(firstRunDir, "100", firstFinals, firstPayloads, func() error {
			close(firstLocked)
			<-releaseFirst
			return nil
		})
	}()
	<-firstLocked

	secondLocked := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- commitProjection(secondRunDir, "200", secondFinals, secondPayloads, func() error {
			close(secondLocked)
			return nil
		})
	}()
	serialized := false
	select {
	case <-secondLocked:
	case <-time.After(2 * time.Second):
		serialized = true
	}
	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatalf("first projection commit: %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second projection commit: %v", err)
	}
	if serialized {
		t.Fatal("projection commits for different bundles serialized against each other")
	}
}

func TestAcquireProjectionLockContextTimesOutWhileHeld(t *testing.T) {
	runDir := t.TempDir()
	held, err := AcquireProjectionLock(runDir)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = AcquireProjectionLockContext(ctx, runDir)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "projection lock held") {
		t.Fatalf("AcquireProjectionLockContext() error = %v, want held-lock timeout", err)
	}
	if elapsed := time.Since(started); elapsed >= 2*time.Second {
		t.Fatalf("AcquireProjectionLockContext() returned after %s, want under 2s", elapsed)
	}
}

func TestProjectionCommitContextTimesOutWhileHeld(t *testing.T) {
	runDir := t.TempDir()
	held, err := AcquireProjectionLock(runDir)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	finals, payloads := projectionCommitFixture(t, "100", "digest\n", "events\n")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err = commitProjectionContext(ctx, runDir, "100", finals, payloads, nil)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "lock projection commit") {
		t.Fatalf("commitProjectionContext() error = %v, want projection-lock timeout", err)
	}
	for _, name := range finals {
		if _, statErr := os.Stat(filepath.Join(runDir, name)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("timed-out projection commit wrote %s, stat error = %v", name, statErr)
		}
	}
}

func TestAcquireProjectionLockContextSucceedsAfterRelease(t *testing.T) {
	runDir := t.TempDir()
	held, err := AcquireProjectionLock(runDir)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	acquired := make(chan *ProjectionLock, 1)
	errs := make(chan error, 1)
	go func() {
		lock, err := AcquireProjectionLockContext(ctx, runDir)
		if err != nil {
			errs <- err
			return
		}
		acquired <- lock
	}()
	select {
	case lock := <-acquired:
		_ = lock.Close()
		t.Fatal("second handle acquired the projection lock before release")
	case err := <-errs:
		t.Fatalf("wait for held projection lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case lock := <-acquired:
		if err := lock.Close(); err != nil {
			t.Fatal(err)
		}
	case err := <-errs:
		t.Fatalf("acquire released projection lock: %v", err)
	case <-ctx.Done():
		t.Fatal("projection lock was not acquired after release")
	}
}

func TestAcquireProjectionLockContextUncontended(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lock, err := AcquireProjectionLockContext(ctx, t.TempDir())
	if err != nil {
		t.Fatalf("AcquireProjectionLockContext() error = %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProjectionCommitLockReleasedAfterFailure(t *testing.T) {
	runDir := t.TempDir()
	finals, failedPayloads := projectionCommitFixture(t, "100", "failed digest\n", "failed events\n")
	err := commitProjection(runDir, "100", finals, failedPayloads, func() error {
		return errors.New("injected commit failure")
	})
	if err == nil || !strings.Contains(err.Error(), "injected commit failure") {
		t.Fatalf("failed projection commit error = %v", err)
	}

	_, goodPayloads := projectionCommitFixture(t, "200", "good digest\n", "good events\n")
	done := make(chan error, 1)
	go func() {
		done <- commitProjection(runDir, "200", finals, goodPayloads, nil)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("projection commit after failure: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("projection lock remained held after a failed commit")
	}
	assertProjectionGeneration(t, runDir, goodPayloads)
}

func projectionCommitFixture(t *testing.T, generation, digestPayload, eventsPayload string) ([]string, [][]byte) {
	t.Helper()
	manifestPayload, err := json.Marshal(struct {
		SchemaVersion int                `json:"schema_version"`
		Producer      runrecord.Producer `json:"producer"`
		Generation    string             `json:"generation"`
		DigestSHA256  string             `json:"digest_sha256"`
		EventsSHA256  string             `json:"events_sha256"`
	}{
		SchemaVersion: ProjectionSchemaVersion,
		Producer:      runrecord.Producer{Name: "acta", Version: "test"},
		Generation:    generation,
		DigestSHA256:  fmt.Sprintf("%x", sha256.Sum256([]byte(digestPayload))),
		EventsSHA256:  fmt.Sprintf("%x", sha256.Sum256([]byte(eventsPayload))),
	})
	if err != nil {
		t.Fatal(err)
	}
	return []string{"digest.json", Filename, "projection.json"}, [][]byte{
		[]byte(digestPayload), []byte(eventsPayload), append(manifestPayload, '\n'),
	}
}

func assertProjectionGeneration(t *testing.T, runDir string, wantPayloads [][]byte) {
	t.Helper()
	for index, name := range []string{"digest.json", Filename, "projection.json"} {
		payload, err := os.ReadFile(filepath.Join(runDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(payload) != string(wantPayloads[index]) {
			t.Fatalf("%s = %q, want one complete generation %q", name, payload, wantPayloads[index])
		}
	}
	var manifest struct {
		DigestSHA256 string `json:"digest_sha256"`
		EventsSHA256 string `json:"events_sha256"`
	}
	if err := json.Unmarshal(wantPayloads[2], &manifest); err != nil {
		t.Fatal(err)
	}
	for index, wantHash := range []string{manifest.DigestSHA256, manifest.EventsSHA256} {
		if got := fmt.Sprintf("%x", sha256.Sum256(wantPayloads[index])); got != wantHash {
			t.Fatalf("projection artifact %d hash = %s, manifest = %s", index, got, wantHash)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readEvents(t *testing.T, path string) []Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var events []Event
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return events
}

func stringPtr(value string) *string {
	return &value
}

func boolPtr(value bool) *bool {
	return &value
}

// A verified-clean workspace must serialize base_dirty:false — absence is
// reserved for "not a git repo / not captured".
func TestBuildKeepsFalseBaseDirty(t *testing.T) {
	record := &runrecord.Record{
		ID:        "run-2",
		Agent:     "codex",
		CWD:       "/repo",
		BaseDirty: boolPtr(false),
		OK:        true,
	}
	events, err := Build(record, &digest.Digest{RunID: "run-2", Agent: "codex"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(events[0].Payload), `"base_dirty":false`) {
		t.Fatalf("run.started must carry base_dirty:false for a clean workspace: %s", events[0].Payload)
	}
}

func TestWriteJSONL(t *testing.T) {
	dir := t.TempDir()
	events := []Event{
		{
			SchemaVersion: SchemaVersion,
			RunID:         "run-1",
			Sequence:      1,
			Timestamp:     time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC),
			Source:        Source,
			Type:          TypeRunStarted,
			Payload:       json.RawMessage(`{"agent":"codex"}`),
		},
	}
	if err := Write(dir, events); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(filepath.Join(dir, Filename))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatal("expected one JSONL event")
	}
	var got Event
	if err := json.Unmarshal(scanner.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Type != TypeRunStarted || got.Sequence != 1 {
		t.Fatalf("bad event: %+v", got)
	}
	if scanner.Scan() {
		t.Fatal("expected exactly one JSONL event")
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestTimelineVocabularyNeverLeaksProviderLifecycleNames(t *testing.T) {
	if got := timelineType(digest.Event{Kind: digest.KindLifecycle, ProviderEvent: "turn.failed"}); got != TypeAgentLifecycle {
		t.Fatalf("lifecycle type = %q", got)
	}
	if got := timelineType(digest.Event{Kind: digest.KindError, ProviderEvent: "turn.failed"}); got != TypeAgentError {
		t.Fatalf("error type = %q", got)
	}
	if got := timelineType(digest.Event{Kind: digest.KindTask, Phase: "future_phase"}); got != TypeAgentEventUnsupported {
		t.Fatalf("unknown task phase type = %q", got)
	}
}

func TestValidateEnvelopeRequiresV2Producer(t *testing.T) {
	event := Event{SchemaVersion: SchemaVersion, RunID: "r-1", Sequence: 1, Source: Source}
	if err := ValidateEnvelope(event, "r-1", 1); err == nil {
		t.Fatal("v2 event without producer was accepted")
	}
	event.Producer = runrecord.Producer{Name: "acta", Version: "v2.0.0"}
	if err := ValidateEnvelope(event, "r-1", 1); err != nil {
		t.Fatal(err)
	}
}

func TestValidateEnvelopeVersionGatesRegeneratedBy(t *testing.T) {
	regenerator := runrecord.Producer{Name: "acta", Version: "v3.0.0"}
	for _, schemaVersion := range []int{2, 3} {
		t.Run(fmt.Sprintf("v%d", schemaVersion), func(t *testing.T) {
			event := Event{
				SchemaVersion: schemaVersion,
				Producer:      runrecord.Producer{Name: "acta", Version: "v2.0.0"},
				RegeneratedBy: &regenerator,
				RunID:         "r-1",
				Sequence:      1,
				Source:        Source,
			}
			err := ValidateEnvelope(event, "r-1", 1)
			if schemaVersion == 2 {
				if err == nil || !strings.Contains(err.Error(), "regenerated_by") {
					t.Fatalf("ValidateEnvelope() error = %v, want unsupported regenerated_by", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateEnvelope() rejected v3 regenerated_by: %v", err)
			}
		})
	}
}

func TestValidateEventVersionGatesWithheldArtifactFields(t *testing.T) {
	tests := []struct {
		name  string
		field string
		setV2 func(*ArtifactRef)
	}{
		{name: "status", field: "status", setV2: func(ref *ArtifactRef) { ref.Status = ArtifactStatusWithheld }},
		{name: "reason", field: "reason", setV2: func(ref *ArtifactRef) { ref.Reason = "reasoning_redaction_unverified" }},
		{name: "redaction state", field: "redaction_state", setV2: func(ref *ArtifactRef) { ref.RedactionState = ArtifactRedactionStateUnverified }},
	}
	for _, test := range tests {
		for _, schemaVersion := range []int{2, 3} {
			t.Run(fmt.Sprintf("%s/v%d", test.name, schemaVersion), func(t *testing.T) {
				ref := ArtifactRef{Kind: "raw_stderr", Path: "agent.stderr.log"}
				if schemaVersion == 2 {
					test.setV2(&ref)
				} else {
					ref.Status = ArtifactStatusWithheld
					ref.Reason = "reasoning_redaction_unverified"
					ref.RedactionState = ArtifactRedactionStateUnverified
				}
				event := Event{
					SchemaVersion: schemaVersion,
					Producer:      runrecord.Producer{Name: "acta", Version: "test"},
					RunID:         "r-1",
					Sequence:      1,
					Source:        Source,
					Type:          TypeRunCompleted,
					Payload:       json.RawMessage(`{"status":"ok","ok":true,"timeout":false,"duration_ms":0}`),
					ArtifactRefs:  []ArtifactRef{ref},
				}
				err := ValidateEvent(event, "r-1", 1)
				if schemaVersion == 2 {
					if err == nil || !strings.Contains(err.Error(), test.field) {
						t.Fatalf("ValidateEvent() error = %v, want unsupported %s", err, test.field)
					}
					return
				}
				if err != nil {
					t.Fatalf("ValidateEvent() rejected v3 withheld %s: %v", test.field, err)
				}
			})
		}
	}
}

func TestValidateEventRejectsNonPositiveArtifactLines(t *testing.T) {
	event := Event{
		SchemaVersion: SchemaVersion,
		Producer:      runrecord.Producer{Name: "acta", Version: "test"},
		RunID:         "r-1",
		Sequence:      1,
		Timestamp:     time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC),
		Source:        Source,
		Type:          TypeRunCompleted,
		Payload:       json.RawMessage(`{"status":"ok","ok":true,"timeout":false,"duration_ms":0}`),
		ArtifactRefs: []ArtifactRef{{
			Kind: "raw_stdout", Path: "codex-events.jsonl", Lines: []int{0, -1},
		}},
	}
	if err := ValidateEvent(event, "r-1", 1); err == nil {
		t.Fatal("artifact reference lines [0,-1] were accepted")
	}
}

func TestWriteRejectsOversizedEvent(t *testing.T) {
	event := Event{
		SchemaVersion: 1, RunID: "r-1", Sequence: 1, Source: Source,
		Timestamp: time.Now(), Type: TypeAgentMessage,
		Payload: json.RawMessage(`{"text":"` + strings.Repeat("x", MaxEventBytes) + `"}`),
	}
	if err := Write(t.TempDir(), []Event{event}); err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("Write() error = %v", err)
	}
}

func FuzzValidateReplayedEventDoesNotPanic(f *testing.F) {
	f.Add(SchemaVersion, "r-1", 1, Source, TypeRunStarted, []byte(`{"agent":"codex"}`), 1, "acta", "dev")
	f.Add(1, "legacy", 7, Source, "future.event", []byte(`null`), 3, "", "")
	f.Add(0, "", -1, "provider", "", []byte(`not-json`), -2, "", "")

	f.Fuzz(func(t *testing.T, schemaVersion int, runID string, sequence int, source string, eventType string, payload []byte, expectedSequence int, producerName string, producerVersion string) {
		if len(runID)+len(source)+len(eventType)+len(payload)+len(producerName)+len(producerVersion) > 1<<20 {
			t.Skip()
		}
		event := Event{
			SchemaVersion: schemaVersion,
			Producer:      runrecord.Producer{Name: producerName, Version: producerVersion},
			RunID:         runID,
			Sequence:      sequence,
			Timestamp:     time.Unix(0, 0).UTC(),
			Source:        source,
			Type:          eventType,
			Payload:       json.RawMessage(payload),
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			return
		}
		var replayed Event
		if err := json.Unmarshal(encoded, &replayed); err != nil {
			t.Fatalf("marshal produced an unreadable event: %v", err)
		}
		_ = ValidateEvent(replayed, runID, expectedSequence)
	})
}
