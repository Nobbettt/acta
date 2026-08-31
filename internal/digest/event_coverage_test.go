package digest

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCodexCapturesRichItemsFailuresAndIncompleteCalls(t *testing.T) {
	raw := strings.Join([]string{
		`{"type":"thread.started","thread_id":"thread-1"}`,
		`{"type":"turn.started"}`,
		`{"type":"item.completed","item":{"id":"reason-1","type":"reasoning","text":"Inspect the failing path."}}`,
		`{"type":"item.started","item":{"id":"mcp-1","type":"mcp_tool_call","server":"docs","tool":"lookup","arguments":{"query":"events"},"status":"in_progress"}}`,
		`{"type":"item.completed","item":{"id":"mcp-1","type":"mcp_tool_call","server":"docs","tool":"lookup","arguments":{"query":"events"},"result":{"content":[{"type":"text","text":"found"}],"structured_content":{"count":1}},"status":"completed"}}`,
		`{"type":"item.started","item":{"id":"web-1","type":"web_search","query":"agent event schema","action":{"type":"search"}}}`,
		`{"type":"item.completed","item":{"id":"future-1","type":"future_item","value":42}}`,
		`{"type":"turn.failed","error":{"message":"context limit","code":"context_window_exceeded"}}`,
	}, "\n") + "\n"

	d, err := parseCodex(strings.NewReader(raw), newWorkspace(""))
	if err == nil || !strings.Contains(err.Error(), "unsupported event") {
		t.Fatalf("semantic error = %v, want unsupported-event failure", err)
	}
	if d.ThreadID != "thread-1" {
		t.Fatalf("thread_id = %q", d.ThreadID)
	}
	if d.Termination.Outcome != "failed" || d.Termination.ErrorMessage != "context limit" {
		t.Fatalf("termination = %+v", d.Termination)
	}
	if d.Metrics.UnsupportedEvents["item.future_item"] != 1 {
		t.Fatalf("unsupported = %+v", d.Metrics.UnsupportedEvents)
	}
	if d.Metrics.IncompleteToolCalls != 1 {
		t.Fatalf("incomplete_tool_calls = %d, want 1", d.Metrics.IncompleteToolCalls)
	}

	var reasoning, mcp, web, unsupported *Event
	for i := range d.Timeline {
		event := &d.Timeline[i]
		switch event.Kind {
		case KindReasoning:
			reasoning = event
		case KindToolCall:
			mcp = event
		case KindWebSearch:
			web = event
		case KindUnsupported:
			unsupported = event
		}
	}
	if reasoning == nil || reasoning.Text != "" || reasoning.LocalReasoningText() != "Inspect the failing path." {
		t.Fatalf("reasoning boundary = %#v / %q, want structural digest plus local-only text", reasoning, reasoning.LocalReasoningText())
	}
	dir := t.TempDir()
	if err := Write(dir, d); err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(filepath.Join(dir, "digest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), "Inspect the failing path.") {
		t.Fatalf("persisted digest leaked reasoning text: %s", persisted)
	}
	if mcp == nil || mcp.Server != "docs" || mcp.Tool != "lookup" || len(mcp.Input) == 0 || len(mcp.Result) == 0 {
		t.Fatalf("mcp event = %+v", mcp)
	}
	if web == nil || web.Query != "agent event schema" || web.Status != "incomplete" || web.CompletedAt != nil {
		t.Fatalf("web event = %+v", web)
	}
	if unsupported == nil || unsupported.Visibility != VisibilityDiagnostic || len(unsupported.Details) == 0 {
		t.Fatalf("unsupported event = %+v", unsupported)
	}
	if len(mcp.RawEventLines) != 2 {
		t.Fatalf("mcp raw lines = %v, want start and completion", mcp.RawEventLines)
	}
}

func TestClaudeCapturesRuntimeTasksOrphansPermissionsAndTermination(t *testing.T) {
	raw := strings.Join([]string{
		`{"type":"system","subtype":"init","session_id":"session-1","model":"claude-test","tools":["Bash","WebSearch"],"agents":["Explore"],"skills":["debug"],"claude_code_version":"2.1.228","permissionMode":"default"}`,
		`{"type":"assistant","session_id":"session-1","message":{"id":"message-1","content":[{"type":"tool_use","id":"pending-1","name":"WebSearch","input":{"query":"event schemas"}}]}}`,
		`{"type":"user","session_id":"session-1","message":{"content":[{"type":"tool_result","tool_use_id":"missing-1","content":"late result"}]}}`,
		`{"type":"system","subtype":"task_started","session_id":"session-1","task_id":"task-1","tool_use_id":"agent-1","description":"Inspect code","prompt":"Find the parser"}`,
		`{"type":"system","subtype":"task_progress","session_id":"session-1","task_id":"task-1","tool_use_id":"agent-1","description":"Reading parser","last_tool_name":"Read"}`,
		`{"type":"system","subtype":"task_notification","session_id":"session-1","task_id":"task-1","tool_use_id":"agent-1","status":"completed","summary":"Inspection complete"}`,
		`{"type":"rate_limit_event","session_id":"session-1","rate_limit_info":{"status":"allowed"}}`,
		`{"type":"result","subtype":"success","session_id":"session-1","is_error":false,"stop_reason":"end_turn","num_turns":2,"structured_output":{"answer":"done"},"modelUsage":{"claude-test":{"outputTokens":4}},"permission_denials":[{"tool_name":"Edit","tool_use_id":"edit-1","tool_input":{"file_path":"main.go"}}]}`,
	}, "\n") + "\n"

	d, err := parseClaude(strings.NewReader(raw), newWorkspace(""))
	if err != nil {
		t.Fatal(err)
	}
	if d.SessionID != "session-1" || d.Runtime.Version != "2.1.228" || len(d.Runtime.Tools) != 2 {
		t.Fatalf("runtime/session = %+v / %q", d.Runtime, d.SessionID)
	}
	if d.Termination.ProviderReason != "end_turn" || d.Termination.Outcome != "completed" {
		t.Fatalf("termination = %+v", d.Termination)
	}
	if d.Metrics.IncompleteToolCalls != 1 || d.Metrics.OrphanedToolResults != 1 {
		t.Fatalf("lifecycle metrics = %+v", d.Metrics)
	}
	if len(d.StructuredOutput) == 0 || len(d.ModelUsage) == 0 {
		t.Fatal("result metadata was not retained")
	}

	wantKinds := map[string]bool{
		KindRuntime: false, KindWebSearch: false, KindToolResult: false,
		KindTask: false, KindRateLimit: false, KindStructuredOutput: false, KindPermission: false,
	}
	for _, event := range d.Timeline {
		if _, ok := wantKinds[event.Kind]; ok {
			wantKinds[event.Kind] = true
		}
	}
	for kind, found := range wantKinds {
		if !found {
			t.Errorf("missing event kind %q", kind)
		}
	}
}

func TestClaudeRedactedThinkingRetainsStructuralReasoningEvent(t *testing.T) {
	originalRaw := strings.Join([]string{
		`{"type":"system","subtype":"init","session_id":"session-1"}`,
		`{"type":"assistant","session_id":"session-1","message":{"id":"message-1","content":[{"type":"thinking","thinking":"private chain of thought"}]}}`,
		`{"type":"result","subtype":"success","session_id":"session-1","is_error":false}`,
	}, "\n") + "\n"
	redactedRaw := strings.Replace(originalRaw, `{"type":"thinking","thinking":"private chain of thought"}`, `{"type":"thinking"}`, 1)

	original, err := parseClaude(strings.NewReader(originalRaw), newWorkspace(""))
	if err != nil {
		t.Fatal(err)
	}
	redacted, err := parseClaude(strings.NewReader(redactedRaw), newWorkspace(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(redacted.Timeline) != len(original.Timeline) {
		t.Fatalf("redacted timeline event count = %d, original = %d", len(redacted.Timeline), len(original.Timeline))
	}
	originalReasoning := findTimelineKind(original.Timeline, KindReasoning)
	redactedReasoning := findTimelineKind(redacted.Timeline, KindReasoning)
	if originalReasoning == nil || redactedReasoning == nil {
		t.Fatalf("reasoning events original=%+v redacted=%+v", originalReasoning, redactedReasoning)
	}
	if originalReasoning.LocalReasoningText() != "private chain of thought" || originalReasoning.Redacted {
		t.Fatalf("original reasoning event = %+v / %q", originalReasoning, originalReasoning.LocalReasoningText())
	}
	if !redactedReasoning.Redacted || redactedReasoning.LocalReasoningText() != "" ||
		redactedReasoning.Kind != originalReasoning.Kind ||
		redactedReasoning.ProviderEvent != originalReasoning.ProviderEvent ||
		strings.TrimSpace(redactedReasoning.Text) != "" ||
		len(redactedReasoning.RawEventLines) != 1 || redactedReasoning.RawEventLines[0] != 2 {
		t.Fatalf("redacted structural reasoning event = %+v / %q", redactedReasoning, redactedReasoning.LocalReasoningText())
	}
}

func TestClaudeRedactedThinkingBlockDigestsCleanlyAndStably(t *testing.T) {
	const secret = "opaque-redacted-thinking-data"
	dir := t.TempDir()
	rawName := "claude-output.jsonl"
	raw := strings.Join([]string{
		`{"type":"system","subtype":"init","session_id":"session-1"}`,
		`{"type":"assistant","session_id":"session-1","message":{"id":"message-1","content":[{"type":"redacted_thinking","data":"` + secret + `"}]}}`,
		`{"type":"result","subtype":"success","session_id":"session-1","is_error":false}`,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, rawName), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	record := validTestRecord(dir, rawName)
	record.Agent = "claude"
	record.Command = []string{"claude", "--print"}
	writeRecord(t, dir, record)

	first, err := FromRunDir(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != StatusOK || first.Termination.Outcome != OutcomeCompleted || len(first.Metrics.UnsupportedEvents) != 0 {
		t.Fatalf("redacted_thinking degraded run: status %q, termination %+v, unsupported %+v", first.Status, first.Termination, first.Metrics.UnsupportedEvents)
	}
	firstReasoning := findTimelineKind(first.Timeline, KindReasoning)
	if firstReasoning == nil || !firstReasoning.Redacted || firstReasoning.ProviderEvent != "assistant.redacted_thinking" ||
		firstReasoning.Text != "" || firstReasoning.LocalReasoningText() != "" || firstReasoning.Details != nil {
		t.Fatalf("redacted_thinking event retained payload or lost structure: %+v", firstReasoning)
	}
	if err := Write(dir, first); err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(filepath.Join(dir, "digest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(persisted, []byte(secret)) {
		t.Fatalf("digest.json retained redacted_thinking data: %s", persisted)
	}

	second, err := FromRunDir(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	secondReasoning := findTimelineKind(second.Timeline, KindReasoning)
	if secondReasoning == nil || !reflect.DeepEqual(*secondReasoning, *firstReasoning) {
		t.Fatalf("re-digested reasoning event = %+v, want %+v", secondReasoning, firstReasoning)
	}
}

func TestCodexRedactedReasoningRetainsStructuralReasoningEvent(t *testing.T) {
	originalRaw := strings.Join([]string{
		`{"type":"thread.started","thread_id":"thread-1"}`,
		`{"type":"turn.started"}`,
		`{"type":"item.completed","item":{"id":"reason-1","type":"reasoning","text":"private chain of thought"}}`,
		`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`,
	}, "\n") + "\n"
	redactedRaw := strings.Replace(originalRaw, `,"text":"private chain of thought"`, "", 1)

	original, err := parseCodex(strings.NewReader(originalRaw), newWorkspace(""))
	if err != nil {
		t.Fatal(err)
	}
	redacted, err := parseCodex(strings.NewReader(redactedRaw), newWorkspace(""))
	if err != nil {
		t.Fatal(err)
	}
	originalReasoning := findTimelineKind(original.Timeline, KindReasoning)
	redactedReasoning := findTimelineKind(redacted.Timeline, KindReasoning)
	if originalReasoning == nil || redactedReasoning == nil {
		t.Fatalf("reasoning events original=%+v redacted=%+v", originalReasoning, redactedReasoning)
	}
	if originalReasoning.Redacted || originalReasoning.LocalReasoningText() != "private chain of thought" {
		t.Fatalf("original reasoning event = %+v / %q", originalReasoning, originalReasoning.LocalReasoningText())
	}
	if !redactedReasoning.Redacted || redactedReasoning.LocalReasoningText() != "" ||
		redactedReasoning.Kind != originalReasoning.Kind ||
		redactedReasoning.ProviderEvent != originalReasoning.ProviderEvent ||
		len(redactedReasoning.RawEventLines) != 1 || redactedReasoning.RawEventLines[0] != 3 {
		t.Fatalf("redacted structural reasoning event = %+v / %q", redactedReasoning, redactedReasoning.LocalReasoningText())
	}
}

func findTimelineKind(timeline []Event, kind string) *Event {
	for index := range timeline {
		if timeline[index].Kind == kind {
			return &timeline[index]
		}
	}
	return nil
}
