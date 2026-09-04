package digest

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// classifyEventCommand and applyRunState run on an event already appended (and
// therefore already normalized) by consumeToolUse, so the caps normalizeEvent
// enforces on every other path must be re-applied explicitly. Without that,
// an rm with more operands than the 1024-entry cap allows would leak that many
// targets and mutations straight through the claude path while the identical
// codex command — classified before its event is ever appended — stays capped.
func TestClaudeCommandClassificationCappedAfterAppend(t *testing.T) {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	// Two-character operands keep the command inside the tokenization limit,
	// but "cd" is skipped: a standalone cd operand taints every path in the
	// command, and this fixture exists to prove the 1,024 cap, not that.
	operands := make([]string, 0, len(alphabet)*len(alphabet))
	for _, a := range alphabet {
		for _, b := range alphabet {
			operand := string(a) + string(b)
			if operand == "cd" {
				continue
			}
			operands = append(operands, operand)
		}
	}
	command := "rm " + strings.Join(operands, " ")
	if len(command) > maxCommandTokenizationChars {
		t.Fatalf("test setup: command is %d chars, want <= %d", len(command), maxCommandTokenizationChars)
	}
	if len(operands) <= 1024 {
		t.Fatalf("test setup: only %d operands, want > 1024", len(operands))
	}

	commandJSON, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{
		fmt.Sprintf(`{"type":"assistant","message":{"id":"m1","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":%s}}]}}`, commandJSON),
		`{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t1","content":"done"}]},"tool_use_result":{"exit_code":0}}`,
	}
	d, err := parseClaude(strings.NewReader(claudeSuccessfulStream(lines...)), newWorkspace(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Timeline) != 1 {
		t.Fatalf("timeline = %d events, want 1", len(d.Timeline))
	}
	e := d.Timeline[0]
	if !slices.Contains(e.Categories, "fs.delete") {
		t.Fatalf("categories = %v, want fs.delete", e.Categories)
	}
	if len(e.Targets) != 1024 || len(e.ShellMutations) != 1024 {
		t.Fatalf("classification fields = targets:%d mutations:%d, want 1024 each", len(e.Targets), len(e.ShellMutations))
	}
}

func TestClaudeNonzeroExitWithoutIsErrorCreditsSandboxDenied(t *testing.T) {
	lines := []string{
		`{"type":"assistant","message":{"id":"m1","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"touch /root/x"}}]}}`,
		`{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t1","content":"touch: /root/x: Permission denied"}]},"tool_use_result":{"exit_code":1}}`,
	}
	d, err := parseClaude(strings.NewReader(claudeSuccessfulStream(lines...)), newWorkspace(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Timeline) != 1 {
		t.Fatalf("timeline = %d events, want 1", len(d.Timeline))
	}
	e := d.Timeline[0]
	if e.IsError {
		t.Fatal("test setup: is_error must be absent/false")
	}
	if e.ExitCode == nil || *e.ExitCode != 1 {
		t.Fatalf("exit code = %v, want 1", e.ExitCode)
	}
	if !slices.Contains(e.Categories, "sandbox.denied") {
		t.Fatalf("categories = %v, want sandbox.denied", e.Categories)
	}
}

func TestClaudeNonzeroExitWithoutIsErrorDoesNotCreditRead(t *testing.T) {
	lines := []string{
		`{"type":"assistant","message":{"id":"m1","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"cat README.md"}}]}}`,
		`{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t1","content":"cat: README.md: Permission denied"}]},"tool_use_result":{"exit_code":1}}`,
	}
	d, err := parseClaude(strings.NewReader(claudeSuccessfulStream(lines...)), newWorkspace(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Timeline) != 1 {
		t.Fatalf("timeline = %d events, want 1", len(d.Timeline))
	}
	e := d.Timeline[0]
	if len(e.Files) != 0 || slices.Contains(e.Categories, "instructions.read") {
		t.Fatalf("failed read credited files/categories: files=%v categories=%v", e.Files, e.Categories)
	}
	for _, target := range e.Targets {
		if target.Kind == "path" {
			t.Fatalf("failed read credited path target %+v", target)
		}
	}
}

func TestClaudeBashCommandPreservesCarriageReturn(t *testing.T) {
	lines := []string{
		`{"type":"assistant","message":{"id":"m1","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"env\r"}}]}}`,
		`{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t1","content":"env\\r: command not found"}]} ,"tool_use_result":{"exit_code":127}}`,
	}
	d, err := parseClaude(strings.NewReader(claudeSuccessfulStream(lines...)), newWorkspace(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Timeline) != 1 {
		t.Fatalf("timeline = %d events, want 1", len(d.Timeline))
	}
	e := d.Timeline[0]
	if e.Command != "env\r" {
		t.Errorf("command = %q, want carriage return preserved", e.Command)
	}
	if slices.Contains(e.Categories, "env.inspect") {
		t.Errorf("categories = %v, want no env.inspect for command word env\\r", e.Categories)
	}
}

func TestClaudeCommandClassificationCannotCrossProjectionBudget(t *testing.T) {
	state := &claudeParseState{
		d:         &Digest{},
		ws:        newWorkspace(""),
		pending:   map[string]int{},
		usageSeen: map[string]bool{},
	}
	input := json.RawMessage(`{"command":"git remote -v"}`)
	state.consumeAssistantContent(
		&ClaudeContent{Type: "tool_use", ID: "t1", Name: "Bash", Input: input},
		&ClaudeItem{Message: &ClaudeMessage{ID: "m1"}},
		1,
		time.Time{},
	)
	if len(state.d.Timeline) != 1 {
		t.Fatalf("test setup: timeline = %d events, want 1", len(state.d.Timeline))
	}
	state.d.projectionLimitBytes = state.d.projectionBytes + MaxEventOutputChars + 4096

	// Distinct HOSTS, not long paths: only a remote's origin is published, so
	// path length no longer grows the payload — many hosts do.
	var output strings.Builder
	for i := 0; i < 25; i++ {
		fmt.Fprintf(&output, "remote%d\thttps://%s%02d.example.test/repo.git (fetch)\n", i, strings.Repeat("h", 3800), i)
	}
	contentJSON, err := json.Marshal(output.String())
	if err != nil {
		t.Fatal(err)
	}
	result := ClaudeContent{ToolUseID: "t1", Content: contentJSON}
	state.consumeToolResult(&result, json.RawMessage(`{"exit_code":0}`), 2, time.Time{})

	if len(state.d.Timeline) != 0 {
		t.Fatalf("timeline retained %d events, want the over-budget completed event dropped", len(state.d.Timeline))
	}
	if state.d.projectionBytes > state.d.projectionLimit() {
		t.Fatalf("projection retained %d bytes, limit is %d", state.d.projectionBytes, state.d.projectionLimit())
	}
	if !state.d.Metrics.ProjectionTruncated || state.d.Metrics.DroppedEvents != 1 {
		t.Fatalf("metrics = %+v, want one projection-budget drop", state.d.Metrics)
	}
}

// A Bash tool_use that never gets a matching tool_result (the run was killed,
// timed out, or cancelled) still finalizes into a shell.command.incomplete
// event. codex classifies the equivalent unfinished item in its own finalize
// path (codexItemEvent with completedLine 0); claude must do the same so
// classification does not depend on which agent produced the digest.
func TestClaudeIncompleteCommandStillClassified(t *testing.T) {
	lines := []string{
		`{"type":"assistant","message":{"id":"m1","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"git status"}}]}}`,
	}
	d, err := parseClaude(strings.NewReader(strings.Join(lines, "\n")+"\n"), newWorkspace(""))
	if err == nil {
		t.Fatal("expected semantic error for a stream that never reaches a result event")
	}
	if len(d.Timeline) != 1 {
		t.Fatalf("timeline = %d events, want 1", len(d.Timeline))
	}
	e := d.Timeline[0]
	if e.Status != "incomplete" {
		t.Fatalf("status = %q, want incomplete", e.Status)
	}
	if !slices.Contains(e.Categories, "vcs.read") {
		t.Fatalf("categories = %v, want vcs.read credited even though the command never completed", e.Categories)
	}
}

func TestClaudeIncompleteClassificationRespectsProjectionBudget(t *testing.T) {
	for _, headroom := range []int{0, 6} {
		t.Run(fmt.Sprintf("headroom_%d", headroom), func(t *testing.T) {
			state := &claudeParseState{
				d:         &Digest{},
				ws:        newWorkspace(""),
				pending:   map[string]int{},
				usageSeen: map[string]bool{},
			}
			state.consumeAssistantContent(
				&ClaudeContent{Type: "tool_use", ID: "t1", Name: "Bash", Input: json.RawMessage(`{"command":"git status"}`)},
				&ClaudeItem{Message: &ClaudeMessage{ID: "m1"}},
				1,
				time.Time{},
			)
			if len(state.d.Timeline) != 1 {
				t.Fatalf("test setup: timeline = %d events, want 1", len(state.d.Timeline))
			}
			state.d.projectionLimitBytes = state.d.projectionBytes + headroom

			d := state.finalize()
			if len(d.Timeline) != 0 {
				t.Fatalf("timeline retained %d events, want over-budget incomplete event dropped", len(d.Timeline))
			}
			if d.projectionBytes > d.projectionLimit() {
				t.Fatalf("projection retained %d bytes, limit is %d", d.projectionBytes, d.projectionLimit())
			}
			if !d.Metrics.ProjectionTruncated || d.Metrics.DroppedEvents != 1 {
				t.Fatalf("metrics = %+v, want one projection-budget drop", d.Metrics)
			}
			if d.Termination.ProviderReason != "projection_limit_exceeded" {
				t.Fatalf("provider reason = %q, want projection_limit_exceeded", d.Termination.ProviderReason)
			}
		})
	}
}
