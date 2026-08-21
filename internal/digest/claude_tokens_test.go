package digest

import (
	"strings"
	"testing"
)

// A killed/timeout run has no final `result` line, so token metrics fall back
// to the assistant messages' usage. The fallback must sum output across
// distinct messages (not report only the last call), and must not double-count
// a message whose content blocks arrive on separate stream lines repeating the
// same usage.
func TestClaudeKilledRunSumsUsageAcrossMessages(t *testing.T) {
	lines := []string{
		`{"type":"assistant","message":{"id":"msg_a","usage":{"input_tokens":100,"output_tokens":10},"content":[{"type":"text","text":"hi"}]}}`,
		`{"type":"assistant","message":{"id":"msg_a","usage":{"input_tokens":100,"output_tokens":10},"content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"ls"}}]}}`,
		`{"type":"assistant","message":{"id":"msg_b","usage":{"input_tokens":250,"output_tokens":40},"content":[{"type":"text","text":"done"}]}}`,
	}
	d, err := parseClaude(strings.NewReader(strings.Join(lines, "\n")+"\n"), newWorkspace(""))
	if err == nil || !strings.Contains(err.Error(), "without a result") {
		t.Fatalf("semantic error = %v, want missing-result failure", err)
	}
	// msg_a counted once (10) + msg_b (40) = 50; not 10 (last only), not 60 (split double-counted).
	if d.Metrics.Tokens.Output != 50 {
		t.Fatalf("output = %d, want 50 (sum of distinct messages, split line not double-counted)", d.Metrics.Tokens.Output)
	}
	if d.Metrics.Tokens.Input != 350 {
		t.Fatalf("input = %d, want 350", d.Metrics.Tokens.Input)
	}
	if d.Metrics.Tokens.Total != 400 {
		t.Fatalf("total = %d, want 400", d.Metrics.Tokens.Total)
	}
}
