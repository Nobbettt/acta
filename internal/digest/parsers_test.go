package digest

import (
	"os"
	"strings"
	"testing"
)

// fixtureWorkspace is invented test data. The Claude fixture deliberately uses
// its /private-prefixed macOS alias to exercise workspace normalization.
const fixtureWorkspace = "/tmp/acta-fixture"

func parseFixture(t *testing.T, name string, parse func(r *os.File, ws *workspace) (*Digest, error)) *Digest {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d, err := parse(f, newWorkspace(fixtureWorkspace))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestParseCodexFixture(t *testing.T) {
	d := parseFixture(t, "codex-events.jsonl", func(r *os.File, ws *workspace) (*Digest, error) {
		return parseCodex(r, ws)
	})

	if d.Metrics.Commands != 2 {
		t.Errorf("commands = %d, want 2", d.Metrics.Commands)
	}
	if d.Metrics.Edits != 1 {
		t.Errorf("edits = %d, want 1", d.Metrics.Edits)
	}
	if d.Metrics.Turns != 1 {
		t.Errorf("turns = %d, want 1", d.Metrics.Turns)
	}
	tok := d.Metrics.Tokens
	if tok.Input != 120 || tok.CacheRead != 80 || tok.Output != 30 {
		t.Errorf("tokens = %+v, want input 120 / cache_read 80 / output 30", tok)
	}
	// Five primary actions plus thread/turn boundaries, one todo update, its
	// inferred incomplete terminal state, and the terminal turn event.
	if len(d.Timeline) != 10 {
		t.Errorf("timeline = %d events, want 10", len(d.Timeline))
	}
	if d.ThreadID == "" || d.Termination.ProviderReason != "turn_completed" {
		t.Errorf("thread/termination metadata missing: thread=%q termination=%+v", d.ThreadID, d.Termination)
	}
	if d.FinalMessage == "" || !strings.Contains(d.FinalMessage, "Synthetic task complete") {
		t.Errorf("final message missing or unexpected: %.80q", d.FinalMessage)
	}

	// `/bin/sh -lc "sed -n '1,40p' src/main.go"` must credit
	// the file with the sed range, via -lc unwrap.
	found := false
	for _, e := range d.Timeline {
		if e.Kind == KindCommand && strings.HasPrefix(e.Command, "sed -n '1,40p'") {
			found = true
			spans := e.Spans["src/main.go"]
			if len(spans) != 1 || spans[0] != (Span{Start: 1, End: 40}) {
				t.Errorf("sed command spans = %v, want [{1 40}]", spans)
			}
		}
	}
	if !found {
		t.Error("sed command event not found in timeline")
	}

	// file_change paths (/var/...) must normalize to repo-relative.
	for _, e := range d.Timeline {
		if e.Kind == KindFileEdit {
			for _, f := range e.Files {
				if strings.HasPrefix(f, "/") {
					t.Errorf("file_change path not normalized: %s", f)
				}
			}
		}
	}
}

func TestParseClaudeFixture(t *testing.T) {
	d := parseFixture(t, "claude-output.jsonl", func(r *os.File, ws *workspace) (*Digest, error) {
		return parseClaude(r, ws)
	})

	wantTools := map[string]int{"Read": 1, "Bash": 1, "Grep": 1, "Edit": 1}
	for tool, want := range wantTools {
		if got := d.Metrics.ToolCalls[tool]; got != want {
			t.Errorf("tool_calls[%s] = %d, want %d", tool, got, want)
		}
	}
	if d.Metrics.Commands != 1 {
		t.Errorf("commands = %d, want 1", d.Metrics.Commands)
	}
	if d.Metrics.Edits != 1 {
		t.Errorf("edits = %d, want 1", d.Metrics.Edits)
	}
	if d.Metrics.Turns != 2 {
		t.Errorf("turns = %d, want 2", d.Metrics.Turns)
	}
	if d.Metrics.CostUSD != 0.01 {
		t.Errorf("cost = %v, want 0.01", d.Metrics.CostUSD)
	}
	tok := d.Metrics.Tokens
	if tok.Output != 20 || tok.CacheRead != 30 || tok.CacheCreation != 10 {
		t.Errorf("tokens = %+v, want output 20 / cache_read 30 / cache_creation 10", tok)
	}
	if d.Model == "" {
		t.Error("model not extracted from system init")
	}
	if d.SessionID == "" || len(d.Runtime.Tools) == 0 {
		t.Errorf("session/runtime metadata missing: session=%q runtime=%+v", d.SessionID, d.Runtime)
	}
	if d.Termination.ProviderReason != "end_turn" || d.Termination.Outcome != "completed" {
		t.Errorf("termination = %+v, want completed/end_turn", d.Termination)
	}
	if len(d.StructuredOutput) == 0 || len(d.ModelUsage) == 0 {
		t.Error("structured output and model usage should be retained from result")
	}
	// result.result is empty in this fixture; final message falls back to the
	// last assistant text.
	if strings.TrimSpace(d.FinalMessage) == "" {
		t.Error("final message empty, fallback to last assistant text failed")
	}

	// The first Read targets /private/tmp/acta-fixture/src/main.go with
	// arrow-numbered output; workspace is recorded without /private — the
	// /private toggle plus arrow span inference must both work.
	found := false
	for _, e := range d.Timeline {
		if e.Kind == KindToolCall && e.Tool == "Read" {
			for _, f := range e.Files {
				if f == "src/main.go" {
					found = true
					if len(e.Spans[f]) == 0 || e.Spans[f][0].Start != 1 {
						t.Errorf("read spans for %s = %v, want span starting at 1", f, e.Spans[f])
					}
				}
			}
			break
		}
	}
	if !found {
		t.Error("first Read of src/main.go not credited")
	}

	// files summary: src/main.go was both read and edited.
	var touch *FileTouch
	for i := range d.Files {
		if d.Files[i].Path == "src/main.go" {
			touch = &d.Files[i]
		}
	}
	files := assembleFiles(d.Timeline)
	for i := range files {
		if files[i].Path == "src/main.go" {
			touch = &files[i]
		}
	}
	if touch == nil {
		t.Fatal("src/main.go missing from files summary")
		return
	}
	if !touch.Read || !touch.Edited {
		t.Errorf("src/main.go read=%v edited=%v, want both true", touch.Read, touch.Edited)
	}
}
