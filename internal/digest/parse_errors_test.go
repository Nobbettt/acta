package digest

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nobbettt/acta/internal/runrecord"
)

// A corrupt/garbage stream line must be counted and surfaced as an error while
// valid events still parse and blank lines are ignored.
func TestParseErrorsFailOnUnparseableLines(t *testing.T) {
	raw := strings.Join([]string{
		`{"type":"item.completed","item":{"id":"c1","type":"command_execution","command":"ls","status":"completed","exit_code":0}}`,
		`not json at all`,
		``, // blank line — must NOT count
		`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`,
	}, "\n") + "\n"

	d, err := parseCodex(strings.NewReader(raw), newWorkspace(""))
	if err == nil {
		t.Fatal("expected malformed JSONL to fail the digest")
	}
	if d.Metrics.ParseErrors != 1 {
		t.Fatalf("parse_errors = %d, want 1 (garbage line only; blank ignored)", d.Metrics.ParseErrors)
	}
	if d.Metrics.Commands != 1 {
		t.Fatalf("valid events must still parse: commands = %d, want 1", d.Metrics.Commands)
	}
}

// The live StreamDigester counts and surfaces parse errors the same way as the
// pull parser, and — critically — keeps consuming lines after a malformed one
// instead of truncating the rest of the run, so a live digest equals a
// re-digest of the same bundle.
func TestStreamDigesterFailsOnParseErrors(t *testing.T) {
	sd, err := NewStreamDigester("codex", "")
	if err != nil {
		t.Fatal(err)
	}
	sd.Line([]byte(`garbage`), time.Time{})
	// A valid event AFTER the garbage line must still be digested.
	sd.Line([]byte(`{"type":"item.completed","item":{"id":"c1","type":"command_execution","command":"ls","status":"completed","exit_code":0}}`), time.Time{})
	sd.Line([]byte(``), time.Time{}) // blank — ignored
	d := sd.codex.d
	if d.Metrics.ParseErrors != 1 {
		t.Fatalf("parse_errors = %d, want 1", d.Metrics.ParseErrors)
	}
	if d.Metrics.Commands != 1 {
		t.Fatalf("commands = %d, want 1 (line after garbage must still parse, no truncation)", d.Metrics.Commands)
	}
	if sd.Err() == nil {
		t.Fatal("expected StreamDigester.Err after malformed JSONL")
	}
}

// FromRunDir surfaces parse errors but still returns the digest built from the
// lines that did parse, rather than discarding it — so `acta digest` writes a
// (fail-loud) digest that matches the live run instead of producing nothing.
func TestFromRunDirKeepsDigestOnParseError(t *testing.T) {
	dir := t.TempDir()
	raw := `{"type":"item.completed","item":{"id":"c1","type":"command_execution","command":"ls","status":"completed","exit_code":0}}` + "\n" + "not json\n"
	if err := os.WriteFile(filepath.Join(dir, "codex-events.jsonl"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := runrecord.Record{ID: "r1", Agent: "codex", CWD: dir, RunDir: dir, RawStdoutPath: filepath.Join(dir, "codex-events.jsonl")}
	payload, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run.json"), payload, 0o644); err != nil {
		t.Fatal(err)
	}

	d, err := FromRunDir(dir, "")
	if err == nil {
		t.Fatal("expected an error for a bundle with a malformed line")
	}
	if d == nil {
		t.Fatal("digest must be returned alongside the parse error, not discarded")
		return
	}
	if d.Metrics.ParseErrors != 1 || d.Metrics.Commands != 1 {
		t.Fatalf("parse_errors=%d commands=%d, want 1 and 1", d.Metrics.ParseErrors, d.Metrics.Commands)
	}
}

// readBoundedLine caps a single line so a giant newline-free blob cannot exhaust
// memory, and still resyncs to the next line afterwards.
func TestReadBoundedLineTruncatesAndResyncs(t *testing.T) {
	const cap = 8
	huge := strings.Repeat("x", 100)
	r := bufio.NewReaderSize(strings.NewReader(huge+"\n"+"ok\n"), 16)

	first, err := readBoundedLine(r, cap)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != cap {
		t.Fatalf("first line len = %d, want capped at %d", len(first), cap)
	}
	second, err := readBoundedLine(r, cap)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(second)) != "ok" {
		t.Fatalf("second line = %q, want \"ok\" (must resync past the oversized line)", strings.TrimSpace(string(second)))
	}
}
