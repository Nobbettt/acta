package digest

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestNormalizeCommandText(t *testing.T) {
	cases := []struct{ in, want string }{
		{"git status", "git status"},
		{"  git status  ", "git status"},
		{"git   status", "git status"},
		{"git\tstatus\nfoo", "git status\nfoo"},
		{"printf 'a  b'", "printf 'a  b'"},
		{`printf "a  b"`, `printf "a  b"`},
		{`printf a\ \ b`, `printf a\ \ b`},
		{"   ", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeCommandText(c.in); got != c.want {
			t.Errorf("normalizeCommandText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestApplyRunStateDoesNotMergeSignificantWhitespace(t *testing.T) {
	prior := Event{Kind: KindCommand, Command: "printf 'a  b'", srcLine: 1}
	e := Event{Kind: KindCommand, Command: "printf 'a b'", srcLine: 2}
	applyRunState(&Digest{Timeline: []Event{prior}}, &e, "")
	if slices.Contains(e.Categories, "command.retried") {
		t.Errorf("commands with different quoted arguments merged as retries: %v", e.Categories)
	}

	prior.Command = "git status\nfoo"
	e = Event{Kind: KindCommand, Command: "git status foo", srcLine: 2}
	applyRunState(&Digest{Timeline: []Event{prior}}, &e, "")
	if slices.Contains(e.Categories, "command.retried") {
		t.Errorf("a command list merged with a single invocation as a retry: %v", e.Categories)
	}

	for _, commands := range [][2]string{
		{"rm a b", "rm a\rb"},
		{"echo a b", "echo a\rb"},
	} {
		prior.Command = commands[0]
		e = Event{Kind: KindCommand, Command: commands[1], srcLine: 2}
		applyRunState(&Digest{Timeline: []Event{prior}}, &e, "")
		if slices.Contains(e.Categories, "command.retried") {
			t.Errorf("commands %q and %q merged as retries: %v", commands[0], commands[1], e.Categories)
		}
	}
}

// command.retried is a property of the run, not the command: the first run of a
// command is never a retry, and only shell commands take part. Every timeline
// event here is given a srcLine strictly before the event under test, so
// these cases exercise the srcLine-ordered comparison directly rather than
// relying on slice position.
func TestApplyRunStateCommandRetried(t *testing.T) {
	cases := []struct {
		name     string
		timeline []Event
		event    Event
		want     bool
	}{
		{"first run", nil, Event{Kind: KindCommand, Command: "go test ./...", srcLine: 1}, false},
		{
			"second run",
			[]Event{{Kind: KindCommand, Command: "go test ./...", srcLine: 1}},
			Event{Kind: KindCommand, Command: "go test ./...", srcLine: 2},
			true,
		},
		{
			"third run",
			[]Event{
				{Kind: KindCommand, Command: "go test ./...", srcLine: 1},
				{Kind: KindCommand, Command: "go test ./...", srcLine: 2},
			},
			Event{Kind: KindCommand, Command: "go test ./...", srcLine: 3},
			true,
		},
		{
			"whitespace only difference still counts",
			[]Event{{Kind: KindCommand, Command: " go   test ./... ", srcLine: 1}},
			Event{Kind: KindCommand, Command: "go test ./...", srcLine: 2},
			true,
		},
		{
			"different command",
			[]Event{{Kind: KindCommand, Command: "go build ./...", srcLine: 1}},
			Event{Kind: KindCommand, Command: "go test ./...", srcLine: 2},
			false,
		},
		{
			"different flags are a different command",
			[]Event{{Kind: KindCommand, Command: "go test -run X ./...", srcLine: 1}},
			Event{Kind: KindCommand, Command: "go test ./...", srcLine: 2},
			false,
		},
		{
			"a non-command event with the same text does not count",
			[]Event{{Kind: KindToolCall, Command: "go test ./...", srcLine: 1}},
			Event{Kind: KindCommand, Command: "go test ./...", srcLine: 2},
			false,
		},
		{
			"a failed earlier run still counts",
			[]Event{{Kind: KindCommand, Command: "go test ./...", IsError: true, srcLine: 1}},
			Event{Kind: KindCommand, Command: "go test ./...", srcLine: 2},
			true,
		},
		{
			"empty command is never a retry",
			[]Event{{Kind: KindCommand, Command: "", srcLine: 1}},
			Event{Kind: KindCommand, Command: "   ", srcLine: 2},
			false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := &Digest{Timeline: slices.Clone(c.timeline)}
			e := c.event
			applyRunState(d, &e, e.Output)
			if got := slices.Contains(e.Categories, "command.retried"); got != c.want {
				t.Errorf("command.retried = %v, want %v (categories %v)", got, c.want, e.Categories)
			}
		})
	}
}

// codex appends a command that started but never completed at the very end
// of d.Timeline only once the whole stream has been read
// (codexParseState.finalize) — after every command that did complete, even
// one that started later. A scan by slice position would then credit
// command.retried to the wrong side of the pair: the command that started
// first (but never finished) instead of the genuine repeat that actually
// completed. srcLine — set to each command's start line regardless of when
// it was appended — must decide this instead, so a is never credited as the
// retry of a command (b) that in source order actually ran after it. (b
// itself is classified before a is ever appended, so it cannot retroactively
// gain the credit either — a missed credit, not a false one, which is the
// acceptable side of the "prove it or credit nothing" rule.)
func TestApplyRunStateCommandRetriedUsesSourceOrderNotAppendOrder(t *testing.T) {
	// "go test ./..." started at line 1 (a) and line 3 (b); b completed and
	// was appended to the timeline first (simulating consume()). a never
	// completed and is appended after b (simulating finalize()), even though
	// it started earlier.
	b := Event{Kind: KindCommand, Command: "go test ./...", srcLine: 3}
	d := &Digest{Timeline: []Event{b}}

	a := Event{Kind: KindCommand, Command: "go test ./...", srcLine: 1}
	d.Timeline = append(d.Timeline, a)
	applyRunState(d, &d.Timeline[1], "")
	if slices.Contains(d.Timeline[1].Categories, "command.retried") {
		t.Errorf("a (started first, never completed) wrongly credited as the retry of b: %v", d.Timeline[1].Categories)
	}
}

// The same reordering happens through the real codex parser: item.started
// for "a" then "b" (both "go test ./..."), then only "b" completes. finalize
// appends "a" (started but never completed) after "b" (already appended by
// consume), even though "a" started first. "a" must not come out of the real
// stream credited command.retried.
func TestCodexCommandRetriedUsesStartOrderNotAppendOrder(t *testing.T) {
	raw := strings.Join([]string{
		`{"type":"thread.started","thread_id":"t-1"}`,
		`{"type":"turn.started"}`,
		`{"type":"item.started","item":{"id":"a","type":"command_execution","command":"go test ./..."}}`,
		`{"type":"item.started","item":{"id":"b","type":"command_execution","command":"go test ./..."}}`,
		`{"type":"item.completed","item":{"id":"b","type":"command_execution","command":"go test ./...","status":"completed","exit_code":0,"aggregated_output":"ok"}}`,
	}, "\n") + "\n"
	d, _ := parseCodex(strings.NewReader(raw), newWorkspace("/work/repo"))
	var incomplete *Event
	for i := range d.Timeline {
		if d.Timeline[i].Kind == KindCommand && d.Timeline[i].Status == "incomplete" {
			incomplete = &d.Timeline[i]
		}
	}
	if incomplete == nil {
		t.Fatalf("no incomplete command event in timeline: %+v", d.Timeline)
	}
	if slices.Contains(incomplete.Categories, "command.retried") {
		t.Errorf("the command that started first but never completed was wrongly credited command.retried: %v", incomplete.Categories)
	}
}

// claude classifies an event that is already in the timeline. It must not
// match itself and report the first run of a command as a retry.
func TestApplyRunStateDoesNotMatchTheEventItself(t *testing.T) {
	d := &Digest{Timeline: []Event{
		{Kind: KindMessage, Text: "starting", srcLine: 1},
		{Kind: KindCommand, Command: "go test ./...", srcLine: 2},
		{Kind: KindCommand, Command: "go test ./...", srcLine: 3},
	}}
	applyRunState(d, &d.Timeline[1], d.Timeline[1].Output)
	if slices.Contains(d.Timeline[1].Categories, "command.retried") {
		t.Errorf("first run credited as a retry: %v", d.Timeline[1].Categories)
	}
	applyRunState(d, &d.Timeline[2], d.Timeline[2].Output)
	if !slices.Contains(d.Timeline[2].Categories, "command.retried") {
		t.Errorf("second run not credited as a retry: %v", d.Timeline[2].Categories)
	}
}

// sandbox.denied needs both halves of its proof: a failure and one of the
// listed markers in the output. Neither half alone is enough.
func TestApplyRunStateSandboxDenied(t *testing.T) {
	cases := []struct {
		name    string
		isError bool
		output  string
		want    bool
	}{
		{"operation not permitted", true, "chmod: /etc/hosts: Operation not permitted\n", true},
		{"permission denied", true, "bash: ./run.sh: Permission denied", true},
		{"read-only file system", true, "touch: /x: Read-only file system", true},
		{"eacces", true, "Error: EACCES: permission denied, open '/x'", true},
		{"sandbox", true, "command blocked by seatbelt sandbox policy", true},
		{"marker is matched case-insensitively", true, "OPERATION NOT PERMITTED", true},
		{"failed with no marker", true, "exit status 1: undefined: foo", false},
		{"failed with empty output", true, "", false},
		{"succeeded despite a marker in the output", false, "grep found: permission denied", false},
		{"succeeded with clean output", false, "ok\n", false},
		{"a near-miss phrase is not a marker", true, "access denied by the remote server", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := Event{Kind: KindCommand, Command: "chmod 755 x", IsError: c.isError, Output: c.output}
			applyRunState(&Digest{}, &e, e.Output)
			if got := slices.Contains(e.Categories, "sandbox.denied"); got != c.want {
				t.Errorf("sandbox.denied = %v, want %v (categories %v)", got, c.want, e.Categories)
			}
		})
	}
}

func TestApplyRunStateIgnoresNonCommandEvents(t *testing.T) {
	d := &Digest{Timeline: []Event{{Kind: KindCommand, Command: "ls"}}}
	e := Event{Kind: KindFileEdit, Command: "ls", IsError: true, Output: "permission denied"}
	applyRunState(d, &e, e.Output)
	if e.Categories != nil {
		t.Errorf("non-command event credited: %v", e.Categories)
	}
}

// The run-state categories join the ones the classifiers already credited,
// sorted and without a duplicate.
func TestApplyRunStateMergesSortedAndDeduped(t *testing.T) {
	d := &Digest{Timeline: []Event{{Kind: KindCommand, Command: "rm -rf build", srcLine: 1}}}
	e := Event{
		Kind:       KindCommand,
		Command:    "rm -rf build",
		IsError:    true,
		Output:     "rm: build: Operation not permitted",
		Categories: []string{"fs.delete", "sandbox.denied"},
		srcLine:    2,
	}
	applyRunState(d, &e, e.Output)
	want := []string{"command.retried", "fs.delete", "sandbox.denied"}
	if !reflect.DeepEqual(e.Categories, want) {
		t.Errorf("categories = %v, want %v", e.Categories, want)
	}
}

func TestApplyRunStateLeavesCleanCommandsAlone(t *testing.T) {
	e := Event{Kind: KindCommand, Command: "go test ./...", Output: "ok\n"}
	applyRunState(&Digest{}, &e, e.Output)
	if e.Categories != nil {
		t.Errorf("categories = %v, want none", e.Categories)
	}
}
