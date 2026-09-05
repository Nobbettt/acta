package digest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func writeObservedFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The point of observing is that a command which changed nothing produces no
// mutation, however delete-shaped its text was.
func TestDiffPathStatesReportsOnlyRealChanges(t *testing.T) {
	root := t.TempDir()
	ws := newWorkspace(root)
	writeObservedFile(t, root, "kept.txt", "same")
	writeObservedFile(t, root, "removed.txt", "gone soon")
	writeObservedFile(t, root, "grown.txt", "small")

	candidates := []string{"kept.txt", "removed.txt", "grown.txt", "created.txt"}
	before := observePathStates(ws, candidates)

	if err := os.Remove(filepath.Join(root, "removed.txt")); err != nil {
		t.Fatal(err)
	}
	writeObservedFile(t, root, "created.txt", "new")
	writeObservedFile(t, root, "grown.txt", "much longer than before")

	after := observePathStates(ws, candidates)
	got := diffPathStates(before, after)
	want := []observedEffect{
		{path: "created.txt", kind: "create"},
		{path: "grown.txt", kind: "modify"},
		{path: "removed.txt", kind: "delete"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("effects = %+v, want %+v", got, want)
	}
}

// A permission change leaves size and content alone, so mode has to count or a
// real chmod would look like it did nothing.
func TestDiffPathStatesNoticesAModeChange(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows has no POSIX permission bits: os.Chmod there only toggles the
		// read-only attribute, so the mode this fixture sets never lands and it
		// would be asserting the local filesystem rather than the comparison.
		// pathStateChanged itself is platform-independent and still covered by
		// the size and existence cases above.
		t.Skip("POSIX permission bits are not settable on this platform")
	}
	root := t.TempDir()
	ws := newWorkspace(root)
	writeObservedFile(t, root, "script.sh", "#!/bin/sh\n")

	before := observePathStates(ws, []string{"script.sh"})
	if err := os.Chmod(filepath.Join(root, "script.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	after := observePathStates(ws, []string{"script.sh"})

	want := []observedEffect{{path: "script.sh", kind: "modify"}}
	if got := diffPathStates(before, after); !reflect.DeepEqual(got, want) {
		t.Fatalf("effects = %+v, want %+v", got, want)
	}
}

// The whole point: a command whose text names a delete, run against a file that
// is still there afterwards, must publish nothing.
func TestDiffPathStatesReportsNothingWhenTheCommandChangedNothing(t *testing.T) {
	root := t.TempDir()
	ws := newWorkspace(root)
	writeObservedFile(t, root, "victim.txt", "still here")

	candidates := []string{"victim.txt"}
	before := observePathStates(ws, candidates)
	after := observePathStates(ws, candidates)
	if got := diffPathStates(before, after); len(got) != 0 {
		t.Fatalf("effects = %+v, want none", got)
	}
}

func TestObservePathStatesSkipsPathsOutsideTheWorkspace(t *testing.T) {
	root := t.TempDir()
	ws := newWorkspace(root)
	writeObservedFile(t, root, "inside.txt", "x")

	states := observePathStates(ws, []string{"inside.txt", "../outside.txt", "/etc/hosts"})
	if _, ok := states["inside.txt"]; !ok {
		t.Fatalf("states = %+v, want inside.txt observed", states)
	}
	if len(states) != 1 {
		t.Fatalf("states = %+v, want only the in-workspace path", states)
	}
}

func TestObservePathStatesBoundsTheNumberOfStats(t *testing.T) {
	root := t.TempDir()
	ws := newWorkspace(root)
	candidates := make([]string, 0, maxObservedCandidatePaths*2)
	for i := 0; i < maxObservedCandidatePaths*2; i++ {
		candidates = append(candidates, "f"+string(rune('a'+i%26))+string(rune('a'+i/26))+".txt")
	}
	if states := observePathStates(ws, candidates); len(states) > maxObservedCandidatePaths {
		t.Fatalf("observed %d paths, want at most %d", len(states), maxObservedCandidatePaths)
	}
}

// Ordering cannot come from map iteration: a digest is compared byte for byte
// against a re-digest of the same bundle.
func TestDiffPathStatesOrdersDeterministically(t *testing.T) {
	before := map[string]pathState{}
	after := map[string]pathState{}
	for _, name := range []string{"z.txt", "a.txt", "m.txt", "b.txt"} {
		before[name] = pathState{exists: true, size: 1, modTime: time.Unix(0, 0)}
		after[name] = pathState{}
	}
	first := diffPathStates(before, after)
	for i := 0; i < 20; i++ {
		if got := diffPathStates(before, after); !reflect.DeepEqual(got, first) {
			t.Fatalf("ordering varied between runs: %+v vs %+v", got, first)
		}
	}
	want := []string{"a.txt", "b.txt", "m.txt", "z.txt"}
	for i, effect := range first {
		if effect.path != want[i] {
			t.Fatalf("effects = %+v, want sorted %v", first, want)
		}
	}
}

func TestCommandObservationCandidates(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    []string
	}{
		{"rm victim.txt", []string{"victim.txt"}},
		{"mv old.txt new.txt", []string{"old.txt", "new.txt"}},
		{"chmod -c 0644 f.txt", []string{"0644", "f.txt"}},
		{"echo hi > out.txt", []string{"hi", "out.txt"}},
		// An expansion names something only the run knows, so watching its
		// literal text would fingerprint the wrong path.
		{"rm ${TARGET}/x.txt", nil},
		{"rm $(date).txt", nil},
		// A heredoc delimiter and a here-string are data, never paths.
		{"head <<< .env", nil},
		{"cat <<EOF\nbody\nEOF\n", nil},
		// A descriptor duplication names an fd, not a file.
		{"chmod -c 0644 f.txt 2>&1", []string{"0644", "f.txt"}},
	} {
		t.Run(tc.command, func(t *testing.T) {
			got := commandObservationCandidates(tc.command)
			if len(got) != len(tc.want) {
				t.Fatalf("candidates = %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("candidates = %q, want %q", got, tc.want)
				}
			}
		})
	}
}

// End to end over the real filesystem: the command says delete, and only the
// file that actually disappeared is reported.
func TestObservedEffectsFollowTheFilesystemNotTheCommandText(t *testing.T) {
	root := t.TempDir()
	ws := newWorkspace(root)
	writeObservedFile(t, root, "gone.txt", "x")
	writeObservedFile(t, root, "stays.txt", "x")

	command := "rm gone.txt stays.txt"
	candidates := commandObservationCandidates(command)
	before := observePathStates(ws, candidates)
	if err := os.Remove(filepath.Join(root, "gone.txt")); err != nil {
		t.Fatal(err)
	}
	after := observePathStates(ws, candidates)

	want := []observedEffect{{path: "gone.txt", kind: "delete"}}
	if got := diffPathStates(before, after); !reflect.DeepEqual(got, want) {
		t.Fatalf("effects = %+v, want %+v", got, want)
	}
}

// The live Claude path must record what the command actually did, and a
// re-digest of the same bundle must not be asked to look at the filesystem
// again — it records the observation instead of repeating it.
func TestClaudeStreamRecordsObservedShellEffects(t *testing.T) {
	root := t.TempDir()
	writeObservedFile(t, root, "victim.txt", "x")

	state := &claudeParseState{d: &Digest{}, ws: newWorkspace(root), pending: map[string]int{}, usageSeen: map[string]bool{}}
	state.consumeAssistantContent(
		&ClaudeContent{Type: "tool_use", ID: "t1", Name: "Bash", Input: json.RawMessage(`{"command":"rm victim.txt"}`)},
		&ClaudeItem{Message: &ClaudeMessage{ID: "m1"}}, 1, time.Time{})
	if len(state.d.Timeline) != 1 {
		t.Fatalf("timeline = %d, want 1", len(state.d.Timeline))
	}
	if err := os.Remove(filepath.Join(root, "victim.txt")); err != nil {
		t.Fatal(err)
	}
	state.consumeToolResult(
		&ClaudeContent{ToolUseID: "t1", Content: json.RawMessage(`""`)},
		json.RawMessage(`{"exit_code":0}`), 2, time.Time{})

	want := []ObservedEffect{{Path: "victim.txt", Kind: "delete"}}
	if got := state.d.Timeline[0].ObservedEffects; !reflect.DeepEqual(got, want) {
		t.Fatalf("observed effects = %+v, want %+v", got, want)
	}
}

// And when the command changed nothing, nothing is recorded, however
// delete-shaped the text was.
func TestClaudeStreamRecordsNoEffectWhenNothingChanged(t *testing.T) {
	root := t.TempDir()
	writeObservedFile(t, root, "victim.txt", "x")

	state := &claudeParseState{d: &Digest{}, ws: newWorkspace(root), pending: map[string]int{}, usageSeen: map[string]bool{}}
	state.consumeAssistantContent(
		&ClaudeContent{Type: "tool_use", ID: "t1", Name: "Bash", Input: json.RawMessage(`{"command":"rm victim.txt"}`)},
		&ClaudeItem{Message: &ClaudeMessage{ID: "m1"}}, 1, time.Time{})
	state.consumeToolResult(
		&ClaudeContent{ToolUseID: "t1", Content: json.RawMessage(`""`)},
		json.RawMessage(`{"exit_code":0}`), 2, time.Time{})

	if got := state.d.Timeline[0].ObservedEffects; len(got) != 0 {
		t.Fatalf("observed effects = %+v, want none", got)
	}
}

// The Codex live path records the same evidence, so classification does not
// depend on which agent produced the run.
func TestCodexStreamRecordsObservedShellEffects(t *testing.T) {
	root := t.TempDir()
	writeObservedFile(t, root, "victim.txt", "x")

	st := newCodexState(newWorkspace(root))
	st.consume(&CodexEvent{Type: "thread.started", ThreadID: "t"}, 1, time.Time{})
	st.consume(&CodexEvent{Type: "turn.started"}, 2, time.Time{})
	st.consume(&CodexEvent{Type: "item.started", Item: &CodexItem{
		ID: "c1", Type: "command_execution", Command: "rm victim.txt",
	}}, 3, time.Time{})
	if err := os.Remove(filepath.Join(root, "victim.txt")); err != nil {
		t.Fatal(err)
	}
	exit := 0
	st.consume(&CodexEvent{Type: "item.completed", Item: &CodexItem{
		ID: "c1", Type: "command_execution", Command: "rm victim.txt",
		Status: "completed", ExitCode: &exit,
	}}, 4, time.Time{})

	var command *Event
	for i := range st.d.Timeline {
		if st.d.Timeline[i].Kind == KindCommand {
			command = &st.d.Timeline[i]
		}
	}
	if command == nil {
		t.Fatalf("timeline has no command event: %+v", st.d.Timeline)
	}
	want := []ObservedEffect{{Path: "victim.txt", Kind: "delete"}}
	if !reflect.DeepEqual(command.ObservedEffects, want) {
		t.Fatalf("observed effects = %+v, want %+v", command.ObservedEffects, want)
	}
}

// The whole point of recording the observation rather than recomputing it: a
// re-digest replays the same evidence, even though by then the workspace has
// moved on and the file is long gone.
func TestObservedEffectsSurviveARedigest(t *testing.T) {
	dir := t.TempDir()
	writeObservedFile(t, dir, "victim.txt", "x")
	lines := []string{
		`{"type":"thread.started","thread_id":"thread-observed"}`,
		`{"type":"turn.started"}`,
		`{"type":"item.started","item":{"id":"c1","type":"command_execution","command":"rm victim.txt","status":"in_progress"}}`,
		`{"type":"item.completed","item":{"id":"c1","type":"command_execution","command":"rm victim.txt","status":"completed","exit_code":0,"aggregated_output":""}}`,
		`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`,
	}
	if err := os.WriteFile(filepath.Join(dir, "codex-events.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := validTestRecord(dir, "codex-events.jsonl")
	payload, _ := json.Marshal(rec)
	if err := os.WriteFile(filepath.Join(dir, "run.json"), payload, 0o644); err != nil {
		t.Fatal(err)
	}

	sd, err := NewStreamDigesterWithOptions("codex", dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 5, 9, 0, 0, 0, time.UTC)
	for i, line := range lines {
		// The command really runs between its start and completion lines, which
		// is the only window where the before-state exists.
		if i == 3 {
			if err := os.Remove(filepath.Join(dir, "victim.txt")); err != nil {
				t.Fatal(err)
			}
		}
		sd.Line([]byte(line), base.Add(time.Duration(i)*time.Second))
	}
	live := sd.Finalize(&rec, dir)

	want := []ObservedEffect{{Path: "victim.txt", Kind: "delete"}}
	if got := commandObservedEffects(t, live); !reflect.DeepEqual(got, want) {
		t.Fatalf("live observed effects = %+v, want %+v", got, want)
	}

	// Persist the live digest, exactly as a run does, then replay the stream.
	livePayload, err := json.Marshal(live)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "digest.json"), livePayload, 0o644); err != nil {
		t.Fatal(err)
	}
	redigested, err := FromRunDir(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := commandObservedEffects(t, redigested); !reflect.DeepEqual(got, want) {
		t.Fatalf("re-digest observed effects = %+v, want %+v", got, want)
	}
}

func commandObservedEffects(t *testing.T, d *Digest) []ObservedEffect {
	t.Helper()
	for _, event := range d.Timeline {
		if event.Kind == KindCommand {
			return event.ObservedEffects
		}
	}
	t.Fatalf("digest has no command event: %+v", d.Timeline)
	return nil
}

// pathStateChanged is what decides a modify, and it is platform-independent
// even where the filesystem fixture above cannot set POSIX permission bits.
func TestPathStateChanged(t *testing.T) {
	base := pathState{exists: true, size: 10, modTime: time.Unix(1000, 0), mode: 0o644}
	for _, tc := range []struct {
		name string
		next pathState
		want bool
	}{
		{name: "identical", next: base, want: false},
		{name: "size", next: pathState{exists: true, size: 11, modTime: base.modTime, mode: base.mode}, want: true},
		{name: "mode", next: pathState{exists: true, size: 10, modTime: base.modTime, mode: 0o755}, want: true},
		{name: "modification time", next: pathState{exists: true, size: 10, modTime: time.Unix(2000, 0), mode: base.mode}, want: true},
		{name: "file became a directory", next: pathState{exists: true, size: 10, modTime: base.modTime, mode: base.mode, isDir: true}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pathStateChanged(base, tc.next); got != tc.want {
				t.Fatalf("pathStateChanged = %v, want %v", got, tc.want)
			}
		})
	}
}

// The filesystem outranks the command text, on both agent paths, and only for
// the facts it can actually speak to.
func TestApplyObservedEffectsSuppressesOnlyContradictedChanges(t *testing.T) {
	root := t.TempDir()
	ws := newWorkspace(root)
	writeObservedFile(t, root, "victim.txt", "x")

	t.Run("a change the disk did not show loses its value but keeps its category", func(t *testing.T) {
		e := &Event{
			Kind: KindCommand, Command: "rm victim.txt",
			Categories:        []string{"fs.delete"},
			Targets:           []CommandTarget{{Kind: "path", Value: "victim.txt"}},
			ShellMutations:    []ShellMutation{{Kind: "delete", Path: "victim.txt"}},
			ObservationStatus: observationStatusObserved,
		}
		applyObservedEffects(e, ws)
		if len(e.Targets) != 0 || len(e.ShellMutations) != 0 {
			t.Fatalf("targets=%+v mutations=%+v, want both withheld", e.Targets, e.ShellMutations)
		}
		if !reflect.DeepEqual(e.Categories, []string{"fs.delete"}) {
			t.Fatalf("categories = %v, want fs.delete kept", e.Categories)
		}
	})

	t.Run("a change the disk confirmed is published", func(t *testing.T) {
		e := &Event{
			Kind: KindCommand, Command: "rm victim.txt",
			Categories:        []string{"fs.delete"},
			Targets:           []CommandTarget{{Kind: "path", Value: "victim.txt"}},
			ShellMutations:    []ShellMutation{{Kind: "delete", Path: "victim.txt"}},
			ObservedEffects:   []ObservedEffect{{Path: "victim.txt", Kind: "delete"}},
			ObservationStatus: observationStatusObserved,
		}
		applyObservedEffects(e, ws)
		if len(e.Targets) != 1 || len(e.ShellMutations) != 1 {
			t.Fatalf("targets=%+v mutations=%+v, want both kept", e.Targets, e.ShellMutations)
		}
	})

	// Absence of evidence is not evidence of absence: a bundle captured before
	// observation existed must classify exactly as it did before.
	t.Run("no observation leaves the classification alone", func(t *testing.T) {
		e := &Event{
			Kind: KindCommand, Command: "rm victim.txt",
			Categories:     []string{"fs.delete"},
			Targets:        []CommandTarget{{Kind: "path", Value: "victim.txt"}},
			ShellMutations: []ShellMutation{{Kind: "delete", Path: "victim.txt"}},
		}
		applyObservedEffects(e, ws)
		if len(e.Targets) != 1 || len(e.ShellMutations) != 1 {
			t.Fatalf("targets=%+v mutations=%+v, want untouched", e.Targets, e.ShellMutations)
		}
	})

	// A path nobody looked at cannot be contradicted, so a derived destination
	// keeps whatever classification produced.
	t.Run("an unwatched path is left alone", func(t *testing.T) {
		e := &Event{
			Kind: KindCommand, Command: "cp victim.txt dir/",
			Categories:        []string{"fs.create"},
			Targets:           []CommandTarget{{Kind: "path", Value: "dir/victim.txt"}},
			ObservationStatus: observationStatusObserved,
		}
		applyObservedEffects(e, ws)
		if len(e.Targets) != 1 {
			t.Fatalf("targets = %+v, want the derived destination kept", e.Targets)
		}
	})

	// A read alters nothing, so an unchanged file is no argument against it.
	t.Run("a read target is never suppressed", func(t *testing.T) {
		e := &Event{
			Kind: KindCommand, Command: "cat victim.txt",
			Categories:        []string{"instructions.read"},
			Targets:           []CommandTarget{{Kind: "path", Value: "victim.txt"}},
			ObservationStatus: observationStatusObserved,
		}
		applyObservedEffects(e, ws)
		if len(e.Targets) != 1 {
			t.Fatalf("targets = %+v, want the read target kept", e.Targets)
		}
	})
}
