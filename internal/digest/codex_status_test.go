package digest

import (
	"strings"
	"testing"
)

func TestCodexItemFailed(t *testing.T) {
	code := func(n int) *int { return &n }
	cases := []struct {
		name string
		item CodexItem
		want bool
	}{
		{"completed", CodexItem{Status: "completed"}, false},
		{"success", CodexItem{Status: "success"}, false},
		{"empty status", CodexItem{Status: ""}, false},
		{"failed", CodexItem{Status: "failed"}, true},
		{"cancelled", CodexItem{Status: "cancelled"}, true},
		{"completed but nonzero exit", CodexItem{Status: "completed", ExitCode: code(1)}, true},
		{"empty status zero exit", CodexItem{Status: "", ExitCode: code(0)}, false},
	}
	for _, c := range cases {
		if got := c.item.Failed(); got != c.want {
			t.Errorf("%s: Failed() = %v, want %v", c.name, got, c.want)
		}
	}
}

// An item.started with no matching item.completed has not proven it ran to
// completion, let alone succeeded: Failed() treats an empty status as "not
// failed", so without an explicit completion gate the finalize path would
// credit a fs.delete (and the file.deleted mutation that backs it) for a
// command that is not known to have run at all.
func TestCodexIncompleteCommandCreditsNoStateChange(t *testing.T) {
	raw := strings.Join([]string{
		`{"type":"thread.started","thread_id":"t-1"}`,
		`{"type":"turn.started"}`,
		`{"type":"item.started","item":{"id":"c1","type":"command_execution","command":"rm src/old.go"}}`,
	}, "\n") + "\n"
	d, _ := parseCodex(strings.NewReader(raw), newWorkspace("/work/repo"))
	var cmd *Event
	for i := range d.Timeline {
		if d.Timeline[i].Kind == KindCommand {
			cmd = &d.Timeline[i]
		}
	}
	if cmd == nil {
		t.Fatal("no command event in timeline")
	}
	if cmd.Status != "incomplete" {
		t.Fatalf("status = %q, want incomplete", cmd.Status)
	}
	if len(cmd.Categories) != 0 {
		t.Errorf("categories = %v, want none for a command that never reported completion", cmd.Categories)
	}
	if len(cmd.ShellMutations) != 0 {
		t.Errorf("shell mutations = %+v, want none", cmd.ShellMutations)
	}
}

func TestCodexFileChangeRejectsTraversal(t *testing.T) {
	raw := strings.Join([]string{
		`{"type":"thread.started","thread_id":"t-1"}`,
		`{"type":"turn.started"}`,
		`{"type":"item.completed","item":{"id":"i1","type":"file_change","status":"completed","changes":[{"path":"../outside.go","kind":"update"}]}}`,
		`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`,
	}, "\n") + "\n"
	d, err := parseCodex(strings.NewReader(raw), newWorkspace("/work/repo"))
	if err != nil {
		t.Fatal(err)
	}
	if d.Metrics.Edits != 1 {
		t.Fatalf("edits = %d, want 1", d.Metrics.Edits)
	}
	if files := assembleFiles(d.Timeline); len(files) != 0 {
		t.Fatalf("traversal path leaked into files summary: %+v", files)
	}
}
