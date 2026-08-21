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
