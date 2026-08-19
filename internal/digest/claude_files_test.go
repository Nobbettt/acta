package digest

import (
	"fmt"
	"strings"
	"testing"
)

func hasFile(files []FileTouch, path string, edited bool) bool {
	for _, f := range files {
		if f.Path == path && f.Edited == edited {
			return true
		}
	}
	return false
}

func claudeSuccessfulStream(lines ...string) string {
	lines = append(lines, `{"type":"result","subtype":"success","session_id":"test-session","is_error":false}`)
	return strings.Join(lines, "\n") + "\n"
}

// NotebookEdit reports the file under notebook_path, not file_path.
func TestClaudeNotebookEditCredited(t *testing.T) {
	line := `{"type":"assistant","message":{"id":"m1","content":[{"type":"tool_use","id":"t1","name":"NotebookEdit","input":{"notebook_path":"analysis.ipynb"}}]}}`
	d, err := parseClaude(strings.NewReader(claudeSuccessfulStream(line)), newWorkspace(""))
	if err != nil {
		t.Fatal(err)
	}
	if d.Metrics.Edits != 1 {
		t.Fatalf("edits = %d, want 1", d.Metrics.Edits)
	}
	files := assembleFiles(d.Timeline)
	if !hasFile(files, "analysis.ipynb", true) {
		t.Fatalf("edited notebook missing from files summary: %+v", files)
	}
}

// A tool path outside the recorded workspace must not leak into the files
// summary as an absolute key; the command-inference path already drops it.
func TestClaudeEditOutsideWorkspaceNotKeyedAbsolute(t *testing.T) {
	ws := newWorkspace("/work/repo")
	line := `{"type":"assistant","message":{"id":"m1","content":[{"type":"tool_use","id":"t1","name":"Edit","input":{"file_path":"/etc/passwd"}}]}}`
	d, err := parseClaude(strings.NewReader(claudeSuccessfulStream(line)), ws)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range assembleFiles(d.Timeline) {
		if strings.HasPrefix(f.Path, "/") {
			t.Fatalf("absolute path leaked into files summary: %q", f.Path)
		}
	}
}

func TestClaudeDirectToolPathsRejectTraversal(t *testing.T) {
	ws := newWorkspace("/work/repo")
	lines := []string{
		`{"type":"assistant","message":{"id":"m1","content":[{"type":"tool_use","id":"edit1","name":"Edit","input":{"file_path":"../outside.go"}}]}}`,
		`{"type":"assistant","message":{"id":"m2","content":[{"type":"tool_use","id":"read1","name":"Read","input":{"file_path":"../outside.go"}}]}}`,
		`{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"read1","content":"1→package outside"}]}}`,
	}
	d, err := parseClaude(strings.NewReader(claudeSuccessfulStream(lines...)), ws)
	if err != nil {
		t.Fatal(err)
	}
	if files := assembleFiles(d.Timeline); len(files) != 0 {
		t.Fatalf("traversal paths leaked into files summary: %+v", files)
	}
}

func TestClaudeReadPathSurvivesCappedInput(t *testing.T) {
	huge := strings.Repeat("x", MaxEventInputChars)
	lines := []string{
		fmt.Sprintf(`{"type":"assistant","message":{"id":"m1","content":[{"type":"tool_use","id":"read1","name":"Read","input":{"file_path":"main.go","note":"%s"}}]}}`, huge),
		`{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"read1","content":"1→package main"}]}}`,
	}
	d, err := parseClaude(strings.NewReader(claudeSuccessfulStream(lines...)), newWorkspace(""))
	if err != nil {
		t.Fatal(err)
	}
	files := assembleFiles(d.Timeline)
	if len(files) != 1 || files[0].Path != "main.go" || !files[0].Read {
		t.Fatalf("capped Read input lost file attribution: %+v", files)
	}
	if !strings.Contains(string(d.Timeline[0].Input), "_truncated_bytes") {
		t.Fatal("test setup failed: input was not capped")
	}
}
