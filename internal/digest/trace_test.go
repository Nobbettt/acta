package digest

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func testWorkspace() *workspace {
	return newWorkspace("/repo")
}

func TestInferReadSpan(t *testing.T) {
	cases := []struct {
		name string
		text string
		want Span
		ok   bool
	}{
		{"arrow markers", "  10→foo\n  11→bar\n  20→baz", Span{10, 20}, true},
		{"numbered from one", "1  package main\n2  import x\n3  func main()", Span{1, 3}, true},
		{"tab separated with empty line", "1\tpackage main\n2\t\n3\timport \"fmt\"\n4\t\n5\tfunc main() {\n6\t}\n7\t", Span{1, 6}, true},
		{"single line one", "1  only line", Span{1, 1}, true},
		{"single line not one", "42  something", Span{}, false},
		{"timestamps rejected", "2024  events\n2025  more\n2030  gap", Span{}, false},
		{"table rejected", "10  a\n20  b\n30  c", Span{}, false},
		{"no numbering", "plain output\nno numbers", Span{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := inferReadSpan(c.text)
			if ok != c.ok || (ok && got != c.want) {
				t.Errorf("inferReadSpan(%q) = %v,%v want %v,%v", c.text, got, ok, c.want, c.ok)
			}
		})
	}
}

func TestUnwrapShell(t *testing.T) {
	cases := []struct{ in, want string }{
		{`/bin/zsh -lc "sed -n '1,50p' foo.py"`, `sed -n '1,50p' foo.py`},
		{`bash -lc 'ls -la'`, `ls -la`},
		{`ls -la`, `ls -la`},
		{`sed -n '1,50p' foo.py`, `sed -n '1,50p' foo.py`},
		// tokens[1] == "-lc" but tokens[0] is not a shell: must NOT unwrap.
		{`ls -lc src`, `ls -lc src`},
		{`git -lc foo`, `git -lc foo`},
	}
	for _, c := range cases {
		if got := unwrapShell(c.in); got != c.want {
			t.Errorf("unwrapShell(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A quote-blind segment split can leave an unbalanced-quote fragment
// (`sys.exit(0)"`); it must not be guessed into a phantom read via
// findPathLikeToken.
func TestRetrievalFromCommandNoPhantomFromQuotedCode(t *testing.T) {
	ws := newWorkspace("")
	cmd := `cat notes.txt && python -c "import sys; sys.exit(0)"`
	got := retrievalFromCommand(cmd, "file contents here\n", ws)
	if got == nil {
		t.Fatal("expected notes.txt to be credited")
		return
	}
	sawNotes := false
	for _, f := range got.files {
		if f == "notes.txt" {
			sawNotes = true
		}
		if strings.Contains(f, "sys.exit") {
			t.Fatalf("phantom file credited from quoted code: %v", got.files)
		}
	}
	if !sawNotes {
		t.Fatalf("notes.txt missing from %v", got.files)
	}
}

func TestCommandHasWord(t *testing.T) {
	cases := []struct {
		command, word string
		want          bool
	}{
		{"cat foo.txt | grep bar", "grep", true},
		{"grep x", "grep", true},
		{"egrep foo", "grep", false}, // substring, not a whole token
		{"a grep b", "grep", true},   // second call hits the cache
		{"cat a.txt", "sed", false},
	}
	for _, c := range cases {
		if got := commandHasWord(c.command, c.word); got != c.want {
			t.Errorf("commandHasWord(%q, %q) = %v, want %v", c.command, c.word, got, c.want)
		}
	}
}

func TestShellTokens(t *testing.T) {
	got := shellTokens(`grep -n "some pattern" 'my file.py' plain`)
	want := []string{"grep", "-n", "some pattern", "my file.py", "plain"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("shellTokens = %#v, want %#v", got, want)
	}
	if shellTokens(`echo "unterminated`) != nil {
		t.Error("unterminated quote should yield nil")
	}
}

func TestShellTokensRemovesContinuationsAndSeparatesOperators(t *testing.T) {
	cases := []struct {
		command string
		want    []string
	}{
		{"rm foo\\\nbar", []string{"rm", "foobar"}},
		{"rm old.txt>/dev/null", []string{"rm", "old.txt", ">", "/dev/null"}},
		{"curl https://example.com|cat", []string{"curl", "https://example.com", "|", "cat"}},
		{`printf '%s' 'a|b'`, []string{"printf", "%s", "a|b"}},
		{`printf a\|b`, []string{"printf", "a|b"}},
		{"rm old.txt 2>&1", []string{"rm", "old.txt", "2>&", "1"}},
	}
	for _, c := range cases {
		if got := shellTokens(c.command); !reflect.DeepEqual(got, c.want) {
			t.Errorf("shellTokens(%q) = %#v, want %#v", c.command, got, c.want)
		}
	}
}

func TestRetrievalFromCommand(t *testing.T) {
	ws := testWorkspace()
	output := "some output\nlines here"
	numbered := "   250\tdef foo():\n   251\t    pass"

	cases := []struct {
		name      string
		command   string
		output    string
		wantFiles []string
		wantSpans map[string][]Span
	}{
		{
			"sed range",
			`sed -n '120,180p' pkg/mod.py`,
			output,
			[]string{"pkg/mod.py"},
			map[string][]Span{"pkg/mod.py": {{120, 180}}},
		},
		{
			"sed range wrapped in -lc",
			`/bin/zsh -lc "sed -n '1,380p' sympy/concrete/products.py"`,
			output,
			[]string{"sympy/concrete/products.py"},
			map[string][]Span{"sympy/concrete/products.py": {{1, 380}}},
		},
		{
			"head count",
			`head -n 50 main.go`,
			output,
			[]string{"main.go"},
			map[string][]Span{"main.go": {{1, 50}}},
		},
		{
			"pipeline status cannot prove nl read the file",
			`nl -ba pkg/mod.py | sed -n '250,310p'`,
			numbered,
			nil,
			nil,
		},
		{
			"program output piped to sed credits nothing",
			`python script.py | sed -n '1,50p'`,
			output,
			nil,
			nil,
		},
		{
			"cat file",
			`cat pkg/mod.py`,
			output,
			[]string{"pkg/mod.py"},
			nil,
		},
		{
			"named extensionless instruction file",
			`cat CONTRIBUTING`,
			output,
			[]string{"CONTRIBUTING"},
			nil,
		},
		{
			"arbitrary extensionless file",
			`cat NOTES`,
			output,
			nil,
			nil,
		},
		{
			"echoed read command is only text",
			`echo cat README.md`,
			"cat README.md\n",
			nil,
			nil,
		},
		{
			"single-file grep",
			`grep -n "pattern" pkg/mod.py`,
			output,
			[]string{"pkg/mod.py"},
			nil,
		},
		{
			"filename-shaped search pattern is not a file",
			`rg README.md .`,
			"notes.txt:README.md",
			nil,
			nil,
		},
		{
			"filename-shaped explicit pattern is not a file",
			`rg -e README.md .`,
			"notes.txt:README.md",
			nil,
			nil,
		},
		{
			"filename-shaped pattern does not hide the scoped file",
			`rg "config.yaml" pkg/mod.py`,
			"pkg/mod.py: config.yaml",
			[]string{"pkg/mod.py"},
			nil,
		},
		{
			"multi-file grep credits nothing",
			`grep -rn "pattern" pkg/a.py pkg/b.py`,
			output,
			nil,
			nil,
		},
		{
			"grep -l suppresses content",
			`grep -l "pattern" pkg/mod.py`,
			output,
			nil,
			nil,
		},
		{
			"find credits nothing",
			`find . -name "*.py"`,
			output,
			nil,
			nil,
		},
		{
			"empty output credits nothing",
			`cat pkg/mod.py`,
			"",
			nil,
			nil,
		},
		{
			"absolute path inside workspace",
			`sed -n '5,9p' /repo/pkg/mod.py`,
			output,
			[]string{"pkg/mod.py"},
			map[string][]Span{"pkg/mod.py": {{5, 9}}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := retrievalFromCommand(c.command, c.output, ws)
			var files []string
			var spans map[string][]Span
			if s != nil {
				files, spans = s.files, s.spans
			}
			if !reflect.DeepEqual(files, c.wantFiles) {
				t.Errorf("files = %#v, want %#v", files, c.wantFiles)
			}
			if !reflect.DeepEqual(spans, c.wantSpans) {
				t.Errorf("spans = %#v, want %#v", spans, c.wantSpans)
			}
		})
	}
}

func TestHeadReadStepRejectsHereString(t *testing.T) {
	ws := testWorkspace()
	cases := []struct {
		name      string
		command   string
		wantFiles []string
		wantSpans map[string][]Span
	}{
		{
			name:    "here string is data rather than a file read",
			command: `head -n 1 <<< .env`,
		},
		{
			name:      "file operand remains a read",
			command:   `head -n 1 .env`,
			wantFiles: []string{".env"},
			wantSpans: map[string][]Span{
				".env": {{Start: 1, End: 1}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := retrievalFromCommand(tc.command, ".env\n", ws)
			var files []string
			var spans map[string][]Span
			if got != nil {
				files, spans = got.files, got.spans
			}
			if !reflect.DeepEqual(files, tc.wantFiles) || !reflect.DeepEqual(spans, tc.wantSpans) {
				t.Fatalf("retrievalFromCommand(%q) = files=%#v spans=%#v, want files=%#v spans=%#v", tc.command, files, spans, tc.wantFiles, tc.wantSpans)
			}
		})
	}
}

func TestRetrievalRetainsOnlyUnambiguousReadContent(t *testing.T) {
	ws := testWorkspace()

	single := retrievalFromCommand(
		`sed -n '12,14p' src/main.ts`,
		"const first = true;\n\nconst last = true;\n",
		ws,
	)
	want := map[string][]ReadRange{
		"src/main.ts": {{Start: 12, End: 14, Content: "const first = true;\n\nconst last = true;"}},
	}
	if single == nil || !reflect.DeepEqual(single.readRanges, want) {
		t.Fatalf("single read ranges = %#v, want %#v", single, want)
	}

	numbered := inferReadStep(
		"src/main.ts",
		"  27→export const hourCycle = 'h23';\n  28→export const ready = true;\n",
		ws,
	)
	want = map[string][]ReadRange{
		"src/main.ts": {{Start: 27, End: 28, Content: "export const hourCycle = 'h23';\nexport const ready = true;"}},
	}
	if numbered == nil || !reflect.DeepEqual(numbered.readRanges, want) {
		t.Fatalf("numbered read ranges = %#v, want %#v", numbered, want)
	}

	combined := retrievalFromCommand(
		`sed -n '1,2p' src/a.ts && sed -n '1,2p' src/b.ts`,
		"a1\na2\nb1\nb2\n",
		ws,
	)
	if combined == nil || len(combined.readRanges) != 0 {
		t.Fatalf("combined command must not guess per-file content: %#v", combined)
	}

	filtered := retrievalFromCommand(
		`sed -n '1,100p' src/main.ts | grep ready`,
		"export const ready = true;\n",
		ws,
	)
	if filtered != nil {
		t.Fatalf("pipeline output cannot prove the leading read succeeded: %#v", filtered)
	}
}

func TestRetrievalFromCommandRejectsPipelineMaskedReadFailure(t *testing.T) {
	got := retrievalFromCommand("cat missing.txt | printf fallback", "fallback", testWorkspace())
	if got != nil {
		t.Fatalf("retrievalFromCommand credited an unproven pipeline read: %+v", got)
	}
}

func TestWorkspaceRelPrivateVarToggle(t *testing.T) {
	ws := newWorkspace("/var/folders/xx/T/work")
	rel, ok := ws.rel("/private/var/folders/xx/T/work/pkg/mod.py")
	if !ok || rel != "pkg/mod.py" {
		t.Errorf("rel = %q,%v want pkg/mod.py,true", rel, ok)
	}
	rel, ok = ws.rel("/var/folders/xx/T/work/pkg/mod.py")
	if !ok || rel != "pkg/mod.py" {
		t.Errorf("rel = %q,%v want pkg/mod.py,true", rel, ok)
	}
	if rel, ok := ws.rel("/elsewhere/file.py"); ok || rel != "/elsewhere/file.py" {
		t.Errorf("outside-workspace path = %q,%v want unchanged,false", rel, ok)
	}
}

func TestWorkspaceRelPortableWindowsPath(t *testing.T) {
	ws := newWorkspace(`C:\work\repo`)
	rel, ok := ws.rel(`C:\work\repo\pkg\mod.py`)
	if !ok || rel != "pkg/mod.py" {
		t.Fatalf("rel = %q,%v want pkg/mod.py,true", rel, ok)
	}
	if rel, ok := ws.rel(`C:\elsewhere\file.py`); ok || rel != `C:\elsewhere\file.py` {
		t.Fatalf("outside-workspace path = %q,%v", rel, ok)
	}
}

func TestNewWorkspaceDoesNotReadProcessWorkingDirectory(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	t.Chdir(first)
	a := newWorkspace("workspace")
	t.Chdir(second)
	b := newWorkspace("workspace")
	if !reflect.DeepEqual(a, b) || a.root != "workspace" {
		t.Fatalf("relative recorded workspace depends on process cwd: first=%+v second=%+v", a, b)
	}
}

func TestWorkspaceRelRejectsAliasSuffixSymlinkEscape(t *testing.T) {
	requirePOSIXSymlinkTraversal(t)
	root := t.TempDir()
	workspaceDir := filepath.Join(root, "repo")
	outsideDir := filepath.Join(root, "outside")
	if err := os.MkdirAll(workspaceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "repo-alias")
	if err := os.Symlink(workspaceDir, alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(workspaceDir, "out")); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(outsideDir, "secret")
	if err := os.WriteFile(secret, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}

	facts := classifyCommand("rm "+filepath.Join(alias, "out", "secret"), "", true, newWorkspace(workspaceDir))
	if facts == nil || !reflect.DeepEqual(facts.categories, []string{"workspace.escape"}) ||
		len(facts.targets) != 0 || len(facts.mutations) != 0 {
		t.Fatalf("alias suffix escape = %+v, want workspace.escape only", facts)
	}
}

// requirePOSIXSymlinkTraversal skips a fixture whose escape depends on POSIX
// path resolution. Both of the fixtures below turn on a symlinked directory
// being traversed by a following `..`, and the two platforms disagree about
// what that means: POSIX resolves the symlink and lands outside, while Windows
// cleans `..` against the preceding NAME before any link is followed, so the
// traversal simply returns to the parent and the escape these tests describe
// cannot be staged there at all. The rejection itself is not
// platform-specific - it is the same code on both, and the corpus exercises it
// - but a fixture that cannot reproduce the hazard would only be asserting the
// local filesystem's behaviour.
func requirePOSIXSymlinkTraversal(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the escape under test depends on POSIX symlink-before-.. resolution")
	}
}

// The command corpus cannot model symlink topology or post-command filesystem
// state, so these path-resolution regressions use temporary workspaces.
func TestWorkspaceRelRejectsSymlinkTraversalBeforeLexicalCleaning(t *testing.T) {
	requirePOSIXSymlinkTraversal(t)
	root := t.TempDir()
	workspaceDir := filepath.Join(root, "workspace")
	outsideDir := filepath.Join(root, "outside")
	if err := os.MkdirAll(workspaceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(workspaceDir, "out")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspaceDir, "victim"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The destination keeps its traversal, because going through `out/..` is
	// the whole point of the fixture - filepath.Join would clean the `..` away
	// along with the symlink it traverses. It still has to be spelled with the
	// platform separator, since a rename given a mixed-separator path fails
	// outright on Windows and the test would never reach its assertion.
	traversed := strings.Join(
		[]string{workspaceDir, "out", "..", "outside", "moved"},
		string(filepath.Separator),
	)
	if err := os.Rename(filepath.Join(workspaceDir, "victim"), traversed); err != nil {
		t.Fatal(err)
	}

	facts := classifyCommand("mv victim out/../outside/moved", "", true, newWorkspace(workspaceDir))
	if facts == nil || !reflect.DeepEqual(facts.categories, []string{"workspace.escape"}) ||
		len(facts.targets) != 0 || len(facts.mutations) != 0 {
		t.Fatalf("symlink traversal move = %+v, want workspace.escape only", facts)
	}
}

func TestWorkspaceRelWithholdsDescendantOfDeletedSymlink(t *testing.T) {
	root := t.TempDir()
	workspaceDir := filepath.Join(root, "workspace")
	outsideDir := filepath.Join(root, "outside")
	if err := os.MkdirAll(workspaceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(workspaceDir, "out")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outsideDir, "secret"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(workspaceDir, "out", "secret")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(workspaceDir, "out")); err != nil {
		t.Fatal(err)
	}

	facts := classifyCommand("rm out/secret out", "", true, newWorkspace(workspaceDir))
	want := &commandFacts{
		categories: []string{"fs.delete"},
		targets:    []CommandTarget{{Kind: "path", Value: "out"}},
		mutations:  []ShellMutation{{Kind: "delete", Path: "out"}},
	}
	if !reflect.DeepEqual(facts, want) {
		t.Fatalf("deleted symlink ancestor = %+v, want %+v", facts, want)
	}
}

func TestNormalizeWorkspacePathPreservesWhitespace(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
		ok    bool
	}{
		{name: "trailing space", value: "victim ", want: "victim ", ok: true},
		{name: "leading space", value: " victim", want: " victim", ok: true},
		{name: "space-only filename", value: " ", want: " ", ok: true},
		{name: "empty operand", value: "", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := normalizeWorkspacePath(tt.value, testWorkspace())
			if got != tt.want || ok != tt.ok {
				t.Fatalf("normalizeWorkspacePath(%q) = %q, %v; want %q, %v", tt.value, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestInferSearchFileStepFromPath(t *testing.T) {
	ws := testWorkspace()
	if s := inferSearchFileStepFromPath("pkg/mod.py", "match found", ws); s == nil || s.files[0] != "pkg/mod.py" {
		t.Errorf("single file grep path should be credited, got %+v", s)
	}
	if s := inferSearchFileStepFromPath("pkg/mod.py", "No matches found", ws); s != nil {
		t.Errorf("no-match output should credit nothing, got %+v", s)
	}
	if s := inferSearchFileStepFromPath(".github", "match", ws); s != nil {
		t.Errorf("hidden directory should credit nothing, got %+v", s)
	}
	if s := inferSearchFileStepFromPath("jquery-3.6", "match", ws); s != nil {
		t.Errorf("version-suffixed directory should credit nothing, got %+v", s)
	}
}

func TestSearchOutputNamesChildOf(t *testing.T) {
	for _, tc := range []struct {
		operand string
		output  string
	}{
		{"docs.api", "./docs.api/file.go:1:TODO\n"},
		{".env.production", "\x1b[32m.env.production/settings\x1b[0m:TODO\n"},
		{"docs.api", `.\\docs.api\\file.go:1:TODO` + "\n"},
	} {
		if !searchOutputNamesChildOf(tc.operand, tc.output) {
			t.Fatalf("child output %q was not recognized", tc.output)
		}
	}
	if file := explicitSingleSearchFile(tokensForSegment("rg --color=always TODO .env.production"), "\x1b[32m.env.production/settings\x1b[0m:TODO\n", testWorkspace()); file != "" {
		t.Fatalf("colored directory output was credited as %q", file)
	}
}

func TestCommandRawStdoutRedirected(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{"chmod -c 0600 file.txt '>' changes.log", false},
		{"chmod -c 0600 file.txt <> rw.log", false},
		{"chmod -c 0600 file.txt 2>&1", false},
		{"chmod -c 0600 file.txt &> changes.log", true},
	} {
		if got := commandRawStdoutRedirected(tc.raw); got != tc.want {
			t.Fatalf("commandRawStdoutRedirected(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestMergeSpans(t *testing.T) {
	got := mergeSpans([]Span{{10, 20}, {1, 5}, {18, 30}, {6, 8}})
	want := []Span{{1, 8}, {10, 30}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mergeSpans = %v, want %v", got, want)
	}
}
