package digest

import (
	"reflect"
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
			"nl piped to sed keeps file credit",
			`nl -ba pkg/mod.py | sed -n '250,310p'`,
			numbered,
			[]string{"pkg/mod.py"},
			map[string][]Span{"pkg/mod.py": {{250, 310}}},
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
			"single-file grep",
			`grep -n "pattern" pkg/mod.py`,
			output,
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
	if filtered == nil || len(filtered.readRanges) != 0 {
		t.Fatalf("filtered output must not be presented as a contiguous range: %#v", filtered)
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

func TestMergeSpans(t *testing.T) {
	got := mergeSpans([]Span{{10, 20}, {1, 5}, {18, 30}, {6, 8}})
	want := []Span{{1, 8}, {10, 30}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mergeSpans = %v, want %v", got, want)
	}
}
