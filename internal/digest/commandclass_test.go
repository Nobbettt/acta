package digest

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestClassifyCommandCreditsNothingForEmptyCommand(t *testing.T) {
	if facts := classifyCommand("", "", true, newWorkspace("/work/repo")); facts != nil {
		t.Fatalf("classifyCommand(\"\") = %+v, want nil", facts)
	}
}

func TestClassifyEventCommandHandlesBackslashNewline(t *testing.T) {
	cases := []struct {
		name        string
		command     string
		wantTargets []CommandTarget
		wantChanges []ShellMutation
	}{
		{
			name:        "continued comment is not a package operand",
			command:     "npm install left-pad \\\n# ghp_SECRET",
			wantTargets: []CommandTarget{{Kind: "package", Value: "left-pad"}},
		},
		{
			name:        "continued path is one operand",
			command:     "rm foo\\\nbar",
			wantTargets: []CommandTarget{{Kind: "path", Value: "foobar"}},
			wantChanges: []ShellMutation{{Kind: "delete", Path: "foobar"}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := Event{Kind: KindCommand, Command: c.command}
			classifyEventCommand(&e, "", true, testWorkspace())
			if !reflect.DeepEqual(e.Targets, c.wantTargets) {
				t.Errorf("targets = %+v, want %+v", e.Targets, c.wantTargets)
			}
			if !reflect.DeepEqual(e.ShellMutations, c.wantChanges) {
				t.Errorf("mutations = %+v, want %+v", e.ShellMutations, c.wantChanges)
			}
		})
	}
}

func TestClassifyCommandSeparatesAttachedShellOperators(t *testing.T) {
	cases := []struct {
		name        string
		command     string
		wantTargets []CommandTarget
		wantChanges []ShellMutation
	}{
		{
			name:        "redirect after delete operand",
			command:     "rm old.txt>/dev/null",
			wantTargets: []CommandTarget{{Kind: "path", Value: "old.txt"}},
			wantChanges: []ShellMutation{{Kind: "delete", Path: "old.txt"}},
		},
		{
			name:        "pipe after URL operand",
			command:     "curl https://example.com|cat",
			wantTargets: []CommandTarget{{Kind: "url", Value: "https://example.com"}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts := classifyCommand(c.command, "", true, testWorkspace())
			if facts == nil {
				t.Fatalf("classifyCommand(%q) credited nothing", c.command)
			}
			if !reflect.DeepEqual(facts.targets, c.wantTargets) {
				t.Errorf("targets = %+v, want %+v", facts.targets, c.wantTargets)
			}
			if !reflect.DeepEqual(facts.mutations, c.wantChanges) {
				t.Errorf("mutations = %+v, want %+v", facts.mutations, c.wantChanges)
			}
		})
	}
}

func TestClassifyCommandRejectsMissingControlListOperands(t *testing.T) {
	commands := []string{
		"curl https://never.example &&",
		"curl https://never.example && # trailing",
		"&& curl https://never.example",
		"curl https://never.example && || wget https://also-never.example",
	}
	for _, command := range commands {
		if facts := classifyCommand(command, "", false, testWorkspace()); facts != nil {
			t.Errorf("classifyCommand(%q) = %+v, want nil for an invalid control list", command, facts)
		}
	}
}

func TestClassifyCommandRejectsMalformedAmpersandLists(t *testing.T) {
	for _, command := range []string{
		"curl https://example.com;&",
		"curl https://example.com&;",
	} {
		if facts := classifyCommand(command, "", false, testWorkspace()); facts != nil {
			t.Errorf("classifyCommand(%q) = %+v, want nil for an invalid ampersand list", command, facts)
		}
	}
}

func TestClassifyCommandTracksLiteralOutsideWorkingDirectory(t *testing.T) {
	commands := []string{
		"cd /tmp && rm victim.txt",
		"cd /tmp && mv old.txt new.txt",
		"cd /tmp && cp source.txt copy.txt",
		"cd /tmp && touch created.txt",
		"cd /tmp && mkdir created",
		"cd /tmp && chmod 600 victim.txt",
		"cd /tmp && tar -xf archive.tar",
	}
	for _, command := range commands {
		facts := classifyCommand(command, "", true, testWorkspace())
		if facts == nil || !reflect.DeepEqual(facts.categories, []string{"workspace.escape"}) ||
			len(facts.targets) != 0 || len(facts.mutations) != 0 {
			t.Errorf("classifyCommand(%q) = %+v, want workspace.escape only", command, facts)
		}
	}
}

func TestClassifyCommandTracksExportedGitWorkTree(t *testing.T) {
	command := `/bin/bash -lc "export GIT_WORK_TREE=/tmp/other && git rm victim.txt"`
	facts := classifyCommand(command, "", true, testWorkspace())
	if facts == nil || !reflect.DeepEqual(facts.categories, []string{"workspace.escape"}) ||
		len(facts.targets) != 0 || len(facts.mutations) != 0 {
		t.Fatalf("classifyCommand(%q) = %+v, want workspace.escape only", command, facts)
	}
}

func TestReadFacetsStopAfterWorkingDirectoryChanges(t *testing.T) {
	ws := testWorkspace()
	ws.controlPrefix = "stage-control"
	e := Event{Kind: KindCommand, Command: "cd /tmp && cat stage-control/task.json"}
	applyStep(&e, retrievalFromCommand(e.Command, "task contents\n", ws))
	classifyEventCommand(&e, "task contents\n", true, ws)
	if len(e.Files) != 0 {
		t.Errorf("files = %v, want none after an untracked cwd change", e.Files)
	}
	if slices.Contains(e.Categories, "control.access") {
		t.Errorf("categories = %v, must not include control.access", e.Categories)
	}
}

const testHeadSHA = "0123456789abcdef0123456789abcdef01234567"

func TestCommandFactsMergeSanitizesTargetsAndMutations(t *testing.T) {
	raw := &commandFacts{
		targets: []CommandTarget{
			{Kind: "url", Value: "https://user:secret@example.test/private"},
			{Kind: "package", Value: "git+https://user:secret@packages.example.test/private.git"},
			{Kind: "path", Value: "$ROOT/private"},
		},
		mutations: []ShellMutation{
			{Kind: "delete", Path: "$(printf victim.txt)"},
			{Kind: "move", From: "old.txt", To: "new.txt"},
			{Kind: "move", From: "incomplete.txt"},
		},
	}
	facts := &commandFacts{}
	facts.merge(raw)
	if want := []CommandTarget{{Kind: "url", Value: "https://example.test"}}; !reflect.DeepEqual(facts.targets, want) {
		t.Fatalf("merged targets = %+v, want %+v", facts.targets, want)
	}
	if want := []ShellMutation{{Kind: "move", From: "old.txt", To: "new.txt"}}; !reflect.DeepEqual(facts.mutations, want) {
		t.Fatalf("merged mutations = %+v, want %+v", facts.mutations, want)
	}
}

// Output belongs to the whole command, never to one segment of it. A
// single-segment command is therefore the only case where output proves
// anything: in `git rev-parse HEAD && echo something` the sha in the output
// could have come from either half, so crediting it as this command's HEAD
// would be an invention. The category, which the command text alone proves,
// survives; only the output-derived target is withheld.
func TestClassifyCommandTrustsOutputOnlyForASingleSegment(t *testing.T) {
	cases := []struct {
		name    string
		command string
		output  string
		want    []CommandTarget
	}{
		{
			"single segment proves the sha",
			"git rev-parse HEAD",
			testHeadSHA + "\n",
			[]CommandTarget{{Kind: "ref", Value: testHeadSHA}},
		},
		{"a second segment withholds it", "git rev-parse HEAD && echo something", testHeadSHA + "\n", nil},
		{"a pipeline withholds it", "git rev-parse HEAD | printf forged", testHeadSHA + "\n", nil},
		{"a leading segment withholds it too", "cd sub; git rev-parse HEAD", testHeadSHA + "\n", nil},
		{
			// Only the origin is published: a remote path can itself carry a
			// secret, and the host is the whole provenance fact.
			"single segment proves the remote",
			"git remote -v",
			"origin\thttps://example.test/a.git (fetch)\n",
			[]CommandTarget{{Kind: "url", Value: "https://example.test"}},
		},
		{
			"a second segment withholds the remote",
			"git remote -v && git status",
			"origin\thttps://example.test/a.git (fetch)\n",
			nil,
		},
		{
			"a pipeline withholds the remote",
			"git remote -v | printf forged",
			"origin\thttps://secret.example.test/credential (fetch)\n",
			nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts := classifyCommand(c.command, c.output, true, testWorkspace())
			if facts == nil {
				t.Fatalf("classifyCommand(%q) credited nothing", c.command)
			}
			if !slices.Contains(facts.categories, "vcs.provenance") {
				t.Errorf("categories = %v, want vcs.provenance", facts.categories)
			}
			if !reflect.DeepEqual(facts.targets, c.want) {
				t.Errorf("targets = %+v, want %+v", facts.targets, c.want)
			}
		})
	}
}

// The same rule covers sandbox.denied, the other fact read out of the output:
// a denial marker in a chained command does not say which half was refused.
func TestSandboxDeniedTrustsOutputOnlyForASingleSegment(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    bool
	}{
		{"single segment", "cp a.txt /etc/a.txt", true},
		{"chained command", "mkdir out && cp a.txt out/", false},
		{"sequenced command", "cd sub; cp a.txt /etc/a.txt", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			output := "cp: Operation not permitted\n"
			e := Event{Kind: KindCommand, Command: c.command, IsError: true, Output: output}
			applyRunState(&Digest{}, &e, output)
			if got := slices.Contains(e.Categories, "sandbox.denied"); got != c.want {
				t.Errorf("sandbox.denied = %v, want %v (categories %v)", got, c.want, e.Categories)
			}
		})
	}
}

// Every category that asserts a state change is gated on the exit status, and
// workspace.escape is no exception: a failed `rm /etc/passwd` removed nothing
// and so escaped nothing. The gate lives in classifyFS, which returns before it
// reads a single operand — nothing downstream has to re-check it.
func TestFailedEscapingDeleteCreditsNothing(t *testing.T) {
	for _, exitOK := range []bool{true, false} {
		e := Event{Kind: KindCommand, Command: "rm /etc/passwd", IsError: !exitOK}
		classifyEventCommand(&e, "", exitOK, testWorkspace())
		switch {
		case exitOK && !reflect.DeepEqual(e.Categories, []string{"workspace.escape"}):
			t.Errorf("successful rm categories = %v, want [workspace.escape]", e.Categories)
		case !exitOK && len(e.Categories) != 0:
			t.Errorf("failed rm categories = %v, want none", e.Categories)
		}
		if len(e.ShellMutations) != 0 {
			t.Errorf("rm outside the workspace recorded mutations %+v", e.ShellMutations)
		}
	}
}

// Several classifiers can credit one command; none of them may credit the same
// category twice, and the published list is sorted.
func TestClassifyEventCommandCategoriesAreSortedAndDeduped(t *testing.T) {
	e := Event{
		Kind:    KindCommand,
		Command: "git rebase -i HEAD~3 && rm dist/old.js && rm docs/AGENTS.md",
		Files:   []string{"docs/AGENTS.md"},
	}
	classifyEventCommand(&e, "", true, testWorkspace())
	want := []string{
		"command.interactive", "fs.delete", "instructions.read",
		"path.generated", "vcs.rewrite",
	}
	if !reflect.DeepEqual(e.Categories, want) {
		t.Fatalf("categories = %v, want %v", e.Categories, want)
	}
}

// A heredoc body is data the command writes or pipes, never a command of its
// own. splitRawChain splits on raw newlines before any tokenizing happens, so
// without stripping the body first, every line written into the heredoc would
// classify as its own fully-formed shell command.
func TestClassifyCommandIgnoresHeredocBody(t *testing.T) {
	cases := []struct {
		name    string
		command string
	}{
		{
			"quoted delimiter",
			"cat > cleanup.sh <<'EOF'\nrm -rf dist\ngit push --force\nEOF",
		},
		{
			"bare delimiter",
			"cat > cleanup.sh <<EOF\nrm -rf dist\nEOF",
		},
		{
			"backslash-quoted delimiter",
			"cat > cleanup.sh <<\\EOF\nrm -rf dist\nEOF",
		},
		{
			"single-quoted delimiter with a hyphen",
			"cat > cleanup.sh <<'EOT-1'\nrm -rf dist\nEOT-1",
		},
		{
			"single-quoted delimiter starting with a digit",
			"cat > cleanup.sh <<'2EOF'\nrm -rf dist\n2EOF",
		},
		{
			"double-quoted delimiter",
			"cat > cleanup.sh <<\"EOF\"\nrm -rf dist\nEOF",
		},
		{
			"dash-stripping opener",
			"cat > cleanup.sh <<-EOF\nrm -rf dist\nEOF",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if facts := classifyCommand(c.command, "", true, testWorkspace()); facts != nil {
				t.Fatalf("classifyCommand(heredoc) = %+v, want nil: the body is not commands", facts)
			}
		})
	}
}

// A `<<` written inside a quoted argument is not a heredoc opener, and must
// not be mistaken for one: the round-1 fix's raw-text regex could not tell
// the difference, so it hunted for a closing delimiter line that would never
// come and silently dropped every segment after the false match. Both
// segments here are real commands and must classify normally.
func TestClassifyCommandDoesNotTreatQuotedShiftOperatorAsHeredoc(t *testing.T) {
	cases := []struct {
		name    string
		command string
	}{
		{"single-quoted << in a commit message", "git commit -m 'shift a << b' && git push"},
		{"double-quoted << in a grep pattern", `rg -n "x << y" src && go build ./...`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts := classifyCommand(c.command, "", true, testWorkspace())
			if facts == nil {
				t.Fatalf("classifyCommand(%q) credited nothing, want the second segment classified", c.command)
			}
			want := map[string]string{
				"single-quoted << in a commit message": "forge.mutate",
				"double-quoted << in a grep pattern":   "verify.run",
			}[c.name]
			if !slices.Contains(facts.categories, want) {
				t.Errorf("categories = %v, want %s", facts.categories, want)
			}
		})
	}
}

// When a heredoc's shape cannot be resolved — the delimiter word itself is
// unparseable, or its closing line never appears — guessing risks a false
// positive in either direction (classifying body text as commands, or
// silently dropping real commands after it). The safe default is to credit
// nothing for the whole command.
func TestClassifyCommandAbandonsWholeCommandOnAmbiguousHeredoc(t *testing.T) {
	cases := []struct {
		name    string
		command string
	}{
		{"unterminated delimiter quote", "cat > f.sh <<'EOF\nrm -rf dist"},
		{"closing delimiter never appears", "cat > f.sh <<EOF\nrm -rf dist\ngit push"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if facts := classifyCommand(c.command, "", true, testWorkspace()); facts != nil {
				t.Fatalf("classifyCommand(%q) = %+v, want nil", c.command, facts)
			}
		})
	}
}

// One exit status cannot be attributed to a segment the chain does not prove
// ran and succeeded. A literal failure can prove its final `||` branch ran;
// unknown commands, earlier terms, semicolon lists, and newlines cannot.
func TestClassifyCommandSuppressesStateChangeAcrossOr(t *testing.T) {
	cases := []struct {
		name        string
		command     string
		wantNil     bool
		wantDeleted bool
	}{
		{"rm rescued by || echo credits nothing", "rm stale.txt || echo already gone", true, false},
		{"a literal failure proves the rescuing command ran", "false || rm stale.txt", false, true},
		{"a plain && chain still credits the delete", "mkdir out && rm stale.txt", false, true},
		{"a semicolon discards the earlier segment's status", "rm stale.txt; echo done", true, false},
		{"a newline discards the earlier segment's status", "rm stale.txt\necho done", true, false},
		{"the && head of A && B || C is equally unproven", "rm stale.txt && echo done || echo failed", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts := classifyCommand(c.command, "", true, testWorkspace())
			if c.wantNil {
				if facts != nil {
					t.Fatalf("classifyCommand(%q) = %+v, want nil", c.command, facts)
				}
				return
			}
			if facts == nil || !slices.Contains(facts.categories, "fs.delete") {
				t.Fatalf("classifyCommand(%q) categories = %+v, want fs.delete", c.command, facts)
			}
		})
	}
}

// is_error is optional in the claude tool_result stream and defaults to
// false, so a failed bash tool can arrive with is_error absent while
// tool_use_result still carries the real nonzero exit_code. classifyEventCommand
// must trust that exit code rather than treating the missing flag as success.
func TestClaudeFailedCommandWithoutIsErrorCreditsNothing(t *testing.T) {
	lines := []string{
		`{"type":"assistant","message":{"id":"m1","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"rm missing.txt"}}]}}`,
		`{"type":"user","tool_use_result":{"exit_code":1,"stdout":"rm: missing.txt: No such file or directory\n"},"message":{"content":[{"type":"tool_result","tool_use_id":"t1","content":"rm: missing.txt: No such file or directory\n"}]}}`,
		`{"type":"result","subtype":"success","session_id":"test-session","is_error":false}`,
	}
	d, err := parseClaude(strings.NewReader(strings.Join(lines, "\n")+"\n"), testWorkspace())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range d.Timeline {
		if e.Kind != KindCommand {
			continue
		}
		if len(e.Categories) != 0 {
			t.Errorf("categories = %v, want none for a failed rm", e.Categories)
		}
		if len(e.ShellMutations) != 0 {
			t.Errorf("mutations = %+v, want none for a failed rm", e.ShellMutations)
		}
	}
}

// A duplicate operand within one segment is one real change. The same mutation
// in two segments is two changes when another command recreated the path in
// between, so deduplication must not span the whole command.
func TestClassifyCommandDedupesMutationsWithinEachSegment(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    int
	}{
		{"repeated operand in one segment", "rm a.txt a.txt", 1},
		{"path recreated between deletes", "rm a.txt && touch a.txt && rm a.txt", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts := classifyCommand(c.command, "", true, testWorkspace())
			if facts == nil {
				t.Fatalf("classifyCommand(%q) credited nothing", c.command)
			}
			if len(facts.mutations) != c.want {
				t.Errorf("mutations = %+v, want exactly %d", facts.mutations, c.want)
			}
		})
	}
}

// A quoted argument that happens to contain shell separator characters is not
// a chain of real commands: a quote-unaware split cuts through the quote and
// turns each embedded line/clause into its own fake segment, which then
// classifies as real commands — file content forging categories and
// mutations, the same class of bug as the heredoc leak. Both cases here must
// classify as exactly one command: the one actually invoked.
func TestClassifyCommandDoesNotSplitInsideAQuotedArgument(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    string // the category the real (unquoted) command must still earn
	}{
		{
			"newline-separated text inside a quoted --body",
			"gh pr create --body \"Removed legacy code.\nrm -rf legacy was run manually.\nSee notes.\"",
			"forge.mutate",
		},
		{
			"semicolon-separated text inside a quoted commit message",
			`git commit -m "wip; rm tmp.txt; done"`,
			"vcs.mutate",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts := classifyCommand(c.command, "", true, testWorkspace())
			if facts == nil {
				t.Fatalf("classifyCommand(%q) credited nothing, want %s", c.command, c.want)
			}
			if !slices.Contains(facts.categories, c.want) {
				t.Errorf("categories = %v, want %s", facts.categories, c.want)
			}
			if slices.Contains(facts.categories, "fs.delete") {
				t.Errorf("categories = %v, must not credit fs.delete: the quoted text is not a command", facts.categories)
			}
			if len(facts.mutations) != 0 {
				t.Errorf("mutations = %+v, want none: nothing inside the quote was actually deleted", facts.mutations)
			}
		})
	}
}

// A leading `(` on a subshell segment must still be recognised as `cd` so
// cwdUncertain is set: without it, a relative operand in the segment after
// the subshell's `cd` is wrongly resolved against the workspace root instead
// of being withheld as unprovable.
func TestClassifyCommandRecognisesCdInsideASubshell(t *testing.T) {
	facts := classifyCommand("(cd frontend && rm old.go )", "", true, testWorkspace())
	if facts != nil {
		t.Fatalf("classifyCommand(subshell cd) = %+v, want nil: the delete target cannot be resolved without a known cwd", facts)
	}
}

// The glued `(cd` form above is not the only shape that hides a `cd`: a
// space after the paren, or an assignment/`sudo` prefix in front of `cd`,
// must taint every path too. A subshell additionally revokes execution proof;
// the prefix forms retain only the command category.
func TestClassifyCommandRecognisesCdBehindASpacedSubshellOrAPrefix(t *testing.T) {
	cases := []struct {
		name         string
		command      string
		wantCategory bool
	}{
		{"space after the subshell paren", "( cd frontend && rm old.go )", false},
		{"env-assignment prefix before cd", "FOO=1 cd frontend && rm old.go", true},
		{"sudo prefix before cd", "sudo cd frontend && rm old.go", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts := classifyCommand(c.command, "", true, testWorkspace())
			if !c.wantCategory {
				if facts != nil {
					t.Fatalf("classifyCommand(%q) = %+v, want nil without execution proof", c.command, facts)
				}
				return
			}
			if facts == nil || !reflect.DeepEqual(facts.categories, []string{"fs.delete"}) || len(facts.targets) != 0 || len(facts.mutations) != 0 {
				t.Fatalf("classifyCommand(%q) = %+v, want category-only fs.delete", c.command, facts)
			}
		})
	}
}

// sandbox.denied must read the same bounded text classifyEventCommand
// classified, not e.Output: digest.go caps e.Output at MaxEventOutputChars
// (8,000 chars), well short of the classifier's own 120,000-char bound, so a
// marker beyond that point would otherwise be invisible to this category
// alone.
func TestSandboxDeniedUsesTheClassifiedOutputNotTheTruncatedField(t *testing.T) {
	full := strings.Repeat("x", 9000) + "operation not permitted"
	e := Event{
		Kind: KindCommand, Command: "cp a.txt /etc/a.txt", IsError: true,
		Output: strings.Repeat("x", MaxEventOutputChars), // simulates the field already truncated short of the marker
	}
	applyRunState(&Digest{}, &e, full)
	if !slices.Contains(e.Categories, "sandbox.denied") {
		t.Errorf("categories = %v, want sandbox.denied", e.Categories)
	}
}

// Bash closes a heredoc only when a later line equals the delimiter exactly
// (for plain `<<`) or, for `<<-`, equals it after leading TABS only are
// stripped — never spaces, never trailing whitespace. Matching the closing
// line with strings.TrimSpace instead accepts lines the shell would not,
// ending the heredoc early and handing everything after it — real body text
// the agent wrote into a file, never executed — to the classifiers as if it
// were the next command. Each case here has a line that looks like it might
// close the heredoc but must not, followed by text that must never be
// credited (network.egress / search.query), and only closes on the true
// final "EOF" line, leaving nothing else to classify.
func TestClassifyCommandRequiresExactHeredocTerminator(t *testing.T) {
	cases := []struct {
		name    string
		command string
	}{
		{
			"space-indented terminator does not close a plain << heredoc",
			"cat <<EOF > a.md\nx\n  EOF\ncurl https://evil.example.com\nEOF",
		},
		{
			"tab-indented terminator does not close a plain << heredoc",
			"cat <<EOF > a.md\nx\n\tEOF\nrg secret-pattern .\nEOF",
		},
		{
			"trailing space on the terminator line does not close it",
			"cat <<EOF > a.md\nx\nEOF \nssh admin@prod.example.com\nEOF",
		},
		{
			"<<- strips leading tabs, not spaces, so a space-indented line still does not close it",
			"cat <<-EOF > a.md\nx\n  EOF\ncurl https://evil2.example.com\nEOF",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if facts := classifyCommand(c.command, "", true, testWorkspace()); facts != nil {
				t.Fatalf("classifyCommand(%q) = %+v, want nil: everything but the opener is heredoc body", c.command, facts)
			}
		})
	}
}

// stripHeredocBodies matches a candidate closing line against raw chain
// segments, which are themselves already cut on unquoted `&&`/`||`/`;` as
// well as `\n`. A heredoc body line that happens to end in e.g. "&&EOF" (no
// space before the delimiter) therefore produces its own trailing segment
// whose text is exactly the delimiter — but that is still body text to the
// real shell, which only closes a heredoc on a line containing nothing but
// the delimiter. Matching the split fragment instead of the physical line
// closes the heredoc early and hands its real remaining body, including a
// command the agent only ever wrote to a file, to the classifiers as if it
// had executed.
func TestClassifyCommandHeredocTerminatorMustBeAWholeLineNotAChainFragment(t *testing.T) {
	command := "cat > notes.txt <<EOF\nsome text&&EOF\ncurl https://evil.example.com/x\nEOF\n"
	if facts := classifyCommand(command, "", true, testWorkspace()); facts != nil {
		t.Fatalf("classifyCommand(%q) = %+v, want nil: the heredoc is still open at the &&EOF fragment", command, facts)
	}
}

// A command-list separator after a heredoc opener is command text even though
// the heredoc body itself starts on the next physical line. If stripping the
// body consumes that same-line segment, it also erases the separator that
// decides whether the successful whole-command exit proves an earlier state
// change. Refuse the whole command when both spans cannot be preserved.
func TestClassifyCommandAbandonsHeredocWithSameLineTrailingSegment(t *testing.T) {
	cases := []struct {
		name    string
		command string
	}{
		{"or branch after opener", "rm -rf dist && cat <<EOF > note.txt || echo failed\nnote\nEOF"},
		{"semicolon command after opener", "rm -rf dist && cat <<EOF > note.txt ; echo done\nnote\nEOF"},
		{"and command after opener", "rm -rf dist && cat <<EOF > note.txt && echo done\nnote\nEOF"},
		{"backgrounded command after opener", "rm -rf dist && cat <<EOF > note.txt ; sleep 1 &\nnote\nEOF"},
		{"single mutation rescued after opener", "git apply <<EOF || echo failed\npatch\nEOF"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if facts := classifyCommand(c.command, "", true, testWorkspace()); facts != nil {
				t.Fatalf("classifyCommand(%q) = %+v, want nil: same-line command text after a heredoc opener is ambiguous", c.command, facts)
			}
		})
	}
}

// A `<<-` heredoc's closing line, once its leading tabs really are stripped,
// must still be recognised — the exact-match fix above must not overcorrect
// into refusing every `<<-` terminator.
func TestClassifyCommandClosesDashHeredocAfterStrippingLeadingTabs(t *testing.T) {
	command := "cat <<-EOF > a.md\nx\n\tEOF\ncurl https://after.example.com\n"
	facts := classifyCommand(command, "", true, testWorkspace())
	if facts == nil || !slices.Contains(facts.categories, "network.egress") {
		t.Fatalf("classifyCommand(%q) = %+v, want network.egress credited for the real command after the heredoc", command, facts)
	}
}

func TestClassifyCommandAbandonsEmptyHeredocDelimiter(t *testing.T) {
	command := "cat <<''\ncurl https://body.example\n\n"
	if facts := classifyCommand(command, "", true, testWorkspace()); facts != nil {
		t.Fatalf("classifyCommand(%q) = %+v, want nil: an empty delimiter must not expose heredoc body text", command, facts)
	}
}

func TestClassifyCommandRejectsIncompletePipelines(t *testing.T) {
	commands := []string{
		"curl https://example.invalid/ |",
		"| curl https://example.invalid/",
		"curl https://example.invalid/ |&",
		"curl https://example.invalid/ | | cat",
		"curl https://example.invalid/ | \\\n",
	}
	for _, command := range commands {
		if facts := classifyCommand(command, "", true, testWorkspace()); facts != nil {
			t.Errorf("classifyCommand(%q) = %+v, want nil for an incomplete pipeline", command, facts)
		}
	}
}

func TestClassifyCommandRejectsIncompleteRedirections(t *testing.T) {
	commands := []string{
		"curl https://example.invalid >",
		"curl https://example.invalid > # no destination",
		"rg needle 2>>",
		"rg needle < | cat",
	}
	for _, command := range commands {
		if facts := classifyCommand(command, "", false, testWorkspace()); facts != nil {
			t.Errorf("classifyCommand(%q) = %+v, want nil for an incomplete redirection", command, facts)
		}
	}
}

func TestClassifyCommandKeepsCompleteRedirections(t *testing.T) {
	facts := classifyCommand("curl https://example.test >/dev/null 2>&1", "", false, testWorkspace())
	if facts == nil || !slices.Contains(facts.categories, "network.egress") {
		t.Fatalf("complete redirections suppressed classification: %+v", facts)
	}
}

// splitRawChain never splits a pipeline into its own segment, so `rm x |
// true`'s leading command and the pipeline's reported exit status are two
// different things: the exit status belongs to the LAST stage. Crediting the
// leading command's state-change category off that status turns a failed rm
// into a proven deletion. The conservative invariant revokes proof for the
// whole chain rather than reasoning about which siblings remain attributable.
func TestClassifyCommandSuppressesStateChangeAcrossAPipe(t *testing.T) {
	cases := []struct {
		name           string
		command        string
		wantCategories []string
	}{
		{"a failed rm masked by a trailing pipe credits nothing", "rm nonexistent | true", nil},
		{"a failed mkdir masked by a trailing pipe credits nothing", "mkdir out | true", nil},
		{"a pipeline revokes proof for the whole chain", "mkdir other && rm nonexistent | true", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts := classifyCommand(c.command, "", true, testWorkspace())
			if c.wantCategories == nil {
				if facts != nil {
					t.Fatalf("classifyCommand(%q) = %+v, want nil", c.command, facts)
				}
				return
			}
			if facts == nil || !reflect.DeepEqual(facts.categories, c.wantCategories) {
				t.Fatalf("classifyCommand(%q) categories = %+v, want %v", c.command, facts, c.wantCategories)
			}
			if slices.Contains(facts.categories, "fs.delete") {
				t.Errorf("categories = %v, must not credit fs.delete: rm's own exit status is unproven behind the pipe", facts.categories)
			}
		})
	}
}

func TestClassifyCommandRequiresUnambiguousWholeChainStatus(t *testing.T) {
	commands := []string{
		"exit 0 && rm victim.txt",
		"exec true && rm victim.txt",
		"(true) && rm victim.txt",
	}
	for _, command := range commands {
		if facts := classifyCommand(command, "", true, testWorkspace()); facts != nil {
			t.Errorf("classifyCommand(%q) = %+v, want nil: the delete did not inherit proven success", command, facts)
		}
	}
}

func TestClassifyCommandWithholdsPathsAfterUntrackedParentShellEnvironment(t *testing.T) {
	cases := []struct {
		command string
		want    []string
	}{
		{`/bin/bash -lc "export GIT_DIR=/tmp/other/.git GIT_WORK_TREE=/tmp/other && git rm victim.txt"`, []string{"workspace.escape"}},
		{`/bin/bash -lc "GIT_WORK_TREE=/tmp/other; git rm victim.txt"`, []string{"fs.delete"}},
		{`/bin/bash -lc "GIT_WORK_TREE=/tmp/other >/dev/null; git rm victim.txt"`, []string{"fs.delete"}},
		{`/bin/bash -lc "declare -x GIT_WORK_TREE=/tmp/other; git rm victim.txt"`, []string{"fs.delete"}},
	}
	for _, c := range cases {
		facts := classifyCommand(c.command, "", true, testWorkspace())
		if facts == nil || !reflect.DeepEqual(facts.categories, c.want) ||
			len(facts.targets) != 0 || len(facts.mutations) != 0 {
			t.Errorf("classifyCommand(%q) = %+v, want categories %v only", c.command, facts, c.want)
		}
	}
}

func TestClassifyCommandCreditsNothingAfterLogout(t *testing.T) {
	command := `/bin/bash -lc "logout; rm victim.txt"`
	if facts := classifyCommand(command, "", true, testWorkspace()); facts != nil {
		t.Errorf("classifyCommand(%q) = %+v, want nil because rm never ran", command, facts)
	}
}

func TestClassifyCommandTaintsEveryRelativePathOnAnyPossibleCwdChange(t *testing.T) {
	commands := []string{
		"command -p cd /tmp && rm victim.txt",
		"time cd ../other && rm victim.txt",
		"nice cd ../other && rm victim.txt",
		"stdbuf -oL cd ../other && rm victim.txt",
		"echo cd && rm victim.txt",
		"rm old.go && cd frontend",
	}
	for _, command := range commands {
		facts := classifyCommand(command, "", true, testWorkspace())
		if facts == nil || !reflect.DeepEqual(facts.categories, []string{"fs.delete"}) {
			t.Errorf("classifyCommand(%q) = %+v, want category-only fs.delete", command, facts)
			continue
		}
		if len(facts.targets) != 0 || len(facts.mutations) != 0 {
			t.Errorf("classifyCommand(%q) published tainted paths: %+v", command, facts)
		}
	}
}

func TestClassifyCommandPrunesEveryProvenUnexecutedSegment(t *testing.T) {
	commands := []string{
		"true || false || git status",
		"false && true && git status",
		"exit 0 && git status",
		"exec true && git status",
		"true || false || nohup python server.py",
		"test 1 = 1 || false || git status",
	}
	for _, command := range commands {
		if facts := classifyCommand(command, "", true, testWorkspace()); facts != nil {
			t.Errorf("classifyCommand(%q) = %+v, want nil: no classified segment ran", command, facts)
		}
	}
}

func TestClassifyCommandRejectsUnhandledShellCompounds(t *testing.T) {
	commands := []string{
		"if false\nthen\ngit status\nfi",
		"while false\ndo\ncurl https://body.example\ndone",
		"case x in\nx) rg secret . ;;\nesac",
		"check() { git status; }",
	}
	for _, command := range commands {
		if facts := classifyCommand(command, "", true, testWorkspace()); facts != nil {
			t.Errorf("classifyCommand(%q) = %+v, want nil for unmodelled compound syntax", command, facts)
		}
	}
}

func TestClassifyCommandPrunesAfterPrefixedExec(t *testing.T) {
	commands := []string{
		"time exec true; curl https://example.com",
		"time -p exec true; git status",
		"! exec true; git status",
	}
	for _, command := range commands {
		if facts := classifyCommand(command, "", true, testWorkspace()); facts != nil {
			t.Errorf("classifyCommand(%q) = %+v, want nil: exec terminated the shell", command, facts)
		}
	}
}

func TestClassifyCommandDoesNotPruneAfterExternalTime(t *testing.T) {
	facts := classifyCommand("/usr/bin/time -o timing.txt true; git status", "", true, testWorkspace())
	if facts == nil || !slices.Contains(facts.categories, "vcs.read") {
		t.Fatalf("external time was mistaken for the shell reserved word: %+v", facts)
	}
}

func TestClassifyCommandWithholdsCommandsAfterUncertainExit(t *testing.T) {
	commands := []string{
		"test 1 = 1 || exit; git status",
		"test 1 = 2 && exec true; curl https://example.com",
	}
	for _, command := range commands {
		if facts := classifyCommand(command, "", true, testWorkspace()); facts != nil {
			t.Errorf("classifyCommand(%q) = %+v, want nil after an uncertain shell terminator", command, facts)
		}
	}
}

func TestClassifyCommandKeepsBranchProvenToRunAfterSkippedTerms(t *testing.T) {
	cases := []struct {
		command string
		exitOK  bool
		want    string
	}{
		{"false && true || git status", true, "vcs.read"},
		{"true || false && git status", true, "vcs.read"},
		{"false || curl https://example.com", true, "network.egress"},
		{"false || curl https://example.com", false, "network.egress"},
		{"false || env", true, "env.inspect"},
		{"false || rm victim.txt", true, "fs.delete"},
		{"false || npm install lodash", true, "package.install"},
	}
	for _, c := range cases {
		facts := classifyCommand(c.command, "", c.exitOK, testWorkspace())
		if facts == nil || !slices.Contains(facts.categories, c.want) {
			t.Errorf("classifyCommand(%q) = %+v, want %s", c.command, facts, c.want)
		}
	}
}

func TestClassifyCommandDoesNotUseMaskedSuccessForConditionalMutation(t *testing.T) {
	if facts := classifyCommand("false || rm victim.txt; true", "", true, testWorkspace()); facts != nil {
		t.Errorf("classifyCommand credited a mutation whose failure could be masked: %+v", facts)
	}
}

func TestClassifyCommandDoesNotUnwrapStatusControllingShellSuffix(t *testing.T) {
	commands := []string{
		"/bin/sh -lc 'rm nonexistent' || true",
		"/bin/bash -lc 'rm missing.txt' | true",
	}
	for _, command := range commands {
		if facts := classifyCommand(command, "", true, testWorkspace()); facts != nil {
			t.Errorf("classifyCommand(%q) = %+v, want nil: the outer status does not prove the inner deletion", command, facts)
		}
	}
}

// heredocDelimiter resolves only the first `<<` it finds. When a segment
// opens a second heredoc on the same line (`cat <<A <<B`), that second
// heredoc's body is still ahead of the first heredoc's closing line and gets
// misread as commands once it is found. The safe default, same as an
// unparseable delimiter or a missing terminator, is to credit nothing for
// the whole command.
func TestClassifyCommandAbandonsWholeCommandOnTwoHeredocsInOneSegment(t *testing.T) {
	command := "cat <<A <<B\nb1\nA\ncurl https://evil3.example.com\nB"
	if facts := classifyCommand(command, "", true, testWorkspace()); facts != nil {
		t.Fatalf("classifyCommand(%q) = %+v, want nil: the second heredoc's body is unresolved", command, facts)
	}
}

// The single-segment guard above only catches two openers written on the
// SAME segment. A chain that opens one heredoc per segment instead —
// `cat <<E1 > a && cat <<E2 > b` — hides the defect from that guard
// entirely: the first heredoc's body scan walks forward looking for E1's
// closing line and steps right over the second `cat <<E2` segment as if it
// were part of that body, so it is never even checked for an opener of its
// own. E2's real body then reaches every classifier as ordinary commands.
func TestClassifyCommandAbandonsWholeCommandOnTwoHeredocsAcrossSegments(t *testing.T) {
	cases := []struct {
		name    string
		command string
	}{
		{
			"second heredoc body reads as a network command",
			"cat <<E1 > a.txt && cat <<E2 > b.txt\nx\nE1\ncurl https://body.example\nE2",
		},
		{
			"second heredoc body reads as a search command",
			"cat <<E1 > a.txt && cat <<E2 > b.txt\nx\nE1\ngrep -rn SECRET_TOKEN_abc .\nE2",
		},
		{
			"second heredoc body reads as a verify command",
			"cat <<E1 > a.py && cat <<E2 > b.py\nx\nE1\ngo test ./...\nE2",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if facts := classifyCommand(c.command, "", true, testWorkspace()); facts != nil {
				t.Fatalf("classifyCommand(%q) = %+v, want nil: the second heredoc's body is unresolved", c.command, facts)
			}
		})
	}
}

// A trailing `&`, or the `a & b` async-separator spelling, backgrounds
// whatever ran before it: the shell reports the exit status of launching the
// job (always 0), never the backgrounded command's own. splitRawChain never
// splits the chain on a lone `&` (only `&&` is a real separator here), so
// without marking the segment itself async, its one reported exit code was
// wrongly treated as proof the backgrounded command succeeded.
func TestClassifyCommandSuppressesStateChangeAcrossBackground(t *testing.T) {
	cases := []struct {
		name           string
		command        string
		wantBackground bool
	}{
		{"trailing & on a delete", "rm -rf dist &", true},
		{"trailing & on a move", "mv a.txt b.txt &", true},
		{"a & b separator spelling", "rm nonexistent.txt & echo done", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts := classifyCommand(c.command, "", true, testWorkspace())
			if facts == nil {
				if c.wantBackground {
					t.Fatalf("classifyCommand(%q) credited nothing, want process.background", c.command)
				}
				return
			}
			if c.wantBackground && !slices.Contains(facts.categories, "process.background") {
				t.Errorf("categories = %v, want process.background", facts.categories)
			}
			if slices.Contains(facts.categories, "fs.delete") || slices.Contains(facts.categories, "fs.move") {
				t.Errorf("categories = %v, must not credit a state change: the reported exit status belongs to launching the background job, not the command", facts.categories)
			}
			if len(facts.mutations) != 0 {
				t.Errorf("mutations = %+v, want none: nothing is proven to have run to completion", facts.mutations)
			}
		})
	}
}

// A lone `&` is a list terminator, not merely a marker on the one segment it
// is found in: `a && b &` backgrounds the WHOLE `a && b` list as a single
// background job, so the one reported exit status proves nothing about `a`
// either, even though `a`'s own separator to `b` was `&&` and `a` contains no
// `&` of its own. splitCommandChain previously only widened orGated to the
// segment async was recorded on, leaving every earlier `&&`-joined segment in
// the list still credited off an exit status that belongs to launching the
// background job, not to them.
func TestClassifyCommandSuppressesStateChangeAcrossBackgroundedList(t *testing.T) {
	cases := []struct {
		name    string
		command string
	}{
		{"a delete before a trailing background &", "rm a.txt && rm b.txt &"},
		{"a create before a backgrounded build", "mkdir logs && npm run build &"},
		{"a longer && chain backgrounded only at the end", "rm a.txt && rm b.txt && rm c.txt &"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts := classifyCommand(c.command, "", true, testWorkspace())
			if facts == nil {
				t.Fatalf("classifyCommand(%q) credited nothing, want process.background", c.command)
			}
			if !slices.Contains(facts.categories, "process.background") {
				t.Errorf("categories = %v, want process.background", facts.categories)
			}
			if slices.Contains(facts.categories, "fs.delete") || slices.Contains(facts.categories, "fs.create") {
				t.Errorf("categories = %v, must not credit a state change: the reported exit status belongs to launching the backgrounded list's job, not to any segment inside it", facts.categories)
			}
			if len(facts.mutations) != 0 {
				t.Errorf("mutations = %+v, want none: nothing in the backgrounded list is proven to have run to completion", facts.mutations)
			}
		})
	}
}

// An escaped `>` or `<` is an ordinary argument character, not the first half
// of an fd-duplication operator. A live `&` immediately after it still
// backgrounds the whole preceding AND-list and revokes its exit-status proof.
func TestClassifyCommandDoesNotHideBackgroundAfterEscapedRedirection(t *testing.T) {
	for _, command := range []string{`rm a.txt && printf x\>&`, `rm a.txt && printf x\<&`} {
		facts := classifyCommand(command, "", true, testWorkspace())
		if facts == nil || !slices.Contains(facts.categories, "process.background") {
			t.Fatalf("classifyCommand(%q) = %+v, want process.background", command, facts)
		}
		if slices.Contains(facts.categories, "fs.delete") || len(facts.mutations) != 0 {
			t.Errorf("classifyCommand(%q) = %+v, want no deletion without foreground exit-status proof", command, facts)
		}
	}
}

// `2>&1` (fd duplication) and `&>`/`&>>` (redirect both streams) contain an
// unquoted `&` too, but neither backgrounds the command: the async detection
// must not treat every lone `&` as the detach operator, or an ordinary
// foreground command loses its credit for no reason the shell would agree
// with.
func TestClassifyCommandDoesNotTreatFdDuplicationAmpersandAsBackground(t *testing.T) {
	command := "rm -r dist 2>&1"
	facts := classifyCommand(command, "", true, testWorkspace())
	if facts == nil || !slices.Contains(facts.categories, "fs.delete") {
		t.Fatalf("classifyCommand(%q) = %+v, want fs.delete: 2>&1 duplicates a file descriptor, it does not background the command", command, facts)
	}
}

// changesWorkingDirectory previously required a real destination argument
// before recognising `cd`/`pushd`, so a bare `cd` (goes to $HOME) or a
// `popd` (pops the directory stack) left cwdUncertain unset even though both
// move the shell's cwd exactly as much as `cd sub` does — the one case the
// guard existed to catch.
func TestClassifyCommandTreatsBareCdAndPopdAsCwdUncertain(t *testing.T) {
	cases := []struct {
		name    string
		command string
	}{
		{"bare cd then a relative delete", "cd && rm -r build"},
		{"popd then a relative delete", "popd && rm -r build"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if facts := classifyCommand(c.command, "", true, testWorkspace()); facts != nil {
				t.Fatalf("classifyCommand(%q) = %+v, want nil for an unknown cwd", c.command, facts)
			}
		})
	}
}

func TestClassifyCommandTreatsPrefixedCdAsCwdUncertain(t *testing.T) {
	cases := []struct {
		name    string
		command string
	}{
		{"command prefix", "command cd sub && rm a.txt"},
		{"builtin prefix", "builtin cd sub && rm a.txt"},
		{"nested prefixes", "command builtin cd sub && rm a.txt"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts := classifyCommand(c.command, "", true, testWorkspace())
			if facts == nil || !reflect.DeepEqual(facts.categories, []string{"fs.delete"}) || len(facts.targets) != 0 || len(facts.mutations) != 0 {
				t.Fatalf("classifyCommand(%q) = %+v, want category-only fs.delete", c.command, facts)
			}
		})
	}
}

// An unquoted `#` starting a word begins a shell comment that runs to the end
// of that physical LINE only; nothing on the rest of the line ever executes.
// Before splitRawChain knew this, the comment text still got cut into fresh
// segments and handed to the classifiers as if it were a real, `&&`-proven
// chain.
func TestClassifyCommandStopsAtShellComment(t *testing.T) {
	commands := []string{
		"echo done # cleanup && rm -rf dist",
		"true;# do not run && rg ghp_SECRET_VALUE .",
	}
	for _, command := range commands {
		if facts := classifyCommand(command, "", true, testWorkspace()); facts != nil {
			t.Fatalf("classifyCommand(%q) = %+v, want nil: nothing after `#` on the same line ever ran", command, facts)
		}
	}
}

// A `#` comment ends only its own line, not the whole command: a shell still
// runs every line after it. Treating `#` as ending the entire scan — as
// splitRawChain once did — silently dropped every later line outright, and
// for a comment on an early line of a longer chain, it also erased the
// separators those later lines contributed to splitCommandChain's all-`&&`
// provenance check, laundering an unrelated later line's exit status onto
// the segment before the comment.
func TestClassifyCommandCommentEndsOnlyItsLine(t *testing.T) {
	t.Run("a newline after the comment still revokes proof, like an explicit one would", func(t *testing.T) {
		command := "rm -rf dist # tidy up\necho done"
		if facts := classifyCommand(command, "", true, testWorkspace()); facts != nil {
			t.Fatalf("classifyCommand(%q) = %+v, want nil: the newline after the comment still separates the chain", command, facts)
		}
	})
	t.Run("a leading comment line does not swallow the real command that follows it", func(t *testing.T) {
		command := "# install deps\nnpm install"
		facts := classifyCommand(command, "", true, testWorkspace())
		if facts == nil || !slices.Contains(facts.categories, "package.install") {
			t.Fatalf("classifyCommand(%q) = %+v, want package.install", command, facts)
		}
	})
	t.Run("an and operator before the comment still relates the next line", func(t *testing.T) {
		command := "rm stale.txt &&# explanation\ntrue"
		facts := classifyCommand(command, "", true, testWorkspace())
		if facts == nil || !slices.Contains(facts.categories, "fs.delete") {
			t.Fatalf("classifyCommand(%q) = %+v, want fs.delete: the comment does not consume the pending &&", command, facts)
		}
	})
}

// The same truncation that used to drop later lines outright also used to
// collapse a two-line command into one segment, which let trustedOutput
// treat the whole run's output as belonging to that single segment. Here
// that would have let gitProvenance read a sha out of `git log`'s output —
// printed by the second line, which never ran under proof — and publish it
// as `git rev-parse HEAD`'s own ref target.
func TestClassifyCommandCommentDoesNotLaunderProvenanceOutput(t *testing.T) {
	const secondSHA = "fedcba9876543210fedcba9876543210fedcba98"
	if len(secondSHA) != 40 {
		t.Fatalf("secondSHA fixture has %d hex digits, want 40", len(secondSHA))
	}
	command := "git rev-parse HEAD # note\ngit log --format=%H"
	output := testHeadSHA + "\n" + secondSHA + "\n"
	facts := classifyCommand(command, output, true, testWorkspace())
	if facts == nil || !slices.Contains(facts.categories, "vcs.provenance") {
		t.Fatalf("classifyCommand(%q) = %+v, want vcs.provenance (the command text alone still proves that)", command, facts)
	}
	if len(facts.targets) != 0 {
		t.Errorf("targets = %+v, want none: two segments means the output cannot be attributed to either one", facts.targets)
	}
}

// A `#` that is not preceded by whitespace (or at the very start of the
// command) is not a comment marker — it is just a character glued to a real
// word, e.g. inside a filename — and must not truncate the chain.
func TestClassifyCommandDoesNotTreatMidWordHashAsAComment(t *testing.T) {
	commands := []string{"rm file#1.txt", `rm file\;#1.txt`}
	for _, command := range commands {
		facts := classifyCommand(command, "", true, testWorkspace())
		if facts == nil || !slices.Contains(facts.categories, "fs.delete") {
			t.Fatalf("classifyCommand(%q) = %+v, want fs.delete: # mid-word is not a comment marker", command, facts)
		}
	}
}
