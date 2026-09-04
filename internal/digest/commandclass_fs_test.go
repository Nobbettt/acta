package digest

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// fsSegment builds the segment classifyFS receives for a single-segment
// command. It exercises the classifier directly so the expectations stay exact
// while the sibling classifiers grow their own categories.
func fsSegment(command string, exitOK bool) commandSegment {
	return commandSegment{
		raw:     command,
		tokens:  tokensForSegment(command),
		command: command,
		exitOK:  exitOK,
		ws:      testWorkspace(),
	}
}

func fsPathTargets(paths ...string) []CommandTarget {
	targets := make([]CommandTarget, 0, len(paths))
	for _, p := range paths {
		targets = append(targets, CommandTarget{Kind: "path", Value: p})
	}
	return targets
}

// fsSegmentCwdUncertain builds a segment as if an earlier `cd`/`pushd` in the
// same command had already made the shell's working directory unknown.
func fsSegmentCwdUncertain(command string, exitOK bool) commandSegment {
	seg := fsSegment(command, exitOK)
	seg.cwdUncertain = true
	return seg
}

func TestClassifyFS(t *testing.T) {
	cases := []struct {
		name    string
		command string
		exitOK  bool
		want    *commandFacts
	}{
		// fs.delete
		{"rm one file", "rm src/old.go", true, &commandFacts{
			categories: []string{"fs.delete"},
			targets:    fsPathTargets("src/old.go"),
			mutations:  []ShellMutation{{Kind: "delete", Path: "src/old.go"}},
		}},
		{"rm force withholds the runtime outcome", "rm -rf build", true, &commandFacts{
			categories: []string{"fs.delete"},
		}},
		{"rm interactive attempt withholds the outcome", "rm -i src/old.go", true, &commandFacts{
			categories: []string{"fs.delete"},
		}},
		{"rm prompt-once attempt withholds the outcome", "rm -I a.txt b.txt c.txt d.txt", true, &commandFacts{
			categories: []string{"fs.delete"},
		}},
		{"rm end of flags", "rm -- -weird.txt", true, &commandFacts{
			categories: []string{"fs.delete"},
			targets:    fsPathTargets("-weird.txt"),
			mutations:  []ShellMutation{{Kind: "delete", Path: "-weird.txt"}},
		}},
		{"rm several files", "rm a.txt src/b.txt", true, &commandFacts{
			categories: []string{"fs.delete"},
			targets:    fsPathTargets("a.txt", "src/b.txt"),
			mutations: []ShellMutation{
				{Kind: "delete", Path: "a.txt"},
				{Kind: "delete", Path: "src/b.txt"},
			},
		}},
		{"git rm", "git rm docs/old.md", true, &commandFacts{
			categories: []string{"fs.delete"},
			targets:    fsPathTargets("docs/old.md"),
			mutations:  []ShellMutation{{Kind: "delete", Path: "docs/old.md"}},
		}},
		{"rm absolute inside workspace", "rm /repo/src/old.go", true, &commandFacts{
			categories: []string{"fs.delete"},
			targets:    fsPathTargets("src/old.go"),
			mutations:  []ShellMutation{{Kind: "delete", Path: "src/old.go"}},
		}},
		{"failed rm deleted nothing", "rm src/old.go", false, nil},
		// A write the workspace does not contain is the escape itself: the
		// category is credited, but no target and no file.deleted event.
		{"rm outside the workspace", "rm /etc/hosts", true, &commandFacts{
			categories: []string{"workspace.escape"},
		}},
		{"rm above the workspace", "rm ../outside.txt", true, &commandFacts{
			categories: []string{"workspace.escape"},
		}},
		{"rm inside and outside at once", "rm a.txt /etc/hosts", true, &commandFacts{
			categories: []string{"fs.delete", "workspace.escape"},
			targets:    fsPathTargets("a.txt"),
			mutations:  []ShellMutation{{Kind: "delete", Path: "a.txt"}},
		}},
		{"a failed escaping rm deleted nothing and escaped nothing", "rm /etc/passwd", false, nil},
		{"rm flags only", "rm -rf", true, nil},
		{"rm unknown flag withholds targets and mutations", "rm --future-output report.txt victim.txt", true, &commandFacts{
			categories: []string{"fs.delete"},
		}},
		{"rm duplicate operand publishes one target", "rm old.txt old.txt", true, &commandFacts{
			categories: []string{"fs.delete"},
			targets:    fsPathTargets("old.txt"),
			mutations:  []ShellMutation{{Kind: "delete", Path: "old.txt"}},
		}},
		{"rm inside a quoted argument", `echo "rm -rf build"`, true, nil},
		{"rm as an echo argument", "echo rm -rf /", true, nil},
		{"rm with unbalanced quotes", `rm "src/old.go`, true, nil},
		{"rm of an unexpanded glob", "rm build/*.o", true, nil},
		// shellTokens has no $()/backtick awareness, so a command substitution
		// tokenizes into plain words. Without `(`/`)`/backtick in the reject set,
		// the non-`$` half of each of these reads as an ordinary path and gets
		// credited as one that was deleted, when nothing was.
		{"rm of a command substitution credits nothing", "rm $(cat list.txt)", true, nil},
		{"rm of a substitution glued to a path credits nothing", "rm dist/$(date +%F).log", true, nil},
		{"rm of a backtick substitution credits nothing", "rm `cat list.txt`", true, nil},
		// The trailing paren of `(cd frontend && rm -rf dist)` arrives glued to
		// "dist" in this segment's own token list; it must not be credited as
		// part of the path either.
		{"rm inside a subshell fragment credits nothing", "rm -rf dist)", true, nil},
		{"git rm behind a global flag", "git -C other/repo rm x.txt", true, nil},
		// `--cached`/`--staged` only untracks the path; the file is still on
		// disk, so nothing here proves a deletion.
		{"git rm --cached leaves the file on disk", "git rm --cached secrets.env", true, nil},
		{"git rm --cached -r leaves the tree on disk", "git rm --cached -r somedir", true, nil},
		{"git rm --staged leaves the file on disk", "git rm --staged config.json", true, nil},
		// A dry run asserts a deletion it did not make, the same false-positive
		// class as --cached/--staged, in both accepted spellings.
		{"git rm -n leaves the file on disk", "git rm -n src/old.go", true, nil},
		{"git rm clustered dry run leaves the file on disk", "git rm -nq tracked.txt", true, nil},
		{"git rm --dry-run leaves the file on disk", "git rm --dry-run src/old.go", true, nil},
		{"git rm pathspec file names no deleted path", "git rm --pathspec-from-file paths.txt", true, &commandFacts{
			categories: []string{"fs.delete"},
		}},
		{"git rm nul pathspec file names no deleted path", "git rm --pathspec-from-file=paths.txt --pathspec-file-nul", true, &commandFacts{
			categories: []string{"fs.delete"},
		}},
		{"rm help deletes nothing", "rm --help src/old.go", true, nil},
		{"rm attached help deletes nothing", "rm --help=all src/old.go", true, nil},
		// sudo and an env-assignment prefix must not hide the real verb.
		{"sudo rm", "sudo rm -rf node_modules", true, &commandFacts{
			categories: []string{"fs.delete"},
		}},
		{"sudo git rm", "sudo git rm docs/old.md", true, &commandFacts{
			categories: []string{"fs.delete"},
			targets:    fsPathTargets("docs/old.md"),
			mutations:  []ShellMutation{{Kind: "delete", Path: "docs/old.md"}},
		}},
		{"cp into the workspace root names the created file", "cp src/app.go .", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("app.go"),
		}},
		{"cp into the absolute workspace root names the created file", "cp src/app.go /repo/", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("app.go"),
		}},

		// fs.move
		// ORCHESTRATOR RULING: a plain two-operand cp/mv with no conditional
		// flag keeps its path. A destination that is secretly a pre-existing
		// directory is the accepted, documented assumption — calling the whole
		// form unprovable would mean file.moved is never emitted for any
		// command at all, deleting the fact instead of getting it right. `-f`
		// only suppresses the prompt, so it reads the same as the plain form.
		{"mv plain rename keeps its path", "mv old.txt src/new.txt", true, &commandFacts{
			categories: []string{"fs.move"},
			targets:    []CommandTarget{{Kind: "path", Value: "old.txt"}, {Kind: "path", Value: "src/new.txt"}},
			mutations:  []ShellMutation{{Kind: "move", From: "old.txt", To: "src/new.txt"}},
		}},
		{"mv force reads like the plain form", "mv -f old.txt new.txt", true, &commandFacts{
			categories: []string{"fs.move"},
			targets:    []CommandTarget{{Kind: "path", Value: "old.txt"}, {Kind: "path", Value: "new.txt"}},
			mutations:  []ShellMutation{{Kind: "move", From: "old.txt", To: "new.txt"}},
		}},
		{"mv no-clobber keeps only the attempted category", "mv -n old.txt new.txt", true, &commandFacts{
			categories: []string{"fs.move"},
		}},
		{"mv long no-clobber keeps only the attempted category", "mv --no-clobber old.txt new.txt", true, &commandFacts{
			categories: []string{"fs.move"},
		}},
		{"mv update keeps only the attempted category", "mv -u old.txt new.txt", true, &commandFacts{
			categories: []string{"fs.move"},
		}},
		{"mv long update keeps only the attempted category", "mv --update old.txt new.txt", true, &commandFacts{
			categories: []string{"fs.move"},
		}},
		{"mv interactive keeps only the attempted category", "mv -i old.txt new.txt", true, &commandFacts{
			categories: []string{"fs.move"},
		}},
		{"mv long interactive keeps only the attempted category", "mv --interactive old.txt new.txt", true, &commandFacts{
			categories: []string{"fs.move"},
		}},
		{"mv no-target-directory proves the destination", "mv -T old.txt new.txt", true, &commandFacts{
			categories: []string{"fs.move"},
			targets:    fsPathTargets("old.txt", "new.txt"),
			mutations:  []ShellMutation{{Kind: "move", From: "old.txt", To: "new.txt"}},
		}},
		{"mv long no-target-directory proves the destination", "mv --no-target-directory old.txt new.txt", true, &commandFacts{
			categories: []string{"fs.move"},
			targets:    fsPathTargets("old.txt", "new.txt"),
			mutations:  []ShellMutation{{Kind: "move", From: "old.txt", To: "new.txt"}},
		}},
		{"failed mv moved nothing", "mv old.txt new.txt", false, nil},
		{"mv help moves nothing", "mv -h old.txt new.txt", true, nil},
		{"mv into an unproven directory keeps only the category", "mv a.txt b.txt archive", true, &commandFacts{
			categories: []string{"fs.move"},
		}},
		{"mv out of the workspace", "mv old.txt /tmp/new.txt", true, &commandFacts{
			categories: []string{"workspace.escape"},
		}},
		{"mv flags only", "mv -v", true, nil},
		{"mv unknown flag withholds targets and mutations", "mv --future-output=report.txt old.txt new.txt", true, &commandFacts{
			categories: []string{"fs.move"},
		}},
		{"mv inside a quoted argument", `echo "mv a.txt b.txt"`, true, nil},
		{"FORCE=1 mv", "FORCE=1 mv old.txt new.txt", true, &commandFacts{
			categories: []string{"fs.move"},
			targets:    []CommandTarget{{Kind: "path", Value: "old.txt"}, {Kind: "path", Value: "new.txt"}},
			mutations:  []ShellMutation{{Kind: "move", From: "old.txt", To: "new.txt"}},
		}},
		// A trailing slash on the destination is mv's own proof that it is a
		// directory: mv refuses that form unless the directory already exists,
		// so a successful exit means the file landed at dir/basename(src), never
		// at the directory path itself.
		{"mv into a directory names the real destination", "mv internal/old.go internal/digest/", true, &commandFacts{
			categories: []string{"fs.move"},
			targets:    fsPathTargets("internal/old.go", "internal/digest/old.go"),
			mutations:  []ShellMutation{{Kind: "move", From: "internal/old.go", To: "internal/digest/old.go"}},
		}},
		{"mv a file into a bare directory", "mv a.txt docs/", true, &commandFacts{
			categories: []string{"fs.move"},
			targets:    fsPathTargets("a.txt", "docs/a.txt"),
			mutations:  []ShellMutation{{Kind: "move", From: "a.txt", To: "docs/a.txt"}},
		}},
		{"mv into a dot-suffixed directory names the real destination", "mv src.txt dest/.", true, &commandFacts{
			categories: []string{"fs.move"},
			targets:    fsPathTargets("src.txt", "dest/src.txt"),
			mutations:  []ShellMutation{{Kind: "move", From: "src.txt", To: "dest/src.txt"}},
		}},
		{"mv into a directory outside the workspace escapes", "mv old.txt /tmp/", true, &commandFacts{
			categories: []string{"workspace.escape"},
		}},
		{"mv into the workspace root names the moved file", "mv old/x.go .", true, &commandFacts{
			categories: []string{"fs.move"},
			targets:    fsPathTargets("old/x.go", "x.go"),
			mutations:  []ShellMutation{{Kind: "move", From: "old/x.go", To: "x.go"}},
		}},
		{"mv into the absolute workspace root names the moved file", "mv old/x.go /repo/", true, &commandFacts{
			categories: []string{"fs.move"},
			targets:    fsPathTargets("old/x.go", "x.go"),
			mutations:  []ShellMutation{{Kind: "move", From: "old/x.go", To: "x.go"}},
		}},
		// GNU mv's -t/--target-directory names the destination directory
		// explicitly, just like cp's; before this fix fsMove had no notion of
		// it, so fsOperands's flag-stripping left the directory in operands[0]
		// and the real source in operands[1], reporting the move backwards.
		{"mv -t credits the real destination, not the reverse", "mv -t archive notes.md", true, &commandFacts{
			categories: []string{"fs.move"},
			targets:    fsPathTargets("notes.md", "archive/notes.md"),
			mutations:  []ShellMutation{{Kind: "move", From: "notes.md", To: "archive/notes.md"}},
		}},
		{"mv -t with a trailing slash on the target directory", "mv -t archive/ notes.md", true, &commandFacts{
			categories: []string{"fs.move"},
			targets:    fsPathTargets("notes.md", "archive/notes.md"),
			mutations:  []ShellMutation{{Kind: "move", From: "notes.md", To: "archive/notes.md"}},
		}},
		{"mv --target-directory= credits the real destination", "mv --target-directory=archive notes.md", true, &commandFacts{
			categories: []string{"fs.move"},
			targets:    fsPathTargets("notes.md", "archive/notes.md"),
			mutations:  []ShellMutation{{Kind: "move", From: "notes.md", To: "archive/notes.md"}},
		}},
		// -t's value can also be glued directly to the flag (GNU getopt accepts
		// a short option's argument attached, no separate token or "=" needed).
		{"mv -t attached credits the real destination", "mv -tarchive notes.md", true, &commandFacts{
			categories: []string{"fs.move"},
			targets:    fsPathTargets("notes.md", "archive/notes.md"),
			mutations:  []ShellMutation{{Kind: "move", From: "notes.md", To: "archive/notes.md"}},
		}},
		{"mv -t attached equals preserves the literal directory name", "mv -t=archive notes.md", true, &commandFacts{
			categories: []string{"fs.move"},
			targets:    fsPathTargets("notes.md", "=archive/notes.md"),
			mutations:  []ShellMutation{{Kind: "move", From: "notes.md", To: "=archive/notes.md"}},
		}},
		{"mv -t with multiple sources credits each move", "mv -t archive a.txt b.txt", true, &commandFacts{
			categories: []string{"fs.move"},
			targets:    fsPathTargets("a.txt", "archive/a.txt", "b.txt", "archive/b.txt"),
			mutations: []ShellMutation{
				{Kind: "move", From: "a.txt", To: "archive/a.txt"},
				{Kind: "move", From: "b.txt", To: "archive/b.txt"},
			},
		}},
		{"mv -t with no source credits nothing", "mv -t archive", true, nil},
		{"mv -t with no value proves no destination", "mv a.txt -t", true, nil},
		{"mv -t out of the workspace escapes", "mv -t /tmp notes.md", true, &commandFacts{
			categories: []string{"workspace.escape"},
		}},
		// A pipeline tail's own -t must not be mistaken for mv's: `xargs -t` here
		// belongs to the downstream stage, so this is still the plain two-operand
		// rename a.txt -> b.txt, not a move into a directory named "archive".
		{"mv piped does not inherit the pipeline tail's -t", "mv a.txt b.txt | xargs -t archive", true, &commandFacts{
			categories: []string{"fs.move"},
			targets:    fsPathTargets("a.txt", "b.txt"),
			mutations:  []ShellMutation{{Kind: "move", From: "a.txt", To: "b.txt"}},
		}},
		// -S/--suffix takes a value too; before this fix its value leaked into
		// mv's operand list, so a real two-operand rename with a trailing -S
		// flag was silently missed (3 "operands" instead of 2).
		{"mv -S does not swallow a real two-operand rename", "mv a.txt b.txt -S .bak", true, &commandFacts{
			categories: []string{"fs.move"},
			targets:    fsPathTargets("a.txt", "b.txt"),
			mutations:  []ShellMutation{{Kind: "move", From: "a.txt", To: "b.txt"}},
		}},
		{"mv suffix value is not rescanned for target-directory flags", "mv -bS.test old.go new.go", true, &commandFacts{
			categories: []string{"fs.move"},
			targets:    []CommandTarget{{Kind: "path", Value: "old.go"}, {Kind: "path", Value: "new.go"}},
			mutations:  []ShellMutation{{Kind: "move", From: "old.go", To: "new.go"}},
		}},
		// `src/.` normalises to `src` once fsPaths cleans it, but mv does not
		// move src ITSELF into the directory when the source is spelled this
		// way; nothing in the command text proves what dir/basename(src) would
		// even mean here, so the category is credited alone, with no
		// synthesised destination path and no move mutation.
		{"mv of a dot-suffixed source names no destination", "mv src/. backup/", true, &commandFacts{
			categories: []string{"fs.move"},
		}},

		// fs.create
		// Same ruling as mv above: the plain two-operand form keeps its path.
		{"cp plain copy keeps its path", "cp src/a.go src/b.go", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    []CommandTarget{{Kind: "path", Value: "src/b.go"}},
		}},
		{"cp recursive keeps its path", "cp -r src backup", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    []CommandTarget{{Kind: "path", Value: "backup"}},
		}},
		{"cp force reads like the plain form", "cp -f source.txt dest.txt", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("dest.txt"),
		}},
		{"cp no-clobber keeps only the attempted category", "cp -n source.txt dest.txt", true, &commandFacts{
			categories: []string{"fs.create"},
		}},
		{"cp long no-clobber keeps only the attempted category", "cp --no-clobber source.txt dest.txt", true, &commandFacts{
			categories: []string{"fs.create"},
		}},
		{"cp update keeps only the attempted category", "cp -u source.txt dest.txt", true, &commandFacts{
			categories: []string{"fs.create"},
		}},
		{"cp long update keeps only the attempted category", "cp --update source.txt dest.txt", true, &commandFacts{
			categories: []string{"fs.create"},
		}},
		{"cp interactive keeps only the attempted category", "cp -i source.txt dest.txt", true, &commandFacts{
			categories: []string{"fs.create"},
		}},
		{"cp long interactive keeps only the attempted category", "cp --interactive source.txt dest.txt", true, &commandFacts{
			categories: []string{"fs.create"},
		}},
		{"cp no-target-directory proves the destination", "cp -T source.txt dest.txt", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("dest.txt"),
		}},
		{"cp long no-target-directory proves the destination", "cp --no-target-directory source.txt dest.txt", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("dest.txt"),
		}},
		{"touch credits every file", "touch a.txt docs/b.md", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("a.txt", "docs/b.md"),
		}},
		{"touch no-create proves no creation", "touch -c absent.txt", true, nil},
		{"touch long no-create proves no creation", "touch --no-create absent.txt", true, nil},
		{"mkdir parents keeps only the attempted category", "mkdir -p src/new/pkg", true, &commandFacts{
			categories: []string{"fs.create"},
		}},
		{"mkdir without parents proves the directory", "mkdir src/new/pkg", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("src/new/pkg"),
		}},
		{"failed mkdir created nothing", "mkdir -p src/new/pkg", false, nil},
		{"cp without a destination", "cp only.txt", true, nil},
		// Only the destination is written, so only it can escape.
		{"cp out of the workspace", "cp src/a.go /tmp/a.go", true, &commandFacts{
			categories: []string{"workspace.escape"},
		}},
		{"cp from outside into the workspace", "cp /tmp/a.go src/a.go", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    []CommandTarget{{Kind: "path", Value: "src/a.go"}},
		}},
		{"touch flags only", "touch -c", true, nil},
		{"touch inside a quoted argument", `echo "touch a.txt"`, true, nil},
		// GNU cp's -t/--target-directory names the destination explicitly; cp
		// refuses that form unless the named directory already exists, so the
		// real destination of each source is dir/basename(src) — never the
		// directory path itself, which this command provably did not create.
		{"cp -t credits each real destination inside the named directory", "cp -t backup a.txt b.txt", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("backup/a.txt", "backup/b.txt"),
		}},
		{"cp --target-directory= credits each real destination inside the named directory", "cp --target-directory=backup a.txt b.txt", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("backup/a.txt", "backup/b.txt"),
		}},
		{"cp -t attached credits each real destination inside the named directory", "cp -tbackup a.txt b.txt", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("backup/a.txt", "backup/b.txt"),
		}},
		{"cp -t attached equals preserves the literal directory name", "cp -t=backup a.txt b.txt", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("=backup/a.txt", "=backup/b.txt"),
		}},
		{"cp attached target value is not reparsed as flags", "cp -tdist a.txt b.txt", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("dist/a.txt", "dist/b.txt"),
		}},
		{"cp version creates nothing", "cp --version a.txt b.txt", true, nil},
		{"cp -t with no value proves no destination", "cp a.txt b.txt -t", true, nil},
		{"cp -t with no source credits nothing", "cp -t backup", true, nil},
		// A trailing slash on cp's sole destination operand is its own proof
		// that the destination is a directory, exactly as it is for mv: cp
		// refuses that form unless the directory already exists.
		{"cp into a directory names the real destination", "cp a.txt backup/", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("backup/a.txt"),
		}},
		{"cp into a dot-suffixed directory names the real destination", "cp a.txt backup/.", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("backup/a.txt"),
		}},
		{"cp into a directory outside the workspace escapes", "cp a.txt /tmp/", true, &commandFacts{
			categories: []string{"workspace.escape"},
		}},
		// A pipeline tail's own -t must not be mistaken for cp's: `xargs -t` here
		// belongs to the downstream stage, so this is still the plain
		// two-operand copy a.txt -> b.txt, not a copy into a directory named
		// "rm".
		{"cp piped does not inherit the pipeline tail's -t", "cp a.txt b.txt | xargs -t rm", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("b.txt"),
		}},
		// With more than one source, the trailing slash still names each
		// source's real destination inside the directory — never the
		// pre-existing directory path itself, which nothing was written to.
		{"cp several sources into a directory credits each real destination", "cp a.txt b.txt backup/", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("backup/a.txt", "backup/b.txt"),
		}},
		{"cp three sources into a directory credits each real destination", "cp a.txt b.txt c.txt dest/", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("dest/a.txt", "dest/b.txt", "dest/c.txt"),
		}},
		// Without a trailing slash, cp still requires dest to already exist as
		// a directory for this form — but nothing in the command text proves
		// that shape, and the files actually written would be dest/a.txt and
		// dest/b.txt, never a path named "dest" itself.
		{"cp three sources with no trailing slash keeps only the category", "cp a.txt b.txt c.txt dest", true, &commandFacts{
			categories: []string{"fs.create"},
		}},
		// `-a src/.` copies the CONTENTS of src into backup/, creating no
		// backup/src at all. fsPaths cleans `src/.` to `src` before this
		// classifier ever sees it, so dir/basename(src) would otherwise name a
		// path the command never wrote — the category is credited alone
		// instead, with no synthesised target.
		{"cp -a of a dot-suffixed source names no destination", "cp -a src/. backup/", true, &commandFacts{
			categories: []string{"fs.create"},
		}},
		{"cp parents withholds its derived destination", "cp --parents src/a.txt backup/", true, &commandFacts{
			categories: []string{"fs.create"},
		}},
		{"cp unmodeled option withholds its destination", "cp --backup=simple src/a.txt backup/a.txt", true, &commandFacts{
			categories: []string{"fs.create"},
		}},
		// mkdir/touch/mv/cp flags that take a separate value must not leak that
		// value into the operand list — a mode, a timestamp or a reference file
		// is not a path this command created.
		{"mkdir -m does not credit the mode as a created path", "mkdir -m 755 secure", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("secure"),
		}},
		{"mkdir unknown flag withholds targets", "mkdir --future-mode=700 secure", true, &commandFacts{
			categories: []string{"fs.create"},
		}},
		{"touch -r does not credit the reference file as created", "touch -r ref.txt new.txt", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("new.txt"),
		}},
		{"touch -t does not credit the timestamp as a path", "touch -t 202401010000 notes.md", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("notes.md"),
		}},
		{"touch BSD adjustment is not a path", "touch -A 0100 file.txt", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("file.txt"),
		}},
		{"touch long BSD adjustment is not a path", "touch -A 010000 notes.md", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("notes.md"),
		}},
		{"touch unmodeled option withholds its path", "touch --no-dereference notes.md", true, &commandFacts{
			categories: []string{"fs.create"},
		}},
		{"touch -d does not credit the date as a path", "touch -d 2024-01-01 notes.md", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("notes.md"),
		}},
		{"touch --time does not credit the selector as a path", "touch --time atime marker", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("marker"),
		}},
		{"touch attached time selector is not a path", "touch --time=atime marker", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("marker"),
		}},
		// Placed after the real operands so the pre-fix bug (no value-flag
		// table) would have credited the suffix value as the destination.
		{"cp -S does not credit the suffix as the destination", "cp a.txt b.txt -S .bak", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("b.txt"),
		}},
		// A value-taking short flag clustered with others (e.g. -pm, -amr, -rt)
		// must not leak its value into the operand list either — the value
		// scanner previously only recognised the flag spelled on its own.
		{"mkdir -pm does not credit the mode as a created path when clustered", "mkdir -pm 700 new", true, &commandFacts{
			categories: []string{"fs.create"},
		}},
		{"touch -amr does not credit the reference file as created when clustered", "touch -amr ref.txt new.txt", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("new.txt"),
		}},
		{"cp -rt credits each real destination when clustered", "cp -rt backup a.txt b.txt", true, &commandFacts{
			categories: []string{"fs.create"},
			targets:    fsPathTargets("backup/a.txt", "backup/b.txt"),
		}},

		// fs.patch
		{"patch with the file named and the diff on stdin", "patch src/foo.go < fix.diff", true, &commandFacts{
			categories: []string{"fs.patch"},
			targets:    fsPathTargets("src/foo.go"),
			mutations:  []ShellMutation{{Kind: "patch", Path: "src/foo.go"}},
		}},
		{"patch with the paths in the diff body", "patch -p1 < fix.diff", true, &commandFacts{
			categories: []string{"fs.patch"},
		}},
		{"patch separate strip count is not a patched path", "patch -p 1 < fix.diff", true, &commandFacts{
			categories: []string{"fs.patch"},
		}},
		{"patch check mode applies nothing", "patch -C orig.txt < fix.diff", true, nil},
		{"patch ifdef symbol is not a patched path", "patch -D SYMBOL < fix.diff", true, &commandFacts{
			categories: []string{"fs.patch"},
		}},
		{"patch long ifdef symbol is not a patched path", "patch --ifdef SYMBOL < fix.diff", true, &commandFacts{
			categories: []string{"fs.patch"},
		}},
		{"patch unmodeled option withholds its path", "patch --merge=diff3 orig.txt < fix.diff", true, &commandFacts{
			categories: []string{"fs.patch"},
		}},
		{"patch version-control value does not become a version probe", "patch -V never orig.txt < fix.diff", true, &commandFacts{
			categories: []string{"fs.patch"},
			targets:    fsPathTargets("orig.txt"),
			mutations:  []ShellMutation{{Kind: "patch", Path: "orig.txt"}},
		}},
		{"patch long strip count is not a patched path", "patch --strip 1 < fix.diff", true, &commandFacts{
			categories: []string{"fs.patch"},
		}},
		// --output/-o (in any spelling) sends the rewrite to a different file,
		// so the sole remaining operand is the UNTOUCHED original, not the file
		// patch actually wrote — crediting it as a target/mutation would report
		// a file.patched event for a file that was never modified.
		{"patch --output= does not credit the untouched input file", "patch --output=new.txt orig.txt < fix.diff", true, &commandFacts{
			categories: []string{"fs.patch"},
		}},
		{"patch -o attached does not credit the untouched input file", "patch -onew.txt orig.txt < fix.diff", true, &commandFacts{
			categories: []string{"fs.patch"},
		}},
		{"patch -o clustered does not credit the untouched input file", "patch -Nfo new.txt orig.txt < fix.diff", true, &commandFacts{
			categories: []string{"fs.patch"},
		}},
		// The separate-token spelling must follow the same output rule after its
		// value is consumed by the flag scanner.
		{"patch -o separate token still proves no target", "patch -o new.txt orig.txt < fix.diff", true, &commandFacts{
			categories: []string{"fs.patch"},
		}},
		{"patch stdout output changes no file", "patch -o - orig.txt < fix.diff", true, nil},
		{"patch dev-null output changes no file", "patch --output=/dev/null orig.txt < fix.diff", true, nil},
		{"patch dev-zero output changes no workspace file", "patch --output=/dev/zero orig.txt < fix.diff", true, nil},
		{"patch cleaned device alias changes no workspace file", "patch --output=/dev/../dev/null orig.txt < fix.diff", true, nil},
		{"patch outside output changes no workspace file", "patch --output=/tmp/new.txt orig.txt < fix.diff", true, nil},
		{"patch dev-stdout output changes no file", "patch -o /dev/stdout orig.txt < fix.diff", true, nil},
		{"patch dev-stderr output changes no file", "patch --output=/dev/stderr orig.txt < fix.diff", true, nil},
		{"patch fd output changes no workspace file", "patch -o /dev/fd/3 orig.txt < fix.diff", true, nil},
		// -d/--directory (in any spelling) chdirs before applying, so the real
		// rewritten path is dir/orig.txt, never the workspace-root orig.txt this
		// classifier would otherwise credit.
		{"patch --directory= does not credit the root-relative path", "patch --directory=frontend orig.txt < fix.diff", true, &commandFacts{
			categories: []string{"fs.patch"},
		}},
		{"patch -d attached does not credit the root-relative path", "patch -dfrontend orig.txt < fix.diff", true, &commandFacts{
			categories: []string{"fs.patch"},
		}},
		{"patch -d separate token does not credit the root-relative path", "patch -d frontend orig.txt < fix.diff", true, &commandFacts{
			categories: []string{"fs.patch"},
		}},
		{"patch --directory separate token does not credit the root-relative path", "patch --directory frontend orig.txt < fix.diff", true, &commandFacts{
			categories: []string{"fs.patch"},
		}},
		{"patch from a heredoc", "patch -p1 <<'EOF'", true, &commandFacts{
			categories: []string{"fs.patch"},
		}},
		{"git apply names the patch not the files", "git apply fix.diff", true, &commandFacts{
			categories: []string{"fs.patch"},
		}},
		{"git cherry-pick names a commit", "git cherry-pick 1a2b3c4", true, &commandFacts{
			categories: []string{"fs.patch"},
		}},
		{"git revert names a commit", "git revert HEAD", true, &commandFacts{
			categories: []string{"fs.patch"},
		}},
		{"failed patch applied nothing", "patch src/foo.go < fix.diff", false, nil},
		{"git apply --check only inspects", "git apply --check fix.diff", true, nil},
		{"patch usage changes nothing", "patch --usage orig.txt < fix.diff", true, nil},
		{"patch lowercase version probe changes nothing", "patch -v", true, nil},
		{"git apply help changes nothing", "git apply --help fix.diff", true, nil},
		{"git revert --abort applies nothing", "git revert --abort", true, nil},
		{"patch out of the workspace still has no path", "patch /tmp/foo.go < fix.diff", true, &commandFacts{
			categories: []string{"fs.patch"},
		}},
		{"patch inside a quoted argument", `echo "git apply fix.diff"`, true, nil},
		// A pipeline tail's own flag must not be mistaken for one of
		// fsInspectFlags: `grep --stat` here belongs to the downstream stage, so
		// this patch still applied, and the file it named is still credited.
		{"patch piped does not inherit the pipeline tail's --stat", "patch foo.go < fix.diff | grep --stat", true, &commandFacts{
			categories: []string{"fs.patch"},
			targets:    fsPathTargets("foo.go"),
			mutations:  []ShellMutation{{Kind: "patch", Path: "foo.go"}},
		}},

		// not a filesystem verb at all
		{"git status", "git status", true, nil},
		{"empty segment", "", true, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyFS(fsSegment(c.command, c.exitOK))
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("classifyFS(%q, exitOK=%v) = %+v, want %+v", c.command, c.exitOK, got, c.want)
			}
		})
	}
}

func TestClassifyCommandWithholdsConditionalFSValues(t *testing.T) {
	cases := []struct {
		command  string
		category string
	}{
		{"rm -f missing.txt", "fs.delete"},
		{"rm -i old.txt", "fs.delete"},
		{"mv -u old.txt new.txt", "fs.move"},
		{"cp -u source.txt dest.txt", "fs.create"},
		{"mkdir -p existing", "fs.create"},
	}
	for _, test := range cases {
		t.Run(test.command, func(t *testing.T) {
			facts := classifyCommand(test.command, "", true, testWorkspace())
			if facts == nil || !reflect.DeepEqual(facts.categories, []string{test.category}) {
				t.Fatalf("categories = %+v, want only %q", facts, test.category)
			}
			if len(facts.targets) != 0 || len(facts.mutations) != 0 {
				t.Fatalf("conditional facts = %+v, want category only", facts)
			}
		})
	}
}

func TestFSOperands(t *testing.T) {
	cases := []struct {
		name       string
		verb       string
		args       []string
		want       []string
		redirected bool
	}{
		{"flags dropped", "rm", []string{"-rf", "build"}, []string{"build"}, false},
		{"end of flags", "rm", []string{"--", "-weird.txt"}, []string{"-weird.txt"}, false},
		{"stdin redirect ends the operands", "patch", []string{"foo.go", "<", "fix.diff"}, []string{"foo.go"}, true},
		{"attached redirect", "patch", []string{"foo.go", "<fix.diff"}, []string{"foo.go"}, true},
		{"heredoc", "patch", []string{"-p1", "<<EOF"}, nil, true},
		{"stderr redirect", "rm", []string{"a.txt", "2>", "/dev/null"}, []string{"a.txt"}, true},
		{"no arguments", "rm", nil, nil, false},
		{"trailing ampersand backgrounds the command", "rm", []string{"-rf", "node_modules", "&"}, []string{"node_modules"}, false},
		{"pipe hands off to the next command", "rm", []string{"old.log", "|", "tee", "cleanup.log"}, []string{"old.log"}, false},
		{"pipe-with-stderr hands off too", "rm", []string{"old.log", "|&", "tee", "cleanup.log"}, []string{"old.log"}, false},
		// fsValueFlags: a verb's flag value must not be mistaken for one of its
		// own operands.
		{"mkdir -m skips the mode value", "mkdir", []string{"-m", "755", "secure"}, []string{"secure"}, false},
		{"touch -r skips the reference file", "touch", []string{"-r", "ref.txt", "new.txt"}, []string{"new.txt"}, false},
		{"touch -A skips the adjustment", "touch", []string{"-A", "0100", "new.txt"}, []string{"new.txt"}, false},
		{"mv -S skips the suffix value", "mv", []string{"a.txt", "b.txt", "-S", ".bak"}, []string{"a.txt", "b.txt"}, false},
		{"git rm skips the pathspec file", "git rm", []string{"--pathspec-from-file", "paths.txt"}, nil, false},
		{"patch skips the ifdef symbol", "patch", []string{"-D", "SYMBOL"}, nil, false},
		// A verb with no entry in fsValueFlags treats every flag as a bare
		// switch, exactly as before this map existed.
		{"a verb with no value-flag table is unaffected", "rm", []string{"-m", "755"}, []string{"755"}, false},
		// A clustered value flag consumes the next token as its value, exactly
		// as the flag spelled on its own already does.
		{"mkdir -pm skips the mode value even clustered", "mkdir", []string{"-pm", "700", "new"}, []string{"new"}, false},
		{"touch -amr skips the reference value even clustered", "touch", []string{"-amr", "ref.txt", "new.txt"}, []string{"new.txt"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, redirected := fsOperands(c.verb, c.args)
			if !reflect.DeepEqual(got, c.want) || redirected != c.redirected {
				t.Errorf("fsOperands(%q, %q) = %q,%v want %q,%v", c.verb, c.args, got, redirected, c.want, c.redirected)
			}
		})
	}
}

func TestScanCommandArgsArity(t *testing.T) {
	model := commandFlagModel{
		"-q": flagBoolean, "-f": flagValue, "--file": flagValue,
		"--lease": flagAttachedValue,
	}
	cases := []struct {
		name     string
		args     []string
		operands []string
		value    string
	}{
		{"long separate", []string{"--file", "value", "target"}, []string{"target"}, "value"},
		{"long attached", []string{"--file=value", "target"}, []string{"target"}, "value"},
		{"short separate", []string{"-f", "value", "target"}, []string{"target"}, "value"},
		{"short attached", []string{"-fvalue", "target"}, []string{"target"}, "value"},
		{"short attached equals is literal", []string{"-f=value", "target"}, []string{"target"}, "=value"},
		{"clustered final value", []string{"-qf", "value", "target"}, []string{"target"}, "value"},
		{"attached-only does not consume next", []string{"--lease", "target"}, []string{"target"}, ""},
		{"attached-only accepts equals", []string{"--lease=main", "target"}, []string{"target"}, "main"},
		{"unknown short spelling stays opaque", []string{"-xforce", "target"}, []string{"target"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			scan := scanCommandArgs(c.args, model)
			if !reflect.DeepEqual(scan.operands, c.operands) {
				t.Fatalf("operands = %q, want %q", scan.operands, c.operands)
			}
			if strings.HasPrefix(c.name, "unknown") {
				if !scan.unknownFlag || len(scan.flags) != 1 || scan.flags[0].name != "-xforce" {
					t.Fatalf("flags = %+v, want one opaque unknown flag", scan.flags)
				}
				return
			}
			if value, _ := scan.flagValue("-f", "--file", "--lease"); value != c.value {
				t.Fatalf("value = %q, want %q", value, c.value)
			}
		})
	}
}

func TestScanCommandArgsPreservesProvenPrefixBeforeUnknownClusterSuffix(t *testing.T) {
	scan := scanCommandArgs([]string{"-hx", "definitely-missing.zip"}, execUnzipFlagModel)
	if !scan.unknownFlag || !scan.hasFlag("-h") {
		t.Fatalf("scanCommandArgs(-hx) = %+v, want unknown suffix with preserved -h", scan)
	}
	if facts := classifyExec(fsSegment("unzip -hx definitely-missing.zip", true)); facts != nil {
		t.Fatalf("unzip -hx classified as %+v, want nil help invocation", facts)
	}
}

func TestAttachedSearchPatternPreservesLeadingEquals(t *testing.T) {
	for _, word := range []string{"grep", "rg"} {
		if got := execSearchPattern(word, []string{"-e=needle"}); got != "=needle" {
			t.Errorf("execSearchPattern(%q, -e=needle) = %q, want =needle", word, got)
		}
	}
}

func TestOutputTargetsWorkspaceFile(t *testing.T) {
	ws := testWorkspace()
	for _, destination := range []string{"", "-", "/dev/null", "/dev/zero", "/dev/../dev/null", "/dev/stdout", "/dev/stderr", "/dev/fd/0", "/dev/fd/12", "/tmp/report.txt", "../report.txt", "$OUTPUT"} {
		if outputTargetsWorkspaceFile(destination, ws, false) {
			t.Errorf("outputTargetsWorkspaceFile(%q) = true, want false", destination)
		}
	}
	for _, destination := range []string{"report.txt", "/repo/report.txt", "dev/fd/name"} {
		if !outputTargetsWorkspaceFile(destination, ws, false) {
			t.Errorf("outputTargetsWorkspaceFile(%q) = false, want true", destination)
		}
	}
	if outputTargetsWorkspaceFile("report.txt", ws, true) {
		t.Error("relative destination with uncertain cwd = true, want false")
	}
}

func TestDisabledBooleanFlagsDoNotEnableModes(t *testing.T) {
	cases := []struct {
		name      string
		command   string
		want      string
		forbidden string
	}{
		{"npm global false stays local", "npm install --global=false left-pad", "package.install", "workspace.escape"},
		{"compose detach false stays foreground", "docker compose up --detach=false", "container.run", "process.background"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts := classifyCommand(c.command, "", true, testWorkspace())
			if facts == nil || !slices.Contains(facts.categories, c.want) || slices.Contains(facts.categories, c.forbidden) {
				t.Fatalf("classifyCommand(%q) = %+v, want %s without %s", c.command, facts, c.want, c.forbidden)
			}
		})
	}
}

// TestFSOwnArgs covers fsOwnArgs directly: a flag scanner that reads its
// verb's own arguments (fsCopyTargetFlag, fsPatch's inspect-flag scan, the
// git-rm --cached/--staged check) must stop at the same points fsOperands
// already stops collecting operands at, or a downstream pipeline stage's own
// flag is mistaken for this verb's.
func TestFSOwnArgs(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"no stopping token returns args unchanged", []string{"-t", "backup", "a.txt"}, []string{"-t", "backup", "a.txt"}},
		{"pipe truncates the tail", []string{"a.txt", "b.txt", "|", "xargs", "-t", "rm"}, []string{"a.txt", "b.txt"}},
		{"pipe-with-stderr truncates the tail", []string{"a.txt", "|&", "tee", "-t"}, []string{"a.txt"}},
		{"background truncates the tail", []string{"a.txt", "&", "-t", "later"}, []string{"a.txt"}},
		{"redirect truncates the tail", []string{"foo.go", "<", "fix.diff", "|", "grep", "--stat"}, []string{"foo.go"}},
		{"no arguments", nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := fsOwnArgs(c.args)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("fsOwnArgs(%q) = %q, want %q", c.args, got, c.want)
			}
		})
	}
}

// Piped and backgrounded commands do not carry a usable success status for
// the leading mutation. Exercise that production provenance gate here; the
// direct fsOperands/fsOwnArgs cases above separately cover argument truncation.
func TestClassifyCommandWithholdsUnprovenFSMutations(t *testing.T) {
	cases := []struct {
		command string
		want    []string
	}{
		{"git rm x.txt | mytool --cached", nil},
		{"rm old.log | tee cleanup.log", nil},
		{"rm -rf node_modules &", []string{"process.background"}},
	}
	for _, c := range cases {
		t.Run(c.command, func(t *testing.T) {
			facts := classifyCommand(c.command, "", true, testWorkspace())
			var categories []string
			if facts != nil {
				categories = facts.categories
			}
			if !reflect.DeepEqual(categories, c.want) || (facts != nil && len(facts.mutations) != 0) {
				t.Fatalf("classifyCommand(%q) = %+v, want categories %v and no mutations", c.command, facts, c.want)
			}
		})
	}
}

func TestClassifyCommandPatchStripCountIsNotAPath(t *testing.T) {
	facts := classifyCommand("patch -p 1 < fix.diff", "", true, testWorkspace())
	if facts == nil || !slices.Contains(facts.categories, "fs.patch") {
		t.Fatalf("classifyCommand did not credit fs.patch: %+v", facts)
	}
	if len(facts.targets) != 0 || len(facts.mutations) != 0 {
		t.Fatalf("strip count became a patched path: %+v", facts)
	}
}

// TestClassifyFSCwdUncertain covers the HANDOFF from the core fixer: once an
// earlier segment ran `cd`/`pushd` with a real argument, this package no
// longer knows the shell's working directory, so a later segment's relative
// fs operands must not be trusted to resolve against the workspace root —
// neither as a credited path nor as a workspace.escape false positive. An
// absolute operand is unaffected: it resolves the same way regardless of cwd.
func TestClassifyFSCwdUncertain(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    *commandFacts
	}{
		{"a relative delete after an unresolved cd credits nothing", "rm old.go", nil},
		{"a relative move after an unresolved cd credits nothing", "mv old.txt new.txt", nil},
		{"a relative create after an unresolved cd credits nothing", "touch new.txt", nil},
		{"an unresolvable relative operand is not a false escape either", "rm ../outside.txt", nil},
		{"an absolute delete stays trustworthy", "rm /repo/old.go", &commandFacts{
			categories: []string{"fs.delete"},
			targets:    fsPathTargets("old.go"),
			mutations:  []ShellMutation{{Kind: "delete", Path: "old.go"}},
		}},
		{"an absolute escape is still credited", "rm /etc/hosts", &commandFacts{
			categories: []string{"workspace.escape"},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyFS(fsSegmentCwdUncertain(c.command, true))
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("classifyFS(%q) with cwdUncertain = %+v, want %+v", c.command, got, c.want)
			}
		})
	}
}

func TestChangesWorkingDirectory(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    bool
	}{
		{"cd into a subdirectory", "cd internal", true},
		{"pushd onto a subdirectory", "pushd src", true},
		// A bare `cd` moves to $HOME and a bare `pushd` swaps the top of the
		// directory stack: both change the directory, so the cwd becomes
		// unknown even though the destination is not named in the command.
		{"bare cd still changes the directory", "cd", true},
		{"bare pushd still changes the directory", "pushd", true},
		{"cd as another command's argument taints conservatively", "echo cd internal", true},
		{"cd in a later pipeline stage", "printf x | cd /tmp", true},
		{"command portable path option", "command -p cd /tmp", true},
		{"command option terminator", "command -- cd /tmp", true},
		{"builtin option terminator", "builtin -- cd /tmp", true},
		{"command query mode mentioning cd still taints", "command -v cd", true},
		{"unknown command option before cd fails closed", "command -x cd /tmp", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := changesWorkingDirectory(tokensForSegment(c.command))
			if got != c.want {
				t.Errorf("changesWorkingDirectory(%q) = %v, want %v", c.command, got, c.want)
			}
		})
	}
}

// TestClassifyCommandCwdChain exercises the full pipeline (classifyCommand,
// not classifyFS directly) to prove commandclass.go sets cwdUncertain on the
// whole command when any segment may change cwd.
func TestClassifyCommandCwdChain(t *testing.T) {
	ws := testWorkspace()
	cases := []struct {
		name    string
		command string
		want    *commandFacts
	}{
		{
			"a relative delete after cd keeps only its category",
			"cd internal && rm old.go",
			&commandFacts{categories: []string{"fs.delete"}},
		},
		{"an absolute delete after cd is tainted too", "cd internal && rm /repo/old.go", &commandFacts{categories: []string{"fs.delete"}}},
		{
			"a delete before a later cd is tainted too",
			"rm old.go && cd internal",
			&commandFacts{categories: []string{"fs.delete"}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyCommand(c.command, "", true, ws)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("classifyCommand(%q) = %+v, want %+v", c.command, got, c.want)
			}
		})
	}
}
