package digest

import (
	"reflect"
	"testing"
)

// Each case here is a shape that produced a review finding while the shell was
// being scanned for '<' and '>' bytes instead of parsed. They are kept as one
// table so a regression names the spelling it broke.
func TestParseShellCommandSeparatesRedirectionsFromArguments(t *testing.T) {
	for _, tc := range []struct {
		name          string
		src           string
		wantWords     []string
		wantStdout    bool
		wantInputFile string
		wantNoInput   bool
	}{
		{
			name:       "unused descriptor is not the file that was read",
			src:        "head -n 1 public.txt 3< README.md",
			wantWords:  []string{"head", "-n", "1", "public.txt"},
			wantStdout: true, wantNoInput: true,
		},
		{
			name:          "stdin redirection names a real file",
			src:           "head -n 1 < README.md",
			wantWords:     []string{"head", "-n", "1"},
			wantStdout:    true,
			wantInputFile: "README.md",
		},
		{
			name:       "a heredoc delimiter is not a file",
			src:        "head -n 1 <<.env\nSECRET=value\n.env\n",
			wantWords:  []string{"head", "-n", "1"},
			wantStdout: true, wantNoInput: true,
		},
		{
			name:       "a here-string is data, not a file",
			src:        "head <<< .env",
			wantWords:  []string{"head"},
			wantStdout: true, wantNoInput: true,
		},
		{
			name:       "read-write redirection opens stdin, so stdout stays captured",
			src:        "chmod -c 0644 file.txt <>rw.log",
			wantWords:  []string{"chmod", "-c", "0644", "file.txt"},
			wantStdout: true,
			// <> supplies input from a real file
			wantInputFile: "rw.log",
		},
		{
			name:       "redirecting stderr leaves stdout captured",
			src:        "chmod -c 0644 f.txt 2>/dev/null",
			wantWords:  []string{"chmod", "-c", "0644", "f.txt"},
			wantStdout: true, wantNoInput: true,
		},
		{
			name:       "redirecting stdout means silence proves nothing",
			src:        "chmod -c 0644 f.txt >/dev/null",
			wantWords:  []string{"chmod", "-c", "0644", "f.txt"},
			wantStdout: false, wantNoInput: true,
		},
		{
			name:       "&> takes stdout with it",
			src:        "chmod -c 0644 f.txt &>/dev/null",
			wantWords:  []string{"chmod", "-c", "0644", "f.txt"},
			wantStdout: false, wantNoInput: true,
		},
		{
			name:          "an explicit stdin alias keeps the redirected input visible",
			src:           "patch -i - < /dev/null",
			wantWords:     []string{"patch", "-i", "-"},
			wantStdout:    true,
			wantInputFile: "/dev/null",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			commands, ok := parseShellCommand(tc.src)
			if !ok || len(commands) != 1 {
				t.Fatalf("parse = %d commands, ok=%v", len(commands), ok)
			}
			got := commands[0]
			if !reflect.DeepEqual(got.wordTexts(), tc.wantWords) {
				t.Errorf("words = %q, want %q", got.wordTexts(), tc.wantWords)
			}
			if got.stdoutCaptured() != tc.wantStdout {
				t.Errorf("stdoutCaptured = %v, want %v", got.stdoutCaptured(), tc.wantStdout)
			}
			file, hasFile := got.inputFile()
			switch {
			case tc.wantNoInput && hasFile:
				t.Errorf("inputFile = %q, want none", file)
			case tc.wantInputFile != "" && file != tc.wantInputFile:
				t.Errorf("inputFile = %q, want %q", file, tc.wantInputFile)
			}
		})
	}
}

// A word that contains an expansion names something the command text does not
// state. Recognising the command is fine; publishing the word as a path is not.
func TestParseShellCommandMarksExpandedWordsNonLiteral(t *testing.T) {
	for _, tc := range []struct {
		src         string
		wantText    string
		wantLiteral bool
	}{
		{src: "rm plain.txt", wantText: "plain.txt", wantLiteral: true},
		{src: `rm "quoted name.txt"`, wantText: "quoted name.txt", wantLiteral: true},
		{src: "rm 'single.txt'", wantText: "single.txt", wantLiteral: true},
		{src: "rm ${TARGET}/x.txt", wantText: "${TARGET}/x.txt", wantLiteral: false},
		{src: "rm $TARGET", wantText: "$TARGET", wantLiteral: false},
		{src: "rm $(date).txt", wantText: "$(date).txt", wantLiteral: false},
		{src: "rm \"pre$SUFFIX\"", wantText: "pre$SUFFIX", wantLiteral: false},
	} {
		t.Run(tc.src, func(t *testing.T) {
			commands, ok := parseShellCommand(tc.src)
			if !ok || len(commands) == 0 {
				t.Fatalf("parse failed for %q", tc.src)
			}
			operand := commands[0].words[len(commands[0].words)-1]
			if operand.text != tc.wantText || operand.literal != tc.wantLiteral {
				t.Fatalf("operand = %+v, want text %q literal %v", operand, tc.wantText, tc.wantLiteral)
			}
		})
	}
}

func TestParseShellCommandRejectsUnparsableText(t *testing.T) {
	for _, src := range []string{"", "rm 'unterminated", `rm "unterminated`, "rm $(unclosed"} {
		if _, ok := parseShellCommand(src); ok {
			t.Errorf("parseShellCommand(%q) reported success, want cannot-parse", src)
		}
	}
}

func TestParseShellCommandKeepsAssignmentsOutOfArguments(t *testing.T) {
	commands, ok := parseShellCommand("GIT_WORK_TREE=/tmp/x git status")
	if !ok || len(commands) != 1 {
		t.Fatalf("parse = %d commands, ok=%v", len(commands), ok)
	}
	if want := []string{"git", "status"}; !reflect.DeepEqual(commands[0].wordTexts(), want) {
		t.Errorf("words = %q, want %q", commands[0].wordTexts(), want)
	}
	if want := []string{"GIT_WORK_TREE=/tmp/x"}; !reflect.DeepEqual(commands[0].assigns, want) {
		t.Errorf("assigns = %q, want %q", commands[0].assigns, want)
	}
}

func TestParseShellCommandWalksTimeClause(t *testing.T) {
	commands, ok := parseShellCommand("time cd ../other")
	if !ok || len(commands) != 1 || !reflect.DeepEqual(commands[0].wordTexts(), []string{"time", "cd", "../other"}) {
		t.Fatalf("parse = %#v, ok=%v", commands, ok)
	}
}

func TestParseShellCommandKeepsDeclarationArguments(t *testing.T) {
	commands, ok := parseShellCommand("export GIT_WORK_TREE=/tmp/x")
	if !ok || len(commands) != 1 || !reflect.DeepEqual(commands[0].wordTexts(), []string{"export", "GIT_WORK_TREE=/tmp/x"}) {
		t.Fatalf("parse = %#v, ok=%v", commands, ok)
	}
}
