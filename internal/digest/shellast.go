package digest

import (
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// This file is the shell front end. Everything downstream asks it what a
// command said, rather than scanning the text again for itself.
//
// It exists because scanning was the wrong tool. The classifiers used to look
// for '<' or '>' bytes to decide whether a command's output had been sent
// away, which cannot tell `2>log` from `>log`, `<>f` from `>f`, or a heredoc
// delimiter from a filename — and each of those was a defect found in review,
// fixed one spelling at a time, three rounds running. A shell grammar is not
// something to re-derive from byte patterns, so this delegates it to
// mvdan.cc/sh, the parser behind shfmt.
//
// Two facts come out of it that the old tokenizer could not express at all,
// and both close whole families of invented facts:
//
//   - a redirection is separated from the command's arguments, and carries the
//     descriptor it actually affects, so `head public.txt 3< README.md` no
//     longer looks like a command that read README.md;
//   - a word records whether it is WHOLLY LITERAL. `${TARGET}/x.txt` and
//     `$(date)` name something this package cannot know, so they must never be
//     published as a path. The old tokenizer handed back the raw text with no
//     way to tell it apart from a filename typed out in full.

// shellWord is one word of a command. literal is false when any part of it was
// a parameter expansion, command substitution or arithmetic expansion: text
// says what will be run, not what the word will become, so a non-literal word
// may be used to recognise a command but never published as an identifying
// value.
type shellWord struct {
	text    string
	literal bool
}

// shellRedirect is one redirection, reduced to the questions callers ask.
type shellRedirect struct {
	fd      int  // the descriptor this redirection affects
	fdAll   bool // `&>` and `&>>` affect stdout and stderr together
	input   bool // it supplies the command's input rather than taking its output
	heredoc bool // the input is literal text, so its word is a delimiter
	dupFd   bool // the word names another descriptor, not a file
	word    shellWord
}

// shellSimpleCommand is one simple command: its words with redirections taken
// out, its leading assignments, and those redirections.
type shellSimpleCommand struct {
	words     []shellWord
	assigns   []string
	redirects []shellRedirect
}

// parseShellCommand parses a whole command line. ok is false when the text
// cannot be parsed at all, which callers must treat as "cannot tell", never as
// a guess — the same contract the previous tokenizer had when quoting was
// unterminated.
func parseShellCommand(src string) ([]shellSimpleCommand, bool) {
	if src == "" || len(src) > maxCommandTokenizationChars {
		return nil, false
	}
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(src), "")
	if err != nil || file == nil {
		return nil, false
	}
	var commands []shellSimpleCommand
	syntax.Walk(file, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		switch command := stmt.Cmd.(type) {
		case *syntax.DeclClause:
			declaration := shellSimpleCommand{
				words:     []shellWord{{text: command.Variant.Value, literal: true}},
				redirects: shellRedirects(src, stmt.Redirs),
			}
			for _, arg := range command.Args {
				declaration.words = append(declaration.words, assignShellWord(src, arg))
			}
			commands = append(commands, declaration)
			return true
		case *syntax.TimeClause:
			if command.Stmt == nil {
				return true
			}
			call, ok := command.Stmt.Cmd.(*syntax.CallExpr)
			if !ok {
				return true
			}
			timed := shellCallCommand(src, command.Stmt, call)
			prefix := []shellWord{{text: "time", literal: true}}
			if command.PosixFormat {
				prefix = append(prefix, shellWord{text: "-p", literal: true})
			}
			timed.words = append(prefix, timed.words...)
			commands = append(commands, timed)
			return false
		case *syntax.CallExpr:
			commands = append(commands, shellCallCommand(src, stmt, command))
			return true
		default:
			// A compound command (if, for, subshell) still has redirections and
			// still contains statements, so keep walking into it.
			return true
		}
	})
	return commands, true
}

func shellCallCommand(src string, stmt *syntax.Stmt, call *syntax.CallExpr) shellSimpleCommand {
	command := shellSimpleCommand{redirects: shellRedirects(src, stmt.Redirs)}
	for _, assign := range call.Assigns {
		command.assigns = append(command.assigns, assignText(src, assign))
	}
	for _, word := range call.Args {
		command.words = append(command.words, shellWordText(src, word))
	}
	return command
}

// firstShellCommand is the outer command in src. Words inside a command
// substitution are deliberately later in syntax.Walk's traversal, so selecting
// the first call keeps their separate control flow from borrowing the outer
// command's status.
func firstShellCommand(src string) (shellSimpleCommand, bool) {
	commands, ok := parseShellCommand(src)
	if !ok || len(commands) == 0 {
		return shellSimpleCommand{}, false
	}
	return commands[0], true
}

// shellCommandTokens preserves the established token-oriented classifiers
// while sourcing their words from the shell parser. Redirections are omitted
// by construction, so their targets cannot become command operands.
func shellCommandTokens(src string) ([]string, shellSimpleCommand, bool) {
	if strings.Contains(src, "\r") {
		// A carriage return is a shell word byte, but mvdan's parser accepts it
		// as whitespace. Retain the tokenizer's established interpretation for
		// this non-redirection form rather than publishing a different command.
		tokens := tokensForSegment(src)
		if len(tokens) == 0 || strings.ContainsAny(src, "<>") {
			return nil, shellSimpleCommand{}, false
		}
		words := make([]shellWord, len(tokens))
		for i, token := range tokens {
			words[i] = shellWord{text: token, literal: true}
		}
		return tokens, shellSimpleCommand{words: words}, true
	}
	command, ok := firstShellCommand(src)
	if !ok {
		return nil, shellSimpleCommand{}, false
	}
	tokens := make([]string, 0, len(command.assigns)+len(command.words))
	tokens = append(tokens, command.assigns...)
	tokens = append(tokens, command.wordTexts()...)
	return tokens, command, true
}

func shellRedirects(src string, redirs []*syntax.Redirect) []shellRedirect {
	var out []shellRedirect
	for _, redir := range redirs {
		r := shellRedirect{fd: redirectDefaultFD(redir.Op)}
		switch redir.Op {
		case syntax.RdrIn, syntax.RdrInOut, syntax.DplIn, syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
			r.input = true
		case syntax.RdrAll, syntax.RdrAllClob, syntax.AppAll, syntax.AppAllClob:
			r.fdAll = true
		}
		switch redir.Op {
		case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
			// The word is the delimiter (or, for `<<<`, the data itself). Either
			// way it names no file, and publishing it as one invents a read.
			r.heredoc = true
		case syntax.DplIn, syntax.DplOut:
			r.dupFd = true
		}
		if redir.N != nil {
			if n, err := strconv.Atoi(redir.N.Value); err == nil {
				r.fd = n
				r.fdAll = false
			}
		}
		if redir.Word != nil {
			r.word = shellWordText(src, redir.Word)
		}
		out = append(out, r)
	}
	return out
}

func redirectDefaultFD(op syntax.RedirOperator) int {
	switch op {
	case syntax.RdrIn, syntax.RdrInOut, syntax.DplIn, syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
		return 0
	default:
		return 1
	}
}

func assignText(src string, assign *syntax.Assign) string {
	return assignShellWord(src, assign).text
}

func assignShellWord(src string, assign *syntax.Assign) shellWord {
	name := ""
	if assign.Name != nil {
		name = assign.Name.Value
	}
	if assign.Naked {
		if assign.Value == nil {
			return shellWord{text: name, literal: true}
		}
		return shellWordText(src, assign.Value)
	}
	if assign.Value == nil {
		return shellWord{text: name + "=", literal: true}
	}
	value := shellWordText(src, assign.Value)
	return shellWord{text: name + "=" + value.text, literal: value.literal}
}

// shellWordText renders a word the way the shell would read it for quoting —
// quotes removed, the text inside them kept — while leaving every expansion as
// written. An expansion is reported through literal=false rather than being
// resolved, because its value is not in the command text and guessing at one
// is how this package used to invent paths.
func shellWordText(src string, word *syntax.Word) shellWord {
	if word == nil {
		return shellWord{literal: true}
	}
	var text strings.Builder
	literal := true
	var writeParts func(parts []syntax.WordPart)
	writeParts = func(parts []syntax.WordPart) {
		for _, part := range parts {
			switch p := part.(type) {
			case *syntax.Lit:
				text.WriteString(p.Value)
			case *syntax.SglQuoted:
				text.WriteString(p.Value)
			case *syntax.DblQuoted:
				writeParts(p.Parts)
			default:
				text.WriteString(nodeSource(src, part))
				literal = false
			}
		}
	}
	writeParts(word.Parts)
	return shellWord{text: text.String(), literal: literal}
}

func nodeSource(src string, node syntax.Node) string {
	start, end := int(node.Pos().Offset()), int(node.End().Offset())
	if start < 0 || end > len(src) || start >= end {
		return ""
	}
	return src[start:end]
}

// stdoutCaptured reports whether the command's standard output still reaches
// the stream this package captured. Only that makes silence evidence: a
// command whose output went to a file said nothing here, which is not the same
// as having nothing to say.
func (c shellSimpleCommand) stdoutCaptured() bool {
	for _, r := range c.redirects {
		if r.input {
			continue
		}
		if r.fdAll || r.fd == 1 {
			return false
		}
	}
	return true
}

// inputRedirect returns the redirection supplying the command's standard
// input, if any.
func (c shellSimpleCommand) inputRedirect() (shellRedirect, bool) {
	for i := len(c.redirects) - 1; i >= 0; i-- {
		if r := c.redirects[i]; r.input && r.fd == 0 {
			return r, true
		}
	}
	return shellRedirect{}, false
}

// inputFile names the file the shell opens on standard input, and reports
// false when nothing does, when the input is literal heredoc text, or when the
// name is not knowable from the command text.
func (c shellSimpleCommand) inputFile() (string, bool) {
	r, ok := c.inputRedirect()
	if !ok || r.heredoc || r.dupFd || !r.word.literal || r.word.text == "" {
		return "", false
	}
	return r.word.text, true
}

// wordTexts is the flat argument list, for callers still written against
// plain tokens.
func (c shellSimpleCommand) wordTexts() []string {
	out := make([]string, 0, len(c.words))
	for _, w := range c.words {
		out = append(out, w.text)
	}
	return out
}
