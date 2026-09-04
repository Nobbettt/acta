package digest

// This file classifies a shell command into categories (what kind of work the
// command did) plus the targets it acted on. It follows the same rule as the
// retrieval inference in trace.go: credit only what the command text — and,
// where stated, its bounded output — proves, and claim nothing when unsure.

import (
	"path"
	"slices"
	"sort"
	"strings"
)

// CommandTarget is one thing a classified command acted on. Kind is one of
// path, package, url, host, pattern, ref or tool.
type CommandTarget struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// ShellMutation is a workspace change proven by a shell command, so deletes
// and moves the agent made without an edit tool still reach the file timeline.
// Kind is delete or move.
type ShellMutation struct {
	Kind string `json:"kind"`
	Path string `json:"path,omitempty"`
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// commandSegment is one `&&`/`||`/`;`-separated slice of a command, handed to
// every classifier together with the whole-command context it may need. tokens
// is empty both for an over-long segment and for one with unbalanced quoting;
// either way a classifier must treat that as "cannot parse", never as a guess.
type commandSegment struct {
	raw     string   // this segment of the command
	tokens  []string // tokensForSegment(raw), may be empty
	command string   // command text used to prove this segment executed
	output  string   // see trustedOutput: empty unless the command is one segment
	exitOK  bool     // the command exited zero
	ws      *workspace
	// cwdUncertain is set on every segment when `cd`, `pushd` or `popd` appears
	// as a standalone token anywhere in the command. Relative path operands in
	// that command then cannot be trusted to identify workspace files.
	cwdUncertain bool
	// cwd is the literal directory established before this segment when the
	// shell chain proves it. cwdKnown distinguishes that from a dynamic cd.
	cwd      string
	cwdKnown bool
}

// trustedOutput is the output a classifier may draw a fact from. Output belongs
// to the whole command, not to any one segment of it, so
// `git rev-parse HEAD && echo something` cannot prove which segment printed
// which line — crediting the sha to either segment would be an invention. Trust
// output only when the command is a single, untransformed segment, exactly as
// attachReadRange already does for read ranges; otherwise there is no output at
// all, and every classifier's existing "empty output proves nothing" rule takes
// over.
func trustedOutput(segments []string, outputText string) string {
	if len(segments) != 1 {
		return ""
	}
	return boundedOutput(outputText)
}

// heredocOperatorEnd scans segment for a `<<`/`<<-` that opens a heredoc,
// tracking single- and double-quote state so a `<<` written inside a quoted
// argument (`git commit -m 'shift a << b'`) is never mistaken for one: only
// an operator seen outside any quote counts. `<<<` (a herestring, which reads
// one word with no body) is skipped rather than matched. Returns the offset
// just past the operator, whether it was the dash-stripping `<<-` form, and
// whether one was found at all.
func heredocOperatorEnd(segment string) (end int, dashStrip bool, ok bool) {
	inSingle, inDouble := false, false
	for i := 0; i < len(segment); i++ {
		switch c := segment[i]; {
		case c == '\\' && !inSingle:
			i++ // an escaped char, including a quote, never toggles quote state
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case !inSingle && !inDouble && c == '<' && i+1 < len(segment) && segment[i+1] == '<':
			if i+2 < len(segment) && segment[i+2] == '<' {
				i += 2 // <<< is a herestring, not a heredoc opener
				continue
			}
			end = i + 2
			if end < len(segment) && segment[end] == '-' {
				end++
				dashStrip = true
			}
			return end, dashStrip, true
		}
	}
	return 0, false, false
}

// heredocOperatorCount reports how many heredoc-opening `<<`/`<<-` operators
// segment contains outside any quote (the same quote tracking as
// heredocOperatorEnd; `<<<` herestrings are not counted). heredocDelimiter
// refuses any segment reporting more than one: resolving only the first
// delimiter would leave a second heredoc's body — still ahead of it in the
// command — unaccounted for and misread as commands once the first
// terminator line is found.
func heredocOperatorCount(segment string) int {
	count := 0
	inSingle, inDouble := false, false
	for i := 0; i < len(segment); i++ {
		switch c := segment[i]; {
		case c == '\\' && !inSingle:
			i++
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case !inSingle && !inDouble && c == '<' && i+1 < len(segment) && segment[i+1] == '<':
			if i+2 < len(segment) && segment[i+2] == '<' {
				i += 2 // <<< is a herestring, not a heredoc opener
				continue
			}
			count++
			i++ // consume the second '<'; the dash check below looks past it
			if i+1 < len(segment) && segment[i+1] == '-' {
				i++
			}
		}
	}
	return count
}

// heredocDelimiter returns the closing word of a heredoc opened in segment,
// or "" if segment does not open one, plus whether the opener was the
// dash-stripping `<<-` form. ambiguous is true when segment opens a heredoc
// but its shape cannot be resolved: the delimiter word itself is unparseable
// (e.g. an unterminated quote), or segment opens more than one heredoc. The
// caller must not guess in either case and instead credits nothing for the
// whole command, the same rule tokensForSegment already applies to
// unbalanced quoting elsewhere. The delimiter word is read with shellTokens,
// so any of its quoting forms (bare, 'single', "double", backslash-escaped,
// or a mix) resolve to the same plain word the shell would compare the
// closing line against.
func heredocDelimiter(segment string) (delim string, dashStrip bool, ambiguous bool) {
	if heredocOperatorCount(segment) > 1 {
		return "", false, true
	}
	end, dashStrip, ok := heredocOperatorEnd(segment)
	if !ok {
		return "", false, false
	}
	tokens := shellTokens(segment[end:])
	if len(tokens) == 0 {
		return "", dashStrip, true
	}
	if tokens[0] == "" {
		return "", dashStrip, true
	}
	return tokens[0], dashStrip, false
}

// heredocLineCloses reports whether line — the exact, untrimmed text of one
// raw chain segment — is the line that closes a heredoc opened with
// delimiter delim. Bash requires the closing line to equal delim exactly for
// a plain `<<`; `<<-` additionally strips leading TABS only (never spaces)
// before comparing. TrimSpace would accept lines the shell does not — an
// indented delimiter under a plain `<<`, or a delimiter with trailing
// whitespace — misreading heredoc body content as the terminator and
// classifying the real commands that follow it as body text, or vice versa.
func heredocLineCloses(line, delim string, dashStrip bool) bool {
	if dashStrip {
		line = strings.TrimLeft(line, "\t")
	}
	return line == delim
}

// commandChainRaw is one `\n`/`&&`/`||`/`;`-delimited slice of a command plus
// the separator that preceded it ("" for the first), before heredoc bodies
// are stripped out. raw is trimmed for tokenizing; rawUntrimmed keeps the
// exact source text (leading/trailing whitespace and all) because a heredoc
// terminator line is matched against that exact text, never a trimmed copy —
// see heredocLineCloses. piped records whether this segment contains an
// unquoted `|` that is not part of `||`. async records whether it contains an
// unquoted, unescaped `&` that is not part of `&&` — backgrounding whatever
// ran before it, whether that `&` sits at the very end of the segment
// (`rm -rf dist &`) or mid-segment as the `a & b` separator shell itself
// never splits on (`rm x & echo done`). subshell records any unquoted `(` or
// `)`, because a single outer exit status cannot prove which subshell-local
// state changes should be attributed to the workspace. executed is set by
// pruneUnexecuted only when the command text proves this term ran; uncertain
// terms cannot lend their literal outcome to a later conditional branch.
type commandChainRaw struct {
	raw          string
	rawUntrimmed string
	sep          string
	piped        bool
	async        bool
	subshell     bool
	executed     bool
}

// splitRawChain is splitCommandSegments plus the separator it finds but
// discards — needed to tell a `||`-adjacent segment from any other. Unlike a
// plain regex split, it tracks single/double-quote and backslash state the
// same way heredocOperatorEnd does, so a separator that only appears inside a
// quoted argument — `echo "build && rm -rf dist"`, a commit message spanning
// several lines — is never mistaken for a real one and split into fake
// segments of its own.
//
// An unquoted `#` starting a word begins a shell comment that runs to the end
// of that physical LINE only — not the rest of the command. The segment
// before it is closed off, the comment text itself is discarded, and the
// scan resumes right after the next unquoted newline (or stops, if the
// comment is the last line) with sep "\n", exactly as if that newline had
// been a real separator. Ending the whole scan instead — returning at the
// first `#` — would silently drop every later line, and worse, would let a
// comment on an early line erase the separators those later lines
// contributed to splitCommandChain's all-`&&` provenance check, laundering
// an unrelated line's exit status onto the segment before the comment. The
// bool is false when an `&&`/`||` or pipeline operator has no command on either
// side: such a list is a shell syntax error, so none of its apparent commands
// can be credited.
func splitRawChain(command string) ([]commandChainRaw, bool) {
	var raw []commandChainRaw
	valid := true
	hasSubshell := false
	piped, async := false, false
	appendChain := func(segment, sep string) {
		if s := trimShellWhitespace(removeShellLineContinuations(segment)); s != "" {
			raw = append(raw, commandChainRaw{raw: s, rawUntrimmed: segment, sep: sep, piped: piped, async: async})
		}
		piped, async = false, false
	}
	sep, start, pipelineStageStart := "", 0, 0
	emptyStage := func(begin, end int) bool {
		return trimShellWhitespace(removeShellLineContinuations(command[begin:end])) == ""
	}
	emptyPipelineTail := func(end int) bool {
		return piped && emptyStage(pipelineStageStart, end)
	}
	wordStart := true
	inSingle, inDouble := false, false
	for i := 0; i < len(command); i++ {
		switch c := command[i]; {
		case c == '\\' && !inSingle:
			if i+1 < len(command) && command[i+1] == '\n' {
				i++
				continue
			}
			wordStart = false
			i++ // an escaped char, including a quote, never toggles quote state
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			wordStart = false
		case c == '"' && !inSingle:
			inDouble = !inDouble
			wordStart = false
		case c == '`' && !inSingle:
			// A command substitution has its own control flow and exit statuses.
			// None of its apparent commands may borrow the outer command's status.
			return nil, false
		case inSingle || inDouble:
			// inside a quote: none of the separators below count
		case c == '#' && wordStart:
			// If the comment begins in the empty span after an operator, keep
			// that operator pending for the command on the next line. In
			// `a &&# note\nb`, the comment occupies only the rest of its
			// physical line; `&&` still relates a to b and is therefore still
			// part of the exit-status proof. A comment after real command text
			// instead contributes its newline as the next separator.
			if trimShellWhitespace(command[start:i]) != "" {
				if emptyPipelineTail(i) {
					valid = false
				}
				appendChain(command[start:i], sep)
				sep = "\n"
			} else if sep == "" {
				sep = "\n"
			}
			if nl := strings.IndexByte(command[i:], '\n'); nl >= 0 {
				start = i + nl + 1
			} else {
				start = len(command)
			}
			pipelineStageStart = start
			wordStart = true
			i = start - 1 // the loop's i++ resumes the scan at start
		case c == ' ' || c == '\t':
			wordStart = true
		case c == '\n':
			if emptyPipelineTail(i) {
				valid = false
			}
			if trimShellWhitespace(command[start:i]) != "" {
				appendChain(command[start:i], sep)
				sep = "\n"
			} else if sep != "&&" && sep != "||" {
				appendChain(command[start:i], sep)
				sep = "\n"
			}
			start = i + 1
			pipelineStageStart = start
			wordStart = true
		case c == ';':
			if emptyPipelineTail(i) {
				valid = false
			}
			if emptyStage(start, i) {
				valid = false
			}
			appendChain(command[start:i], sep)
			sep, start = ";", i+1
			pipelineStageStart = start
			wordStart = true
		case c == '&' && i+1 < len(command) && command[i+1] == '&':
			if emptyPipelineTail(i) {
				valid = false
			}
			if trimShellWhitespace(command[start:i]) == "" {
				valid = false
			}
			appendChain(command[start:i], sep)
			sep, start = "&&", i+2
			pipelineStageStart = start
			wordStart = true
			i++
		case c == '&':
			// A lone `&` backgrounds whatever precedes it: the shell reports the
			// exit status of launching the job (always 0), never the
			// backgrounded command's own. splitRawChain does not split the
			// chain on it (unlike `&&`, a shell does not treat `a & b` as two
			// independently-classified halves here either), so this only marks
			// the segment async; see chainSegment.orGated. `N>&M`/`N<&M` (fd
			// duplication, e.g. `2>&1`) and `&>`/`&>>` (redirect both streams)
			// are excluded — that `&` is not the detach operator.
			afterRedirect := i > 0 && (command[i-1] == '>' || command[i-1] == '<')
			if afterRedirect {
				backslashes := 0
				for j := i - 2; j >= 0 && command[j] == '\\'; j-- {
					backslashes++
				}
				afterRedirect = backslashes%2 == 0
			}
			beforeRedirect := i+1 < len(command) && command[i+1] == '>'
			if !afterRedirect && !beforeRedirect {
				if emptyStage(start, i) {
					valid = false
				}
				j := i + 1
				for j < len(command) && (command[j] == ' ' || command[j] == '\t') {
					j++
				}
				if j < len(command) && (command[j] == ';' || command[j] == '&' || command[j] == '|') {
					valid = false
				}
				async = true
			}
			wordStart = true
		case c == '|' && i+1 < len(command) && command[i+1] == '|':
			if emptyPipelineTail(i) {
				valid = false
			}
			if trimShellWhitespace(command[start:i]) == "" {
				valid = false
			}
			appendChain(command[start:i], sep)
			sep, start = "||", i+2
			pipelineStageStart = start
			wordStart = true
			i++
		case c == '|':
			// A lone pipe does not separate the chain — both sides remain one
			// segment, exactly as the shell reports one process group — but it
			// does mean this segment's exit status is the LAST pipeline stage's,
			// not the leading command's. See chainSegment.orGated.
			if emptyStage(pipelineStageStart, i) {
				valid = false
			}
			piped = true
			if i+1 < len(command) && command[i+1] == '&' {
				i++
			}
			pipelineStageStart = i + 1
			wordStart = true
		case c == '(' || c == ')' || c == '<' || c == '>':
			// Shell metacharacters end the preceding word even though this
			// splitter does not otherwise need to segment on them.
			if c == '(' || c == ')' {
				hasSubshell = true
			}
			wordStart = true
		default:
			wordStart = false
		}
	}
	if emptyPipelineTail(len(command)) {
		valid = false
	}
	if (sep == "&&" || sep == "||") && trimShellWhitespace(command[start:]) == "" {
		valid = false
	}
	appendChain(command[start:], sep)
	if hasSubshell {
		for i := range raw {
			raw[i].subshell = true
		}
	}
	return raw, valid
}

// stripHeredocBodies drops every raw segment belonging to a heredoc's body, up
// to and including its closing delimiter line. segmentSplitRe splits on raw
// newlines before any tokenizing happens, so without this, every line written
// into a heredoc — a script, a patch, a config file — would otherwise look
// like its own fully-formed shell command.
//
// ok is false when a heredoc was opened but its shape could not be resolved:
// an unparseable delimiter word, a segment opening more than one heredoc, a
// second heredoc opened by a later segment of the same command, or a closing
// line that never appears in the rest of the command. Either way the
// body/command boundary is unknown, so the caller must credit nothing for
// the whole command rather than guess — guessing risks classifying body text
// as commands (a false positive) just as easily as it risks silently
// dropping real, later commands.
//
// The second heredoc case needs its own pass, up front, across every segment
// in raw: heredocOperatorCount/heredocDelimiter already refuse more than one
// opener within a single segment, but that alone misses `cat <<E1 > a &&
// cat <<E2 > b`, one opener per segment. Once the first heredoc's body scan
// below starts, it walks forward looking for E1's closing line and has no way
// to notice that the segment it steps over on the way (the second `cat <<E2`)
// opened a heredoc of its own — that segment is never even visited, since it
// gets consumed as if it were E1's body. Counting openers across the whole
// command before any body is stripped is the only way to see the second one.
func stripHeredocBodies(raw []commandChainRaw) (out []commandChainRaw, ok bool) {
	openers := 0
	for _, r := range raw {
		delim, _, ambiguous := heredocDelimiter(r.raw)
		if ambiguous || delim != "" {
			openers++
		}
		if openers > 1 {
			return nil, false
		}
	}
	for i := 0; i < len(raw); i++ {
		out = append(out, raw[i])
		delim, dashStrip, ambiguous := heredocDelimiter(raw[i].raw)
		if ambiguous {
			return nil, false
		}
		if delim == "" {
			continue
		}
		j := i + 1
		for ; j < len(raw); j++ {
			if j == i+1 && raw[j].sep != "\n" {
				return nil, false
			}
			// raw was cut on unquoted `&&`/`||`/`;` as well as `\n`, so a segment
			// alone is not proof it is a whole physical line: a heredoc body line
			// ending "&&EOF" produces a segment whose text is exactly delim, even
			// though the shell never treats it as anything but body text. Only a
			// segment that both starts right after a newline and ends right before
			// one — occupies its line by itself — can be the closing line.
			lineStart := raw[j].sep == "\n"
			lineEnd := j+1 == len(raw) || raw[j+1].sep == "\n"
			if lineStart && lineEnd && heredocLineCloses(raw[j].rawUntrimmed, delim, dashStrip) {
				break
			}
		}
		if j == len(raw) {
			return nil, false // closing delimiter never found
		}
		i = j // consumes the closing delimiter line too; it is not a command either
	}
	return out, true
}

// chainSegment is one command segment plus whether command text proves it ran
// and whether the final exit status proves it succeeded. The command reports
// a single exit code for the whole chain. That code proves every segment ran and succeeded only
// when the chain is a single segment, or every separator in it is `&&` — a
// `&&` chain short-circuits on the first failure, so if it reaches the last
// segment and exits zero, every segment before it must have succeeded too.
// Any `;`, newline or `||` anywhere breaks that proof for the whole chain:
// `;` and a newline discard the preceding segment's status outright, and
// `a || b` reports one code for two candidates (a succeeded and b never ran,
// or a failed and b rescued it) — either way orGated goes on every segment,
// not just the one next to the offending separator.
//
// A segment containing an unquoted `|` (`rm x | true`) makes every segment
// orGated, even inside an all-`&&` chain: accepting an earlier sibling while
// rejecting only the pipeline would still require partial shell-status
// reasoning. The fail-closed invariant instead trusts the whole chain or none
// of it.
//
// A segment backgrounded with a lone `&` (`rm x &`, or `rm x & echo done`)
// gets orGated for the same reason as a pipe: the reported status proves the
// job was launched, not that the backgrounded command itself succeeded. A
// lone `&` is also a list terminator, not just a segment marker: `a && b &`
// backgrounds the WHOLE `a && b` list as one job, so the reported status
// proves nothing about `a` either, even though `a`'s own separator was `&&`
// and it contains no `&` itself. So async breaks the all-`&&` provenance
// check for the whole chain, exactly like `;`, a newline or `||` does — not
// just the one segment it was found on.
type chainSegment struct {
	raw          string
	orGated      bool
	executed     bool
	statusProven bool
	cwdUncertain bool
	piped        bool
}

// splitCommandChain is splitCommandSegments with heredoc bodies removed
// before segmenting, plus the all-`&&` provenance check described on
// chainSegment, so classifyCommand never has to track shell semantics
// itself. A single simple command, an unbroken `&&` chain, or the final branch
// proven to run from literal outcomes can prove a state change. A pipeline,
// background operator or subshell never can. Untracked cwd or parent-shell
// environment changes make relative paths uncertain, while pruneUnexecuted
// removes commands after an executed exit/exec. Returns nil when a heredoc's
// shape could not be resolved — see stripHeredocBodies — so the caller credits
// nothing for the whole command.
func splitCommandChain(command string) []chainSegment {
	if len(command) > maxCommandTokenizationChars {
		return []chainSegment{{raw: command}}
	}
	raw, valid := splitRawChain(command)
	if !valid {
		return nil
	}
	raw, ok := stripHeredocBodies(raw)
	if !ok || !commandSyntaxModelled(raw) {
		return nil
	}
	proven := true
	cwdUncertain := false
	for i, r := range raw {
		tokens := tokensForSegment(r.raw)
		if changesWorkingDirectory(tokens) || len(raw) > 1 && parentShellEnvironmentMutation(tokens) {
			cwdUncertain = true
		}
		if (i > 0 && r.sep != "&&") || r.piped || r.async || r.subshell ||
			containsShellControlCommand(tokens, "eval", "source", ".") {
			proven = false
		}
	}
	pruned := pruneUnexecuted(raw)
	segments := make([]chainSegment, 0, len(pruned))
	for i, r := range pruned {
		segments = append(segments, chainSegment{
			raw:      r.raw,
			orGated:  !proven,
			executed: r.executed,
			statusProven: proven || r.executed && i == len(pruned)-1 &&
				!r.piped && !r.async && !r.subshell,
			cwdUncertain: cwdUncertain,
			piped:        r.piped,
		})
	}
	return segments
}

var unmodelledShellWords = []string{
	"if", "then", "elif", "else", "fi",
	"for", "select", "while", "until", "do", "done",
	"case", "esac", "function", "{", "}",
}

// commandSyntaxModelled rejects shell shapes this classifier cannot prove it
// has segmented correctly. Compound bodies can put an apparent command in a
// branch that never ran, traps and shell options can change later control flow,
// and a redirection without a word is a parse error that prevents its command
// from starting at all.
func commandSyntaxModelled(raw []commandChainRaw) bool {
	for _, r := range raw {
		if r.subshell {
			return false
		}
		tokens := tokensForSegment(r.raw)
		leading := execLeadingTokens(tokens)
		if len(tokens) == 0 || len(tokens) > 1 && slices.Contains(tokens, "set") ||
			containsShellControlCommand(tokens, "trap", "shopt", "logout") ||
			len(leading) > 0 && (slices.Contains(unmodelledShellWords, leading[0]) ||
				strings.HasSuffix(leading[0], "()")) || !redirectionsComplete(tokens) {
			return false
		}
	}
	return true
}

func parentShellEnvironmentMutation(tokens []string) bool {
	if containsShellControlCommand(tokens, "export", "unset", "readonly", "declare", "typeset", "local") {
		return true
	}
	foundAssignment := false
	for i := 0; i < len(tokens); i++ {
		switch {
		case execIsAssignment(tokens[i]):
			foundAssignment = true
		case isRedirection(tokens[i]) && i+1 < len(tokens):
			i++
		default:
			return false
		}
	}
	return foundAssignment
}

func redirectionsComplete(tokens []string) bool {
	for i := 0; i < len(tokens); i++ {
		if !isRedirection(tokens[i]) {
			continue
		}
		if i+1 == len(tokens) || isRedirection(tokens[i+1]) || slices.Contains(
			[]string{"|", "|&", "&&", "||", ";", "&"}, tokens[i+1],
		) {
			return false
		}
		if tokens[i+1] == "" && !strings.Contains(tokens[i], "<<<") {
			return false
		}
		i++ // the redirection word is not another operator
	}
	return true
}

type shellOutcome uint8

const (
	shellOutcomeUnknown shellOutcome = iota
	shellOutcomeSuccess
	shellOutcomeFailure
)

// pruneUnexecuted applies the shell-list facts that are provable from command
// text alone before any classifier or retrieval inference sees a segment. It
// removes certainly skipped terms and marks uncertain ones unexecuted. A known
// outcome survives skipped branches, so `true || false || git status` does not
// revive status by comparing it only with the adjacent skipped false. An
// executed exit or exec terminates the list; an uncertain one makes every later
// term uncertain too.
func pruneUnexecuted(raw []commandChainRaw) []commandChainRaw {
	out := make([]commandChainRaw, 0, len(raw))
	outcome := shellOutcomeUnknown
	terminated, mayHaveTerminated := false, false
	for i, r := range raw {
		if terminated {
			continue
		}
		runs, certain := true, true
		if i > 0 {
			switch r.sep {
			case "&&":
				runs, certain = outcome != shellOutcomeFailure, outcome != shellOutcomeUnknown
			case "||":
				runs, certain = outcome != shellOutcomeSuccess, outcome != shellOutcomeUnknown
			}
		}
		if mayHaveTerminated {
			certain = false
		}
		if !runs {
			continue
		}
		r.executed = certain
		out = append(out, r)
		tokens := tokensForSegment(r.raw)
		loadsParentShell := containsShellControlCommand(tokens, "eval", "source", ".")
		if !certain {
			mayHaveTerminated = mayHaveTerminated || loadsParentShell ||
				containsShellControlCommand(tokens, "exit", "exec")
			outcome = shellOutcomeUnknown
			continue
		}
		outcome = knownShellOutcome(tokens)
		terminated = containsShellControlCommand(tokens, "exit", "exec")
		mayHaveTerminated = mayHaveTerminated || loadsParentShell
	}
	return out
}

func knownShellOutcome(tokens []string) shellOutcome {
	if len(tokens) != 1 {
		return shellOutcomeUnknown
	}
	switch tokens[0] {
	case "true", ":":
		return shellOutcomeSuccess
	case "false":
		return shellOutcomeFailure
	default:
		return shellOutcomeUnknown
	}
}

// chainSegmentTexts is the raw text of every untransformed segment in chain.
// A pipeline returns nil because its aggregate output belongs to the final
// stage, not necessarily to the command a classifier recognised.
func chainSegmentTexts(chain []chainSegment) []string {
	texts := make([]string, len(chain))
	for i, c := range chain {
		if c.piped {
			return nil
		}
		texts[i] = c.raw
	}
	return texts
}

// commandFacts is what the classifiers credited for one command: categories
// and targets are sets, mutations keep the order the command performed them in.
type commandFacts struct {
	categories []string
	targets    []CommandTarget
	mutations  []ShellMutation
}

// merge is the publication boundary for classifier results. It folds another
// result in through the target and mutation sanitizers, and dedupes categories
// so a command matched by several classifiers is still credited once.
func (f *commandFacts) merge(other *commandFacts) {
	if other == nil {
		return
	}
	for _, category := range other.categories {
		if !slices.Contains(f.categories, category) {
			f.categories = append(f.categories, category)
		}
	}
	for _, target := range other.targets {
		appendCommandTarget(f, target)
	}
	// Deduped within this merge scope. classifyCommand uses one scope per shell
	// segment so repeated operands collapse without erasing a later real change.
	for _, mutation := range other.mutations {
		appendShellMutation(f, mutation)
	}
}

// appendShellMutation is the only route from a classifier result into the
// aggregate file mutations. It accepts only the two complete wire shapes and
// refuses unexpanded shell expressions, matching appendCommandTarget's
// fail-closed boundary.
func appendShellMutation(facts *commandFacts, mutation ShellMutation) {
	switch mutation.Kind {
	case "delete":
		if mutation.Path == "" || mutation.From != "" || mutation.To != "" {
			return
		}
	case "move":
		if mutation.Path != "" || mutation.From == "" || mutation.To == "" {
			return
		}
	default:
		return
	}
	if strings.ContainsAny(mutation.Path+mutation.From+mutation.To, fsShellMetacharacters) ||
		slices.Contains(facts.mutations, mutation) {
		return
	}
	facts.mutations = append(facts.mutations, mutation)
}

func (f *commandFacts) empty() bool {
	return len(f.categories) == 0 && len(f.targets) == 0 && len(f.mutations) == 0
}

// sortCategories puts the categories in their published order. merge is the one
// place a category is deduped and this is the one place they are sorted; every
// entry point below leaves both invariants true on the way out, so no caller
// ever has to sort or dedupe again.
func (f *commandFacts) sortCategories() {
	sort.Strings(f.categories)
}

// segmentClassifiers are applied to every segment of every command, in this
// order. Each one owns a disjoint slice of the category table.
var segmentClassifiers = []func(commandSegment) *commandFacts{
	classifyVCS,
	classifyFS,
	classifyExec,
}

// classifyCommand splits a command the same way readLikeStep does and runs each
// segment past every classifier. exitOK gates the categories that assert a
// state change; classifiers that describe an observation may credit a failed
// command too. Returns nil when nothing was credited.
func classifyCommand(command, outputText string, exitOK bool, ws *workspace) *commandFacts {
	rawCommand := unwrapShell(command)
	chain := splitCommandChain(rawCommand)
	output := trustedOutput(chainSegmentTexts(chain), outputText)
	facts := &commandFacts{}
	cwd, cwdKnown := canonicalWorkspacePath(ws.root), ws.root != ""
	gitWorkTree, gitWorkTreeKnown := "", false
	for _, c := range chain {
		segmentFacts := &commandFacts{}
		tokens := tokensForSegment(c.raw)
		if gitWorkTreeKnown {
			leading := execLeadingTokens(tokens)
			if len(leading) > 0 && path.Base(leading[0]) == "git" {
				tokens = append([]string{"GIT_WORK_TREE=" + gitWorkTree}, tokens...)
			}
		}
		executionCommand := rawCommand
		if c.executed {
			executionCommand = c.raw
		}
		segment := commandSegment{
			raw:          c.raw,
			tokens:       tokens,
			command:      executionCommand,
			output:       output,
			exitOK:       exitOK && c.statusProven,
			ws:           ws,
			cwdUncertain: c.cwdUncertain,
			cwd:          cwd,
			cwdKnown:     cwdKnown,
		}
		for _, classify := range segmentClassifiers {
			segmentFacts.merge(classify(segment))
		}
		if c.cwdUncertain {
			probe := segment
			probe.cwdUncertain = false
			if fsFacts := classifyFS(probe); fsFacts != nil {
				if cwdKnown && !directoryInsideWorkspace(cwd, ws) {
					outsideProbe := probe
					outsideProbe.ws = newWorkspace(cwd)
					if outsideFacts := classifyFS(outsideProbe); outsideFacts != nil &&
						(len(outsideFacts.targets) != 0 || len(outsideFacts.mutations) != 0) {
						segmentFacts.merge(&commandFacts{categories: []string{"workspace.escape"}})
					}
				} else {
					for _, category := range fsFacts.categories {
						if strings.HasPrefix(category, "fs.") {
							segmentFacts.merge(&commandFacts{categories: []string{category}})
						}
					}
				}
			}
		}
		// Categories and targets are command-wide sets. Mutations are only a set
		// within one segment: a later segment may recreate and mutate the same path.
		mutations := segmentFacts.mutations
		segmentFacts.mutations = nil
		facts.merge(segmentFacts)
		facts.mutations = append(facts.mutations, mutations...)
		cwd, cwdKnown = nextLiteralWorkingDirectory(tokensForSegment(c.raw), c.statusProven, cwd, cwdKnown)
		gitWorkTree, gitWorkTreeKnown = nextLiteralGitWorkTree(tokensForSegment(c.raw), c.statusProven, gitWorkTree, gitWorkTreeKnown)
	}
	if facts.empty() {
		return nil
	}
	facts.sortCategories()
	return facts
}

func directoryInsideWorkspace(dir string, ws *workspace) bool {
	if fsIsWorkspaceRoot(dir, ws) {
		return true
	}
	_, ok := normalizeWorkspacePath(dir, ws)
	return ok
}

func nextLiteralWorkingDirectory(tokens []string, statusProven bool, cwd string, known bool) (string, bool) {
	for len(tokens) > 0 && execIsAssignment(tokens[0]) {
		tokens = tokens[1:]
	}
	if len(tokens) == 0 || tokens[0] != "cd" {
		return cwd, known
	}
	if !statusProven {
		return "", false
	}
	args := fsOwnArgs(tokens[1:])
	if len(args) == 2 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) != 1 || args[0] == "-" || strings.ContainsAny(args[0], fsShellMetacharacters) {
		return "", false
	}
	dir := canonicalWorkspacePath(args[0])
	if fsOperandAbsolute(args[0]) {
		return dir, true
	}
	if !known {
		return "", false
	}
	return path.Join(cwd, dir), true
}

func nextLiteralGitWorkTree(tokens []string, statusProven bool, value string, known bool) (string, bool) {
	touches := slices.ContainsFunc(tokens, func(token string) bool {
		name, _, _ := strings.Cut(token, "=")
		return name == "GIT_WORK_TREE"
	})
	if !touches {
		return value, known
	}
	if !statusProven {
		return "", false
	}
	var assignment string
	switch {
	case len(tokens) == 1:
		assignment = tokens[0]
	case len(tokens) == 2 && tokens[0] == "export":
		assignment = tokens[1]
	default:
		return "", false
	}
	name, assigned, ok := strings.Cut(assignment, "=")
	if !ok || name != "GIT_WORK_TREE" || assigned == "" || strings.ContainsAny(assigned, fsShellMetacharacters) {
		return "", false
	}
	return assigned, true
}

// changesWorkingDirectory marks the whole command uncertain whenever cd,
// pushd or popd appears as a standalone token anywhere, or a parent-shell code
// loader could run one invisibly. Classifiers then reject relative paths while
// retaining absolute paths whose workspace identity is independent of cwd.
func changesWorkingDirectory(tokens []string) bool {
	if containsShellControlCommand(tokens, "eval", "source", ".") {
		return true
	}
	return slices.ContainsFunc(tokens, func(token string) bool {
		return token == "cd" || token == "pushd" || token == "popd"
	})
}

func containsShellControlCommand(tokens []string, words ...string) bool {
	for len(tokens) > 0 {
		end := slices.IndexFunc(tokens, func(token string) bool {
			return strings.HasPrefix(token, "|")
		})
		if end < 0 {
			end = len(tokens)
		}
		if shellStageStartsWith(tokens[:end], words...) {
			return true
		}
		tokens = tokens[end:]
		if len(tokens) > 0 {
			tokens = tokens[1:]
		}
	}
	return false
}

func shellStageStartsWith(tokens []string, words ...string) bool {
	for len(tokens) > 0 {
		tokens = execLeadingTokens(tokens)
		for len(tokens) >= 2 && isRedirection(tokens[0]) {
			tokens = tokens[2:]
		}
		if len(tokens) == 0 {
			return false
		}
		word := path.Base(strings.Trim(tokens[0], "()"))
		if word == "" {
			tokens = tokens[1:]
			continue
		}
		if slices.Contains(words, word) {
			return true
		}
		switch word {
		case "time":
			// Only the literal reserved word has this grammar. /usr/bin/time has
			// unrelated value-taking flags and must not expose one of their values
			// as an exit/exec command.
			if strings.Trim(tokens[0], "()") != "time" {
				return false
			}
			tokens = tokens[1:]
			for len(tokens) > 0 && tokens[0] == "-p" {
				tokens = tokens[1:]
			}
			if len(tokens) > 0 && strings.HasPrefix(tokens[0], "-") {
				return false
			}
		case "!":
			tokens = tokens[1:]
		case "command":
			tokens = tokens[1:]
			for len(tokens) > 0 && strings.HasPrefix(tokens[0], "-") {
				switch tokens[0] {
				case "-v", "-V":
					return false
				case "-p", "--":
					tokens = tokens[1:]
				default:
					return slices.ContainsFunc(tokens[1:], func(token string) bool {
						return slices.Contains(words, path.Base(strings.Trim(token, "()")))
					})
				}
			}
		case "builtin":
			tokens = tokens[1:]
			if len(tokens) > 0 && tokens[0] == "--" {
				tokens = tokens[1:]
			}
		default:
			return false
		}
	}
	return false
}

// classifyEventCommand stamps the classification onto a shell command event.
// exitOK is the caller's proof that the command is known to have run to
// completion and succeeded — not merely "not flagged as an error", which for
// an unfinished command (no terminal status, no exit code) is often the
// zero-value default rather than evidence of anything. Call it after the
// retrieval step has been applied, so the path-derived facets in
// classifyPaths see every file the command was credited with.
func classifyEventCommand(e *Event, outputText string, exitOK bool, ws *workspace) {
	facts := classifyCommand(e.Command, outputText, exitOK, ws)
	if facts == nil {
		facts = &commandFacts{}
	}
	classifyPaths(facts, e.Files, ws)
	if facts.empty() {
		return
	}
	facts.sortCategories()
	e.Categories = facts.categories
	e.Targets = facts.targets
	e.ShellMutations = facts.mutations
}
