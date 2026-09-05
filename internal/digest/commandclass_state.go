package digest

// This file credits the two categories a single command cannot prove on its
// own: command.retried needs the commands already seen in this run, and
// sandbox.denied needs the failed command's output matched against a fixed
// list of denial markers.

import (
	"slices"
	"strings"
)

// denialMarkers is the whole of what proves sandbox.denied: a closed list of
// substrings, matched case-insensitively. A failed command is only called
// sandboxed when its output says so in one of these words — no heuristics.
var denialMarkers = []string{
	"operation not permitted",
	"permission denied",
	"read-only file system",
	"eacces",
	"sandbox",
}

// applyRunState credits the two categories that a single command cannot prove
// on its own. Call it after classifyEventCommand, with the digest holding
// every event seen so far in this run, and with the same outputText passed to
// classifyEventCommand — not e.Output, which digest.go has already capped to
// MaxEventOutputChars (8,000 chars) and may have cut the marker this category
// depends on before the classifier's own, more generous bound ever saw it.
func applyRunState(d *Digest, e *Event, outputText string) {
	if e.Kind != KindCommand {
		return
	}
	added := &commandFacts{}
	if commandRanEarlier(d, e) {
		added.categories = append(added.categories, "command.retried")
	}
	// sandbox.denied is the one category that exists only on failure. Like every
	// other output-derived fact it is trusted only for a single-segment command:
	// in `mkdir out && cp a out/`, the marker in the output does not say which
	// half the sandbox refused.
	denial := trustedOutput(chainSegmentTexts(splitCommandChain(unwrapShell(e.Command))), outputText)
	failed := e.IsError || (e.ExitCode != nil && *e.ExitCode != 0)
	if failed && hasDenialMarker(denial) {
		added.categories = append(added.categories, "sandbox.denied")
	}
	if len(added.categories) == 0 {
		return
	}
	facts := &commandFacts{categories: e.Categories}
	facts.merge(added)
	facts.sortCategories()
	e.Categories = facts.categories
}

// commandRanEarlier reports whether the same command already ran earlier in
// this run, judged by srcLine — the source line the command started on —
// rather than by position in d.Timeline. Timeline order is not always source
// order: codex appends a command that started but never completed only once
// the whole stream has been read (codexParseState.finalize), after every
// command that did complete, even one that started later. Scanning by slice
// position would then credit the wrong side of two commands with the same
// text; comparing srcLine judges every event against the commands that
// actually preceded it, including e itself (prior.srcLine == e.srcLine is
// never "earlier", so e never matches itself).
func commandRanEarlier(d *Digest, e *Event) bool {
	normalized := normalizeCommandText(e.Command)
	if normalized == "" {
		return false
	}
	// ponytail: rescan per command; a seen-set on Digest if runs get long.
	for i := range d.Timeline {
		prior := &d.Timeline[i]
		if prior.Kind != KindCommand || prior.srcLine >= e.srcLine {
			continue
		}
		if normalizeCommandText(prior.Command) == normalized {
			return true
		}
	}
	return false
}

// normalizeCommandText collapses only unquoted horizontal separator space.
// Whitespace inside quotes and command-separating newlines are semantic and
// must survive, or two different programs can be credited as one retry.
func normalizeCommandText(command string) string {
	command = strings.Trim(command, " \t")
	var normalized strings.Builder
	normalized.Grow(len(command))
	inSingle, inDouble, space := false, false, false
	last := byte(0)
	write := func(c byte) {
		normalized.WriteByte(c)
		last = c
	}
	for i := 0; i < len(command); i++ {
		c := command[i]
		if c == '\\' && !inSingle {
			if space {
				write(' ')
				space = false
			}
			write(c)
			if i+1 < len(command) {
				i++
				write(command[i])
			}
			continue
		}
		if !inSingle && !inDouble && (c == ' ' || c == '\t') {
			space = normalized.Len() > 0 && last != '\n'
			continue
		}
		if !inSingle && !inDouble && c == '\n' {
			space = false
			write(c)
			continue
		}
		if space {
			write(' ')
			space = false
		}
		write(c)
		if c == '\'' && !inDouble {
			inSingle = !inSingle
		} else if c == '"' && !inSingle {
			inDouble = !inDouble
		}
	}
	return normalized.String()
}

func hasDenialMarker(output string) bool {
	lowered := strings.ToLower(output)
	return slices.ContainsFunc(denialMarkers, func(marker string) bool {
		return strings.Contains(lowered, marker)
	})
}
