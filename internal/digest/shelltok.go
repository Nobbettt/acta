package digest

import (
	"path"
	"regexp"
	"strings"
	"sync"
)

// shellTokens is a minimal POSIX-ish tokenizer (Go has no stdlib shlex).
// Returns nil on unterminated quoting — callers treat that as "cannot parse".
// It has no $(), backtick, or expansion awareness; heuristics downstream fail
// conservatively when tokens look wrong.
func shellTokens(s string) []string {
	var tokens []string
	var current strings.Builder
	inToken := false
	i := 0
	for i < len(s) {
		c := s[i]
		switch c {
		case '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return nil
			}
			current.WriteString(s[i+1 : i+1+end])
			inToken = true
			i += end + 2
		case '"':
			i++
			for {
				if i >= len(s) {
					return nil
				}
				if s[i] == '"' {
					i++
					break
				}
				if s[i] == '\\' && i+1 < len(s) {
					next := s[i+1]
					if next == '"' || next == '\\' || next == '$' || next == '`' {
						current.WriteByte(next)
						i += 2
						continue
					}
				}
				current.WriteByte(s[i])
				i++
			}
			inToken = true
		case '\\':
			if i+1 >= len(s) {
				return nil
			}
			current.WriteByte(s[i+1])
			inToken = true
			i += 2
		case ' ', '\t', '\n', '\r':
			if inToken {
				tokens = append(tokens, current.String())
				current.Reset()
				inToken = false
			}
			i++
		default:
			current.WriteByte(c)
			inToken = true
			i++
		}
	}
	if inToken {
		tokens = append(tokens, current.String())
	}
	return tokens
}

// unwrapShell strips a `/bin/zsh -lc "..."` (or similar) wrapper.
func unwrapShell(command string) string {
	if len(command) > maxCommandTokenizationChars {
		return command
	}
	tokens := shellTokens(command)
	if len(tokens) >= 3 && isShell(tokens[0]) && tokens[1] == "-lc" {
		return tokens[2]
	}
	return command
}

// isShell reports whether tok invokes a POSIX-ish shell, so `X -lc arg` is only
// unwrapped when X is actually a shell (not e.g. `ls -lc src`).
func isShell(tok string) bool {
	switch path.Base(tok) {
	case "sh", "bash", "zsh", "dash", "ksh":
		return true
	}
	return false
}

func commandTokens(command string) []string {
	if len(command) > maxCommandTokenizationChars {
		return nil
	}
	return shellTokens(unwrapShell(command))
}

func tokensForSegment(segment string) []string {
	if len(segment) > maxCommandTokenizationChars {
		return nil
	}
	return shellTokens(segment)
}

var (
	wordReMu    sync.Mutex
	wordReCache = map[string]*regexp.Regexp{}
)

// commandHasWord reports whether command contains word as a whole shell token.
// The regex is cached per word: the vocabulary is a fixed handful, but this is
// called up to ~8 times per command event, so recompiling each time is pure
// waste.
func commandHasWord(command, word string) bool {
	wordReMu.Lock()
	re, ok := wordReCache[word]
	if !ok {
		re = regexp.MustCompile(`(^|[^A-Za-z0-9_./-])` + regexp.QuoteMeta(word) + `([^A-Za-z0-9_./-]|$)`)
		wordReCache[word] = re
	}
	wordReMu.Unlock()
	return re.MatchString(command)
}

func splitCommandSegments(command string) []string {
	if len(command) > maxCommandTokenizationChars {
		return []string{command}
	}
	var segments []string
	for _, segment := range segmentSplitRe.Split(command, -1) {
		if s := strings.TrimSpace(segment); s != "" {
			segments = append(segments, s)
		}
	}
	return segments
}
