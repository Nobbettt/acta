package digest

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// This file answers "what did this shell command actually do to the workspace?"
// by looking, instead of by reading the command text and predicting.
//
// The prediction approach is why classification kept inventing facts. Whether
// `chmod -c 0644 f` changed anything depends on f's mode before it ran; whether
// `rg TODO .github` read a file depends on whether .github is a directory;
// where `cp -T a b` lands depends on whether b is a symlink. None of that is in
// the command text, so a text-only classifier must guess, and a guess published
// as a path is a false audit record.
//
// So the command text is used only to decide WHICH paths are worth looking at.
// It never decides what happened. A path the filesystem does not show changing
// produces no mutation, which means this can miss an effect but cannot fabricate
// one - the direction that matters for a record something is audited against.
//
// Observation happens while the run is live, because that is the only moment
// the before-state exists. It is then written into the digest and replayed on a
// re-digest, exactly as captured file patches already are, so re-digesting a
// bundle stays byte-identical instead of depending on what the workspace looks
// like later.

// maxObservedCandidatePaths bounds the stat calls one command may cause. A
// command naming more paths than this is doing something broad enough that
// per-path attribution was never going to be meaningful anyway.
const maxObservedCandidatePaths = 64

// pathState is the cheap fingerprint taken either side of a command. It is
// deliberately not a content hash: this decides whether a path changed, and
// reading every candidate's bytes twice per command would cost far more than
// the question is worth.
type pathState struct {
	exists  bool
	isDir   bool
	size    int64
	modTime time.Time
	mode    os.FileMode
}

// observedEffect is one change the filesystem showed. Kind is create, delete or
// modify.
type observedEffect struct {
	path string // workspace-relative, as every published path must be
	kind string
}

// observePathStates fingerprints each candidate. Paths are workspace-relative
// and are resolved against the recorded root; anything that escapes the
// workspace, or that cannot be resolved, is skipped rather than guessed at.
func observePathStates(ws *workspace, candidates []string) map[string]pathState {
	if ws == nil || ws.root == "" || len(candidates) == 0 {
		return nil
	}
	states := make(map[string]pathState, len(candidates))
	for _, candidate := range candidates {
		if len(states) >= maxObservedCandidatePaths {
			break
		}
		if _, seen := states[candidate]; seen {
			continue
		}
		rel, ok := normalizeWorkspacePath(candidate, ws)
		if !ok {
			continue
		}
		states[rel] = statPath(ws, rel)
	}
	return states
}

func statPath(ws *workspace, rel string) pathState {
	target := filepath.Join(ws.root, filepath.FromSlash(rel))
	info, err := os.Lstat(target)
	if err != nil {
		return pathState{}
	}
	return pathState{
		exists:  true,
		isDir:   info.IsDir(),
		size:    info.Size(),
		modTime: info.ModTime(),
		mode:    info.Mode(),
	}
}

// diffPathStates reports what changed between two fingerprints of the same
// paths. Only paths present in both maps are compared: one the command did not
// cause us to look at before it ran tells us nothing about whether it caused
// the change.
func diffPathStates(before, after map[string]pathState) []observedEffect {
	if len(before) == 0 || len(after) == 0 {
		return nil
	}
	var effects []observedEffect
	for path, was := range before {
		is, looked := after[path]
		if !looked {
			continue
		}
		switch {
		case was.exists && !is.exists:
			effects = append(effects, observedEffect{path: path, kind: "delete"})
		case !was.exists && is.exists:
			effects = append(effects, observedEffect{path: path, kind: "create"})
		case was.exists && is.exists && pathStateChanged(was, is):
			effects = append(effects, observedEffect{path: path, kind: "modify"})
		}
	}
	sortObservedEffects(effects)
	return effects
}

// pathStateChanged treats a size, mode or modification-time difference as a
// change. Mode matters because a permission change leaves everything else
// untouched, and it is the only evidence a chmod actually did anything.
func pathStateChanged(was, is pathState) bool {
	return was.size != is.size || was.mode != is.mode || !was.modTime.Equal(is.modTime) ||
		was.isDir != is.isDir
}

func sortObservedEffects(effects []observedEffect) {
	// Ordering must not depend on map iteration: a digest is compared byte for
	// byte against a re-digest of the same bundle.
	for i := 1; i < len(effects); i++ {
		for j := i; j > 0 && observedEffectLess(effects[j], effects[j-1]); j-- {
			effects[j], effects[j-1] = effects[j-1], effects[j]
		}
	}
}

func observedEffectLess(a, b observedEffect) bool {
	if a.path != b.path {
		return a.path < b.path
	}
	return a.kind < b.kind
}

// commandObservationCandidates lists the workspace paths worth fingerprinting
// around a command. This is the ONLY use the command text is put to here, and
// it is deliberately generous: naming a path that turns out not to change costs
// one stat and reports nothing, while missing one costs a real effect. What it
// must never do is treat a word as a path when the word does not state one.
//
// A word containing an expansion is skipped for exactly that reason. `${TARGET}`
// names something knowable only at run time, and fingerprinting the literal
// text would watch a path that does not exist while the real one changed
// unobserved - the same fabrication this file exists to end, wearing a
// different hat.
func commandObservationCandidates(command string) []string {
	commands, ok := parseShellCommand(unwrapShell(command))
	if !ok {
		return nil
	}
	var candidates []string
	seen := map[string]bool{}
	add := func(text string) {
		if text == "" || text == "-" || seen[text] {
			return
		}
		seen[text] = true
		candidates = append(candidates, text)
	}
	for _, simple := range commands {
		for i, word := range simple.words {
			// The command word itself names a program, not an operand this
			// command acts on, so it is not worth watching.
			if i == 0 || !word.literal || strings.HasPrefix(word.text, "-") {
				continue
			}
			add(word.text)
		}
		for _, redirect := range simple.redirects {
			// A heredoc word is a delimiter and a dup target is a descriptor;
			// neither is a file. A write redirection target, however, is a path
			// this command may well create.
			if redirect.heredoc || redirect.dupFd || !redirect.word.literal {
				continue
			}
			add(redirect.word.text)
		}
	}
	return candidates
}

// sortedObservedPaths lists the paths of a fingerprint in a stable order, so
// the second look happens over exactly the first one's set.
func sortedObservedPaths(states map[string]pathState) []string {
	paths := make([]string, 0, len(states))
	for path := range states {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}
