package digest

// This file adds the facets that follow from the paths a command was already
// credited with. It never resolves a path of its own: every category here is a
// property of a path the read inference or a shell mutation already proved.

import (
	"path"
	"slices"
	"strings"
)

// instructionFiles are the basenames that make a read an instructions.read:
// the files an agent consults to learn how it is expected to behave in this
// repo. Matched case-sensitively, so READMEs/notes.md is an ordinary read.
var instructionFiles = []string{
	"AGENTS.md",
	"CLAUDE.md",
	"README",
	"README.md",
	"CONTRIBUTING",
	"CONTRIBUTING.md",
	".cursorrules",
	".editorconfig",
}

// generatedDirs hold files produced by a tool rather than written by hand.
var generatedDirs = []string{"dist", "build", "vendor", "node_modules"}

// withControlPrefix records the caller-declared control-plane directory — the
// only thing control.access is ever credited from — and returns a copy, so the
// workspace it is called on is left untouched. A directory that does not
// resolve inside the workspace leaves the prefix unset, and with it unset
// control.access simply never fires.
func (w *workspace) withControlPrefix(dir string) *workspace {
	prefix, ok := normalizeWorkspacePath(dir, w)
	if !ok {
		return w
	}
	next := *w
	next.controlPrefix = prefix
	return &next
}

// classifyPaths adds the facets that follow from the paths a command was
// already credited with — instructions.read, control.access, path.sensitive
// and path.generated. It runs after the retrieval step, so paths holds exactly
// the files the command proved it read; the other facets also cover the path
// targets and mutations the classifiers credited. workspace.escape is not one
// of these: an escaping path never reaches a target or a mutation, so it is
// credited where it is seen, by the fs and exec classifiers.
func classifyPaths(facts *commandFacts, paths []string, ws *workspace) {
	added := &commandFacts{}
	credit := func(category string) { added.categories = append(added.categories, category) }

	for _, read := range paths {
		base := path.Base(read)
		if slices.Contains(instructionFiles, base) {
			credit("instructions.read")
		}
		if strings.HasPrefix(base, ".env") {
			credit("env.inspect")
		}
	}
	for _, credited := range creditedPaths(facts, paths, ws) {
		if isSensitivePath(credited) {
			credit("path.sensitive")
		}
		if isGeneratedPath(credited) {
			credit("path.generated")
		}
		if underControlPrefix(credited, ws) {
			credit("control.access")
		}
	}
	facts.merge(added)
}

// creditedPaths is every in-workspace path this command was credited with: the
// read paths plus the path targets and mutation targets the classifiers
// recorded. Paths that do not relativize are dropped here; workspace.escape is
// the only facet that cares about them.
func creditedPaths(facts *commandFacts, paths []string, ws *workspace) []string {
	var credited []string
	add := func(value string) {
		normalized, ok := normalizeWorkspacePath(value, ws)
		if ok && !slices.Contains(credited, normalized) {
			credited = append(credited, normalized)
		}
	}
	for _, read := range paths {
		add(read)
	}
	for _, target := range facts.targets {
		if target.Kind == "path" {
			add(target.Value)
		}
	}
	for _, mutation := range facts.mutations {
		add(mutation.Path)
		add(mutation.From)
		add(mutation.To)
	}
	return credited
}

// isSensitivePath reports the paths whose contents are credentials, CI
// definitions or deployment configuration.
func isSensitivePath(p string) bool {
	if strings.HasPrefix(p, ".github/workflows/") {
		return true
	}
	base := path.Base(p)
	return strings.HasPrefix(base, "Dockerfile") ||
		strings.HasPrefix(base, "docker-compose") ||
		strings.HasPrefix(base, ".env") ||
		strings.HasSuffix(base, ".pem") ||
		strings.HasSuffix(base, ".key")
}

// isGeneratedPath reports the paths a tool produced rather than a human.
func isGeneratedPath(p string) bool {
	base := path.Base(p)
	if base == "go.sum" || strings.HasSuffix(base, "lock.json") || strings.HasSuffix(base, ".lock") {
		return true
	}
	// A whole directory segment must match, so distributed/x.ts is not dist/**;
	// any depth counts, so a monorepo's packages/app/node_modules does.
	for _, segment := range strings.Split(path.Dir(p), "/") {
		if slices.Contains(generatedDirs, segment) {
			return true
		}
	}
	return false
}

// underControlPrefix reports a path inside the caller-declared control plane.
func underControlPrefix(p string, ws *workspace) bool {
	if ws.controlPrefix == "" {
		return false
	}
	return p == ws.controlPrefix || strings.HasPrefix(p, ws.controlPrefix+"/")
}
