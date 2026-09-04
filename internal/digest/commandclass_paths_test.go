package digest

import (
	"reflect"
	"slices"
	"testing"
)

// Every path facet, on the read paths a command was credited with. The
// negatives are the near misses: a README-like name that is not an instruction
// file, and a directory whose name merely starts with a generated one.
func TestClassifyPathsReadFacets(t *testing.T) {
	cases := []struct {
		name  string
		paths []string
		want  []string
	}{
		{"agents md", []string{"AGENTS.md"}, []string{"instructions.read"}},
		{"claude md nested", []string{"docs/CLAUDE.md"}, []string{"instructions.read"}},
		{"readme without extension", []string{"README"}, []string{"instructions.read"}},
		{"readme md", []string{"README.md"}, []string{"instructions.read"}},
		{"contributing", []string{"CONTRIBUTING"}, []string{"instructions.read"}},
		{"contributing md", []string{"CONTRIBUTING.md"}, []string{"instructions.read"}},
		{"cursorrules", []string{".cursorrules"}, []string{"instructions.read"}},
		{"editorconfig", []string{".editorconfig"}, []string{"instructions.read"}},
		{"readme-like directory is not an instruction file", []string{"READMEs/notes.md"}, nil},
		{"lowercase readme is not an instruction file", []string{"readme.md"}, nil},
		{"readme suffix is not an instruction file", []string{"README.old"}, nil},

		{"workflow", []string{".github/workflows/ci.yml"}, []string{"path.sensitive"}},
		{"workflow nested", []string{".github/workflows/release/deploy.yml"}, []string{"path.sensitive"}},
		{"dockerfile", []string{"Dockerfile"}, []string{"path.sensitive"}},
		{"dockerfile suffixed", []string{"build/ci/Dockerfile.prod"}, []string{"path.generated", "path.sensitive"}},
		{"docker compose", []string{"docker-compose.yml"}, []string{"path.sensitive"}},
		{"dotenv", []string{".env"}, []string{"path.sensitive"}},
		{"dotenv suffixed", []string{"config/.env.local"}, []string{"path.sensitive"}},
		{"pem", []string{"certs/server.pem"}, []string{"path.sensitive"}},
		{"key", []string{"certs/server.key"}, []string{"path.sensitive"}},
		{"github issue template is not sensitive", []string{".github/ISSUE_TEMPLATE.md"}, nil},
		{"keyboard is not a key file", []string{"src/keyboard.ts"}, nil},
		{"dockerignore is not a dockerfile", []string{".dockerignore"}, nil},

		{"package lock", []string{"package-lock.json"}, []string{"path.generated"}},
		{"nested lock json", []string{"web/pnpm-lock.json"}, []string{"path.generated"}},
		{"lock suffix", []string{"Cargo.lock"}, []string{"path.generated"}},
		{"go sum", []string{"go.sum"}, []string{"path.generated"}},
		{"dist dir", []string{"dist/app.js"}, []string{"path.generated"}},
		{"nested dist dir", []string{"packages/web/dist/app.js"}, []string{"path.generated"}},
		{"build dir", []string{"build/out.o"}, []string{"path.generated"}},
		{"vendor dir", []string{"vendor/github.com/x/y.go"}, []string{"path.generated"}},
		{"node modules", []string{"node_modules/left-pad/index.js"}, []string{"path.generated"}},
		{"dist as a name prefix is not a generated dir", []string{"distributed/x.ts"}, nil},
		{"builder is not a build dir", []string{"builder/x.ts"}, nil},
		{"a file named dist is not a generated dir", []string{"dist"}, nil},
		{"go mod is not generated", []string{"go.mod"}, nil},
		{"locket is not a lockfile", []string{"src/locket.ts"}, nil},

		{"several paths merge and dedupe", []string{"README.md", "AGENTS.md", "dist/a.js", "dist/b.js"}, []string{"instructions.read", "path.generated"}},
		{"ordinary source file", []string{"internal/digest/trace.go"}, nil},
		{"no paths", nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts := &commandFacts{}
			classifyPaths(facts, c.paths, testWorkspace())
			got := slices.Clone(facts.categories)
			slices.Sort(got)
			bothEmpty := len(got) == 0 && len(c.want) == 0
			if !reflect.DeepEqual(got, c.want) && !bothEmpty {
				t.Errorf("classifyPaths(%v) = %v, want %v", c.paths, got, c.want)
			}
		})
	}
}

// control.access exists only because the caller declared a control-plane
// directory; with none declared it can never be credited.
func TestClassifyPathsControlAccess(t *testing.T) {
	cases := []struct {
		name    string
		control string
		paths   []string
		want    bool
	}{
		{"file under the prefix", "stage-control", []string{"stage-control/task.json"}, true},
		{"nested under the prefix", "stage-control", []string{"stage-control/in/task.json"}, true},
		{"the prefix itself", "stage-control", []string{"stage-control"}, true},
		{"absolute prefix inside the workspace", "/repo/stage-control", []string{"stage-control/task.json"}, true},
		{"no prefix configured", "", []string{"stage-control/task.json"}, false},
		{"prefix outside the workspace is ignored", "/elsewhere/stage-control", []string{"stage-control/task.json"}, false},
		{"sibling directory sharing the prefix name", "stage-control", []string{"stage-controls/task.json"}, false},
		{"unrelated path", "stage-control", []string{"src/main.go"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ws := testWorkspace().withControlPrefix(c.control)
			facts := &commandFacts{}
			classifyPaths(facts, c.paths, ws)
			if got := slices.Contains(facts.categories, "control.access"); got != c.want {
				t.Errorf("control.access = %v, want %v (categories %v)", got, c.want, facts.categories)
			}
		})
	}
}

// withControlPrefix must not mutate the workspace it is called on: the digest
// shares one workspace across every event of a run.
func TestWithControlPrefixLeavesTheOriginalAlone(t *testing.T) {
	ws := testWorkspace()
	scoped := ws.withControlPrefix("stage-control")
	if ws.controlPrefix != "" {
		t.Errorf("original workspace mutated: controlPrefix = %q", ws.controlPrefix)
	}
	if scoped.controlPrefix != "stage-control" {
		t.Errorf("scoped controlPrefix = %q, want %q", scoped.controlPrefix, "stage-control")
	}
}

// The facets cover the paths a mutation proved as well as the ones a read did,
// and a mutation target that will not relativize is the escape itself.
func TestClassifyPathsMutationAndTargetFacets(t *testing.T) {
	cases := []struct {
		name  string
		facts commandFacts
		want  []string
	}{
		{
			"deleted lockfile",
			commandFacts{mutations: []ShellMutation{{Kind: "delete", Path: "package-lock.json"}}},
			[]string{"path.generated"},
		},
		{
			"moved env file",
			commandFacts{mutations: []ShellMutation{{Kind: "move", From: ".env", To: "config/.env.bak"}}},
			[]string{"path.sensitive"},
		},
		{
			"path target",
			commandFacts{targets: []CommandTarget{{Kind: "path", Value: "certs/server.pem"}}},
			[]string{"path.sensitive"},
		},
		{
			"non-path target is not a path",
			commandFacts{targets: []CommandTarget{{Kind: "package", Value: "server.pem"}}},
			nil,
		},
		{
			// workspace.escape belongs to the classifier that saw the operand:
			// an escaping path never becomes a target or a mutation, so nothing
			// here can, or should, re-derive it.
			"an unresolvable mutation target credits no facet",
			commandFacts{mutations: []ShellMutation{{Kind: "delete", Path: "/etc/hosts"}}},
			nil,
		},
		{
			"in-workspace mutation is still faceted",
			commandFacts{mutations: []ShellMutation{{Kind: "move", From: "a.md", To: "docs/a.md"}}},
			nil,
		},
		{
			"instructions.read is not credited for a mutated instruction file",
			commandFacts{mutations: []ShellMutation{{Kind: "delete", Path: "AGENTS.md"}}},
			nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts := c.facts
			classifyPaths(&facts, nil, testWorkspace())
			got := slices.Clone(facts.categories)
			slices.Sort(got)
			bothEmpty := len(got) == 0 && len(c.want) == 0
			if !reflect.DeepEqual(got, c.want) && !bothEmpty {
				t.Errorf("classifyPaths = %v, want %v", got, c.want)
			}
		})
	}
}

// classifyPaths must not re-credit a category an earlier classifier already
// added, and must leave that classifier's other findings intact.
func TestClassifyPathsDedupesAgainstExistingCategories(t *testing.T) {
	facts := &commandFacts{categories: []string{"fs.delete", "path.generated"}}
	classifyPaths(facts, []string{"dist/app.js", "go.sum"}, testWorkspace())
	if want := []string{"fs.delete", "path.generated"}; !reflect.DeepEqual(facts.categories, want) {
		t.Errorf("categories = %v, want %v", facts.categories, want)
	}
}
