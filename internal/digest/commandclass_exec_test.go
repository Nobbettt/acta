package digest

import (
	"reflect"
	"sort"
	"testing"
)

// execClassify runs only the exec classifier over a command, so these cases stay
// independent of what the vcs and fs classifiers credit for the same text.
// output is what classifyCommand's trustedOutput would have produced for this
// command: the real command output for a single-segment command, "" for
// anything else — tests that care pass it explicitly, everyone else leaves it
// empty, exactly like an untrusted multi-segment command would see.
func execClassify(command string, exitOK bool, output string) *commandFacts {
	raw := unwrapShell(command)
	chain := splitCommandChain(raw)
	output = trustedOutput(chainSegmentTexts(chain), output)
	facts := &commandFacts{}
	for _, segment := range chain {
		facts.merge(classifyExec(commandSegment{
			raw:          segment.raw,
			tokens:       tokensForSegment(segment.raw),
			command:      raw,
			output:       output,
			exitOK:       exitOK && !segment.orGated,
			ws:           testWorkspace(),
			cwdUncertain: segment.cwdUncertain,
		}))
	}
	sort.Strings(facts.categories)
	return facts
}

type execCase struct {
	name    string
	command string
	failed  bool
	output  string
	want    []string
	targets []CommandTarget
}

func runExecCases(t *testing.T, cases []execCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := execClassify(c.command, !c.failed, c.output)
			if !reflect.DeepEqual(got.categories, c.want) {
				t.Errorf("categories for %q = %v, want %v", c.command, got.categories, c.want)
			}
			if !reflect.DeepEqual(got.targets, c.targets) {
				t.Errorf("targets for %q = %+v, want %+v", c.command, got.targets, c.targets)
			}
		})
	}
}

func urlTarget(value string) []CommandTarget {
	return []CommandTarget{{Kind: "url", Value: value}}
}
func host(value string) []CommandTarget { return []CommandTarget{{Kind: "host", Value: value}} }

func TestAppendCommandTargetSanitizesEveryKind(t *testing.T) {
	tests := []struct {
		name   string
		target CommandTarget
		want   []CommandTarget
	}{
		{"url origin", CommandTarget{Kind: "url", Value: "https://user:token@example.com/private"}, urlTarget("https://example.com")},
		{"scp url host", CommandTarget{Kind: "url", Value: "git@github.com:org/private.git"}, urlTarget("github.com")},
		{"host origin", CommandTarget{Kind: "host", Value: "ssh://user@build.example.com/private"}, host("ssh://build.example.com")},
		{"malformed host", CommandTarget{Kind: "host", Value: "password=hunter2.example.com"}, nil},
		{"package source", CommandTarget{Kind: "package", Value: "git+https://example.com/private.git"}, nil},
		{"bare package", CommandTarget{Kind: "package", Value: "left-pad"}, []CommandTarget{{Kind: "package", Value: "left-pad"}}},
		{"package extras", CommandTarget{Kind: "package", Value: "requests[socks]"}, []CommandTarget{{Kind: "package", Value: "requests[socks]"}}},
		{"package path", CommandTarget{Kind: "package", Value: "dist/app"}, nil},
		{"package artifact", CommandTarget{Kind: "package", Value: "dist/app.tgz"}, nil},
		{"opaque credential package", CommandTarget{Kind: "package", Value: "user:token@example.com"}, nil},
		{"workspace path", CommandTarget{Kind: "path", Value: "internal/digest/trace.go"}, []CommandTarget{{Kind: "path", Value: "internal/digest/trace.go"}}},
		{"traversal path", CommandTarget{Kind: "path", Value: "../private"}, nil},
		{"path expression", CommandTarget{Kind: "path", Value: "$ROOT/private"}, nil},
		{"pattern glob", CommandTarget{Kind: "pattern", Value: "*.secret"}, nil},
		{"free-form pattern", CommandTarget{Kind: "pattern", Value: "password=hunter2"}, nil},
		{"object ref", CommandTarget{Kind: "ref", Value: "0000000000000000000000000000000000000000"}, []CommandTarget{{Kind: "ref", Value: "0000000000000000000000000000000000000000"}}},
		{"ref substitution", CommandTarget{Kind: "ref", Value: "$(git rev-parse HEAD)"}, nil},
		{"tool name", CommandTarget{Kind: "tool", Value: "Read"}, []CommandTarget{{Kind: "tool", Value: "Read"}}},
		{"free-form tool", CommandTarget{Kind: "tool", Value: "password=hunter2"}, nil},
		{"unknown kind", CommandTarget{Kind: "mode", Value: "hunter2"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			facts := &commandFacts{}
			appendCommandTarget(facts, tt.target)
			if !reflect.DeepEqual(facts.targets, tt.want) {
				t.Fatalf("targets = %+v, want %+v", facts.targets, tt.want)
			}
		})
	}
}

func TestClassifyExecNetworkEgress(t *testing.T) {
	runExecCases(t, []execCase{
		{
			name:    "curl url",
			command: "curl https://example.com/api",
			want:    []string{"network.egress"},
			targets: urlTarget("https://example.com"),
		},
		{
			name:    "failed curl still egress",
			command: "curl https://example.com/api",
			failed:  true,
			want:    []string{"network.egress"},
			targets: urlTarget("https://example.com"),
		},
		{
			name:    "wget download is also an extract",
			command: "wget https://example.com/a.tgz -O a.tgz",
			want:    []string{"archive.extract", "network.egress"},
			targets: urlTarget("https://example.com"),
		},
		{
			name:    "credentialed url is published without its credentials",
			command: "curl https://user:ghp_secrettoken@api.github.com/repos/x",
			want:    []string{"network.egress"},
			targets: urlTarget("https://api.github.com"),
		},
		{
			name:    "ordinary url publishes only its origin",
			command: "curl https://api.github.com/repos/x",
			want:    []string{"network.egress"},
			targets: urlTarget("https://api.github.com"),
		},
		{
			name:    "query string credential is removed with the url path",
			command: `curl "https://api.example.com/v1/runs?access_token=ghp_REDACTEDSECRET"`,
			want:    []string{"network.egress"},
			targets: urlTarget("https://api.example.com"),
		},
		{
			name:    "url fragment is removed with the url path",
			command: "curl https://api.example.com/v1/runs#internal-token",
			want:    []string{"network.egress"},
			targets: urlTarget("https://api.example.com"),
		},
		{
			// Regression: webhook credentials commonly live in the URL path, so
			// stripping only userinfo, query and fragment still published them.
			name:    "credential-bearing url path publishes only the origin",
			command: "curl https://hooks.slack.com/services/T00000000/B00000000/SECRET_TOKEN",
			want:    []string{"network.egress"},
			targets: urlTarget("https://hooks.slack.com"),
		},
		{
			name:    "ssh host operand",
			command: "ssh deploy@build.example.com uptime",
			want:    []string{"network.egress"},
			targets: host("build.example.com"),
		},
		{
			name:    "ssh port flag value is not the host",
			command: "ssh -p 2222 build.example.com uptime",
			want:    []string{"network.egress"},
			targets: host("build.example.com"),
		},
		{
			name:    "ssh log flag value is not the host",
			command: "ssh -E session.log build.example.com uptime",
			want:    []string{"network.egress"},
			targets: host("build.example.com"),
		},
		{
			name:    "ssh remote command url is not the peer",
			command: "ssh build.example.com echo https://never-contacted.invalid/path",
			want:    []string{"network.egress"},
			targets: host("build.example.com"),
		},
		{
			name:    "ssh subsystem flag does not swallow the host",
			command: "ssh -s build.example.com sftp",
			want:    []string{"network.egress"},
			targets: host("build.example.com"),
		},
		{
			// Regression: same clustered-flag gap as pip's -qr, here the value is
			// a port rather than a requirements file: -qp swallowed "2222" as a
			// plain flag instead of consuming it as -p's value, so the port itself
			// was published as the host.
			name:    "ssh clustered port flag does not publish the port as the host",
			command: "ssh -qp 2222 build.example.com uptime",
			want:    []string{"network.egress"},
			targets: host("build.example.com"),
		},
		{
			name:    "scp remote destination",
			command: "scp notes.txt deploy@build.example.com:/srv/notes.txt",
			want:    []string{"network.egress"},
			targets: host("build.example.com"),
		},
		{
			name:    "scp bracketed ipv6 destination",
			command: "scp /dev/null '[::1]:/tmp/'",
			want:    []string{"network.egress"},
			targets: host("::1"),
		},
		{
			name:    "scp user and bracketed ipv6 destination",
			command: "scp notes.txt 'deploy@[2001:db8::1]:/srv/notes.txt'",
			want:    []string{"network.egress"},
			targets: host("2001:db8::1"),
		},
		{
			name:    "expanded ssh host is withheld",
			command: `ssh "$HOST" true`,
			want:    []string{"network.egress"},
		},
		{
			name:    "malformed ssh operand cannot publish credential text",
			command: "ssh 'build.example.com password=supersecret'",
			failed:  true,
			want:    []string{"network.egress"},
		},
		{
			name:    "rsync remote form",
			command: "rsync -a dist/ deploy@build.example.com:/srv/app/",
			want:    []string{"network.egress"},
			targets: host("build.example.com"),
		},
		{
			name:    "rsync daemon URL",
			command: "rsync rsync://mirror.example.com/module/a ./a",
			want:    []string{"network.egress"},
			targets: urlTarget("rsync://mirror.example.com"),
		},
		{
			name:    "rsync rejects https spelling as a remote operand",
			command: "rsync https://example.com/a ./a",
		},
		{
			name:    "nc host and port",
			command: "nc build.example.com 443",
			want:    []string{"network.egress"},
			targets: host("build.example.com"),
		},
		{
			name:    "nc source address value is not the host",
			command: "nc -s 127.0.0.2 build.example.com 443",
			want:    []string{"network.egress"},
			targets: host("build.example.com"),
		},
		{
			// Regression: curl's -s (silent) takes no value, unlike ssh's -i or
			// scp/rsync's -w which share the -o/-i/-w spellings. Treating -s as
			// a value flag swallowed the only operand and hid the request.
			name:    "curl silent flag does not swallow the scheme-less host",
			command: "curl -s example.com",
			want:    []string{"network.egress"},
		},
		{
			// Regression: execRemoteHost used to parse ANY curl/wget operand as
			// an [user@]host:path spec, so a -u user:password value fell through
			// execOperands (curl has no -u host flag) and was published as the
			// contacted host, a credential landing in a CommandTarget. curl/wget
			// now never infer a host this way; the command still credits
			// network.egress, just without a target it cannot prove.
			name:    "curl basic auth credential is not published as a host",
			command: "curl -u sk_live_ABCDEF: api.example.com/v1/charges",
			want:    []string{"network.egress"},
		},
		{
			name:    "curl auth header value is not published as a host",
			command: `curl -H "Authorization: Bearer sk-live-XYZ" example.com`,
			want:    []string{"network.egress"},
		},
		{
			name:    "curl user:pass operand is not published as a host",
			command: "curl -u admin:hunter2 example.com",
			want:    []string{"network.egress"},
		},
		{
			name:    "curl referrer url is not the destination",
			command: "curl -e https://referrer.example.com https://api.example.com/data",
			want:    []string{"network.egress"},
			targets: urlTarget("https://api.example.com"),
		},
		{
			name:    "curl proxy url is not the destination",
			command: "curl --proxy http://proxy.internal:3128 https://api.example.com/v1/data",
			want:    []string{"network.egress"},
			targets: urlTarget("https://api.example.com"),
		},
		{
			name:    "curl short proxy url is not the destination",
			command: "curl -x http://proxy.internal:3128 https://api.example.com/v2/data",
			want:    []string{"network.egress"},
			targets: urlTarget("https://api.example.com"),
		},
		{
			name:    "wget output value url is not the destination",
			command: "wget -O https://local-name.example https://api.example.com/archive",
			want:    []string{"archive.extract", "network.egress"},
			targets: urlTarget("https://api.example.com"),
		},
		{
			name:    "wget user agent url is not the destination",
			command: "wget --user-agent https://decoy.example https://real.example",
			want:    []string{"network.egress"},
			targets: urlTarget("https://real.example"),
		},
		{
			name:    "wget short user agent value is not the destination",
			command: "wget -U https://decoy.example https://real.example",
			want:    []string{"network.egress"},
			targets: urlTarget("https://real.example"),
		},
		// Negatives.
		{name: "echoed curl", command: "echo curl https://example.com/api"},
		{name: "quoted curl in a python string", command: `python -c "print('curl https://example.com')"`},
		{name: "local rsync never leaves the machine", command: "rsync -a dist/ /tmp/dist/"},
		{name: "rsync exclude pattern is not a remote spec", command: "rsync -a --exclude cache:old src/ dst/"},
		{name: "nc listener has no peer", command: "nc -l 8080"},
		{name: "nc listener with bind host has no peer", command: "nc -l 127.0.0.1 8080"},
		{name: "successful conditional skips curl", command: "true || curl https://never.example"},
		{name: "unbalanced quotes classify nothing", command: `curl "https://example.com/api`},
		{name: "empty command", command: ""},
		{name: "curl version probe opens no socket", command: "curl --version"},
		{name: "curl help with url opens no socket", command: "curl --help https://never.invalid"},
		{name: "curl version with url opens no socket", command: "curl --version https://example.com"},
		{name: "curl clustered short version opens no socket", command: "curl -sV https://never.invalid"},
		{name: "ssh config dump opens no connection", command: "ssh -G example.com"},
		{name: "ssh clustered config dump opens no connection", command: "ssh -vG example.com"},
		{name: "wget help probe opens no socket", command: "wget --help"},
	})
}

func TestClassifyCommandSuppressesUnexecutedConditionalExecSegments(t *testing.T) {
	for _, c := range []struct {
		name    string
		command string
		exitOK  bool
	}{
		{name: "successful or skips curl", command: "true || curl https://never.example", exitOK: true},
		{name: "failed and skips curl", command: "false && curl https://never.example", exitOK: false},
		{name: "wrapped false skips background launcher", command: "command false && nohup sleep 60", exitOK: false},
		{name: "exit terminates later command", command: "exit 0; curl https://never.example", exitOK: true},
		{name: "exec terminates later command", command: "exec true; curl https://never.example", exitOK: true},
		{name: "known outcome propagates through or list", command: "true || false || nohup sleep 60", exitOK: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if facts := classifyCommand(c.command, "", c.exitOK, testWorkspace()); facts != nil {
				t.Fatalf("classifyCommand(%q) = %+v, want no facts", c.command, facts)
			}
		})
	}
}

func TestClassifyExecForgeMutate(t *testing.T) {
	runExecCases(t, []execCase{
		{name: "pr create", command: "gh pr create --fill", want: []string{"forge.mutate"}},
		{name: "pr merge", command: "gh pr merge 12 --squash", want: []string{"forge.mutate"}},
		{name: "issue comment", command: "gh issue comment 4 --body done", want: []string{"forge.mutate"}},
		{name: "release upload", command: "gh release upload v1.2.0 acta.tgz", want: []string{"forge.mutate"}},
		{name: "pr create help changes nothing", command: "gh pr create --help"},
		{name: "issue close short help changes nothing", command: "gh issue close -h"},
		// Negatives.
		{name: "pr view is a read", command: "gh pr view 12"},
		{name: "issue list is a read", command: "gh issue list"},
		{name: "failed pr create changed nothing", command: "gh pr create --fill", failed: true},
		{name: "release list is a read", command: "gh release list"},
		{name: "release view is a read", command: "gh release view v1.2.0"},
		{name: "release download is a read", command: "gh release download v1.2.0"},
	})
}

func TestClassifyExecPackageInstall(t *testing.T) {
	runExecCases(t, []execCase{
		{
			name:    "npm install one package",
			command: "npm install left-pad",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "left-pad"}},
		},
		{
			name:    "yarn add two packages",
			command: "yarn add react react-dom",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "react"}, {Kind: "package", Value: "react-dom"}},
		},
		{name: "bare npm install credits no target", command: "npm install", want: []string{"package.install"}},
		{
			name:    "pip install from a credentialed url has no package target",
			command: "pip install git+https://user:token@example.com/org/repo.git",
			want:    []string{"package.install"},
		},
		{
			// A package URL is a source location, not a package name; even its
			// sanitized origin must not become a package target.
			name:    "pip install from an url has no package target",
			command: "pip install https://example.com/pkg.tar.gz?token=ghp_REDACTEDSECRET",
			want:    []string{"package.install"},
		},
		{
			name:    "pip package url path has no package target",
			command: "pip install https://packages.example.test/sk-live-SECRET/pkg.whl",
			want:    []string{"package.install"},
		},
		{
			name:    "scoped npm package name is unaffected",
			command: "npm install @testing-library/react",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "@testing-library/react"}},
		},
		{
			name:    "npm alias package is preserved",
			command: "npm install my-react@npm:react@18.3.1",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "my-react@npm:react@18.3.1"}},
		},
		{
			name:    "pip install",
			command: "pip3 install ruff",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "ruff"}},
		},
		{
			name:    "pip requirements file is not a package",
			command: "pip install -r requirements.txt",
			want:    []string{"package.install"},
		},
		{
			// Regression: execOperands only matched a value flag by exact token,
			// so a clustered short flag ending in one (pip's -r inside -qr) was
			// skipped as a plain flag and its value fell through as a package.
			name:    "clustered flag value is not a package",
			command: "pip install -qr requirements.txt",
			want:    []string{"package.install"},
		},
		{
			name:    "go get",
			command: "go get github.com/google/go-cmp",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "github.com/google/go-cmp"}},
		},
		{
			name:    "cargo add",
			command: "cargo add serde",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "serde"}},
		},
		{
			name:    "brew install",
			command: "brew install jq",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "jq"}},
		},
		{
			name:    "gem install",
			command: "gem install bundler",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "bundler"}},
		},
		{
			name:    "attached redirect target is not a package",
			command: "npm install --save-dev jest >install.log",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "jest"}},
		},
		{
			// Regression: an empty quoted operand must not become a target —
			// schemas/*.schema.json require target.value to be non-empty, and a
			// zero-length "package" is not a package name anyone installed.
			name:    "empty quoted operand credits no target",
			command: `npm install ""`,
			want:    []string{"package.install"},
		},
		{
			// Regression: an operand that is entirely userinfo strips down to
			// the empty string, not the original operand — the emptiness check
			// must run after stripURLCredentials, not before it.
			name:    `operand that strips to empty credits no target`,
			command: `npm install //user@`,
			want:    []string{"package.install"},
		},
		{
			name:    "credential-shaped package without a safe origin is withheld",
			command: "npm install user:token@packages.example.test",
			want:    []string{"package.install"},
		},
		{
			name:    "command substitution is not a package target",
			command: `npm install "$(printf lodash)"`,
			want:    []string{"package.install"},
		},
		// Regression: an install flag outside execPackageValueFlags fell through
		// as an ordinary flag, so execOperands never skipped its value — the
		// value itself, not a package anyone installed, was published.
		{
			name:    "cargo add feature flag value is not a package",
			command: "cargo add serde --features derive",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "serde"}},
		},
		{
			name:    "npm workspace flag value is not a package",
			command: "npm install -w api left-pad",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "left-pad"}},
		},
		{
			name:    "pnpm filter flag value is not a package",
			command: "pnpm add --filter web react",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "react"}},
		},
		{
			// pip's --proxy carries a credential the same way a URL does; before
			// this fix net/url parsed it as scheme "admin" with an opaque body
			// (no recognisable userinfo), so stripURLCredentials left it
			// untouched and it was published as a package name outright.
			name:    "pip proxy credential is not a package",
			command: "pip install --proxy admin:hunter2@proxy.example.com requests",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "requests"}},
		},
		{
			name: "pip value flags are never package targets",
			command: "pip install --timeout 60 --retries 2 --root /tmp/out --trusted-host pypi.org " +
				"--upgrade-strategy eager --no-binary :all: --only-binary wheel --log pip.log " +
				"--exists-action i --progress-bar off --global-option build --config-settings key=value requests",
			want:    []string{"package.install", "workspace.escape"},
			targets: []CommandTarget{{Kind: "package", Value: "requests"}},
		},
		{
			name:    "pip report path is not a package",
			command: "pip install --report report.json requests",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "requests"}},
		},
		{
			name:    "attached pip report path is not a package",
			command: "pip install --report=report.json requests",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "requests"}},
		},
		{
			name:    "node manager value flags are never package targets",
			command: "npm install --userconfig ./npmrc --omit optional --tag next left-pad",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "left-pad"}},
		},
		{
			name:    "npm install strategy is not a package",
			command: "npm install --install-strategy hoisted lodash",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "lodash"}},
		},
		{
			name:    "attached npm install strategy is not a package",
			command: "npm install --install-strategy=hoisted lodash",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "lodash"}},
		},
		{
			name:    "unmodelled install flag withholds every package target",
			command: "npm install --future-output report.json lodash",
		},
		{
			name:    "npm otp credential is never a package target",
			command: "npm install --otp 123456 private-package",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "private-package"}},
		},
		{
			name:    "attached npm otp credential is never a package target",
			command: "npm install --otp=123456 private-package",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "private-package"}},
		},
		{
			name:    "gem short version value is not a package",
			command: "gem install rails -v 7.0.4",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "rails"}},
		},
		{
			name:    "gem long version value is not informational",
			command: "gem install rails --version 7.0.4",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "rails"}},
		},
		{
			name:    "gem install directory is not a package",
			command: "gem install -i vendor/gems bundler",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "bundler"}},
		},
		{
			name:    "gem long install directory is not a package",
			command: "gem install --install-dir vendor/gems bundler",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "bundler"}},
		},
		{name: "npm artifact path is not a package", command: "npm install dist/app.tgz", want: []string{"package.install"}},
		{name: "yarn local path is not a package", command: "yarn add ./local", want: []string{"package.install"}},
		{name: "pnpm parent path is not a package", command: "pnpm add ../pkg", want: []string{"package.install"}},
		{name: "pip3 artifact path is not a package", command: "pip3 install wheels/app.whl", want: []string{"package.install"}},
		{name: "go local pattern is not a package", command: "go get ./...", want: []string{"package.install"}},
		{name: "cargo local artifact is not a package", command: "cargo add ./local.zip", want: []string{"package.install"}},
		{name: "gem local artifact is not a package", command: "gem install ./x.gem", want: []string{"package.install"}},
		{name: "brew local path is not a package", command: "brew install ./formula.rb", want: []string{"package.install"}},
		{
			name:    "pip extras are preserved",
			command: "pip install requests[socks]",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "requests[socks]"}},
		},
		// Negatives.
		{name: "npm dry run installs nothing", command: "npm install --dry-run left-pad"},
		{name: "npm package-lock-only installs nothing", command: "npm install --package-lock-only left-pad"},
		{
			name:    "npm disabled package lock only installs",
			command: "npm install --package-lock-only=false left-pad",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "left-pad"}},
		},
		{name: "pnpm lockfile-only installs nothing", command: "pnpm install --lockfile-only left-pad"},
		{name: "yarn update-lockfile mode installs nothing", command: "yarn install --mode=update-lockfile left-pad"},
		{name: "pip attached dry run installs nothing", command: "pip install --dry-run=true requests"},
		{name: "cargo dry run installs nothing", command: "cargo add --dry-run serde"},
		{name: "brew short dry run installs nothing", command: "brew install -n jq"},
		{name: "gem explain installs nothing", command: "gem install --explain rails"},
		{name: "failed npm install installed nothing", command: "npm install left-pad", failed: true},
		{name: "npm ci is not in the table", command: "npm ci"},
		{name: "go list is not an install", command: "go list ./..."},
		{name: "echoed pip install", command: "echo pip install ruff"},
	})
}

func TestClassifyExecWorkspaceEscapeFlags(t *testing.T) {
	runExecCases(t, []execCase{
		{
			name:    "global npm install",
			command: "npm install -g typescript",
			want:    []string{"package.install", "workspace.escape"},
			targets: []CommandTarget{{Kind: "package", Value: "typescript"}},
		},
		{
			name:    "pip user install",
			command: "pip install --user ruff",
			want:    []string{"package.install", "workspace.escape"},
			targets: []CommandTarget{{Kind: "package", Value: "ruff"}},
		},
		{
			name:    "global git config",
			command: "git config --global user.name acta",
			want:    []string{"workspace.escape"},
		},
		// Negatives.
		{
			name:    "local npm install stays inside",
			command: "npm install typescript",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "typescript"}},
		},
		{name: "local git config", command: "git config user.name acta"},
		{name: "failed global install escaped nothing", command: "npm install -g typescript", failed: true},
		{name: "dry-run global install escaped nothing", command: "npm install -g --dry-run typescript"},
		{name: "unknown global install flag proves no mutation", command: "npm install -g --future-output report.json typescript"},
		{
			name:    "explicitly disabled npm global flag stays local",
			command: "npm install --global=false left-pad",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "left-pad"}},
		},
		{name: "global git config help writes nothing", command: "git config --global --help"},
		{name: "unknown global config flag proves no mutation", command: "git config --global --future user.name acta"},
		// Regression: a global config *read* mutates nothing and must not be
		// credited workspace.escape.
		{name: "global git config get is a read", command: "git config --global --get user.email"},
		{name: "global git config one-arg shorthand is a read", command: "git config --global user.email"},
		{name: "global git config list is a read", command: "git config --global --list"},
		{name: "global git config get-regexp is a read", command: "git config --global --get-regexp user.name '.*'"},
		{name: "global git config get-urlmatch is a read", command: "git config --global --get-urlmatch remote.origin.url https://example.com"},
		{
			name:    "global git config unset is still a write",
			command: "git config --global --unset user.email",
			want:    []string{"workspace.escape"},
		},
	})
}

func TestClassifyExecVerifyRun(t *testing.T) {
	runExecCases(t, []execCase{
		{name: "go test", command: "go test ./...", want: []string{"verify.run"}},
		{name: "failing go test is still a test run", command: "go test ./...", failed: true, want: []string{"verify.run"}},
		{name: "go build", command: "go build ./...", want: []string{"verify.run"}},
		{name: "go vet", command: "go vet ./...", want: []string{"verify.run"}},
		{name: "pytest", command: "pytest -q tests", want: []string{"verify.run"}},
		{name: "pytest help runs no verification", command: "pytest --help"},
		{name: "pytest clustered help runs no verification", command: "pytest -qh"},
		{name: "vitest", command: "vitest run", want: []string{"verify.run"}},
		{name: "cargo clippy", command: "cargo clippy -- -D warnings", want: []string{"verify.run"}},
		{name: "golangci-lint", command: "golangci-lint run", want: []string{"verify.run"}},
		{name: "tsc", command: "tsc --noEmit", want: []string{"verify.run"}},
		{name: "make test", command: "make test", want: []string{"verify.run"}},
		{name: "make clean build runs the second target", command: "make clean build", want: []string{"verify.run"}},
		{name: "npm run test", command: "npm run test", want: []string{"verify.run"}},
		{name: "pnpm run typecheck", command: "pnpm run typecheck", want: []string{"verify.run"}},
		{name: "env prefix does not hide the command", command: "CI=1 env GOFLAGS=-mod=mod go test ./...", want: []string{"verify.run"}},
		// Negatives.
		{name: "npm run dev is not a verification", command: "npm run dev"},
		{name: "make deploy is not a verification", command: "make deploy"},
		{name: "go run is not a verification", command: "go run ./cmd/acta"},
		{name: "go test print-only mode runs no verification", command: "go test -n ./..."},
		{name: "go build print-only mode runs no verification", command: "go build -n ./..."},
		{name: "go vet print-only mode runs no verification", command: "go vet -n ./..."},
		{name: "echoed go test", command: "echo go test ./..."},
		{name: "make -C flag value is not the target", command: "make -C build install"},
		{name: "make short dry run runs no verification", command: "make -n test"},
		{name: "make just-print runs no verification", command: "make --just-print test"},
		{name: "make dry-run runs no verification", command: "make --dry-run test"},
		{name: "make recon runs no verification", command: "make --recon test"},
	})
}

func TestClassifyExecSearchQuery(t *testing.T) {
	runExecCases(t, []execCase{
		{
			name:    "rg over a directory",
			command: "rg TODO internal/digest",
			want:    []string{"search.query"},
		},
		{
			name:    "rg over the whole tree",
			command: "rg --hidden classifyExec",
			want:    []string{"search.query"},
		},
		{
			name:    "explicit pattern flag",
			command: "rg -n -e func.*Classify internal cmd",
			want:    []string{"search.query"},
		},
		{
			name:    "grep over two files",
			command: "grep -n TODO trace.go digest.go",
			want:    []string{"search.query"},
		},
		{
			// Regression: grep's -r is --recursive (no value), unlike rg's
			// -r/--replace. A shared value-flag table swallowed the pattern
			// and reported the scanned directory as the search target.
			name:    "grep recursive flag does not swallow the pattern",
			command: "grep -r TODO internal/digest",
			want:    []string{"search.query"},
		},
		{
			// Regression: execSearchPattern matched a value flag by exact token
			// only, unlike execOperands, so a clustered short flag ending in one
			// (-A's context count inside -nA) fell through as an ignorable flag
			// and its value — a context-line count, not anything searched for —
			// was published as the pattern.
			name:    "grep clustered context flag does not swallow the pattern",
			command: "grep -nA 5 TODO README.md",
			want:    []string{"search.query"},
		},
		{
			name:    "rg clustered type and context flags do not swallow the pattern",
			command: "rg -nC 2 TODO src",
			want:    []string{"search.query"},
		},
		{
			name:    "grep long value flags do not become the pattern",
			command: "grep -r --exclude-dir node_modules --include '*.go' TODO .",
			want:    []string{"search.query"},
		},
		{
			name:    "rg long value flags do not become the pattern",
			command: "rg --max-depth 2 --sort path TODO",
			want:    []string{"search.query"},
		},
		{
			name:    "rg color mode is not the pattern",
			command: "rg --color always TODO .",
			want:    []string{"search.query"},
		},
		{
			name:    "rg attached color mode is not the pattern",
			command: "rg --color=always TODO .",
			want:    []string{"search.query"},
		},
		{
			name:    "rg color spec is not the pattern",
			command: "rg --colors path:none TODO .",
			want:    []string{"search.query"},
		},
		{
			name:    "rg dfa size limit is not the pattern",
			command: "rg --dfa-size-limit 10M TODO src",
			want:    []string{"search.query"},
		},
		{
			name:    "rg attached dfa size limit is not the pattern",
			command: "rg --dfa-size-limit=10M TODO src",
			want:    []string{"search.query"},
		},
		{
			name:    "unmodelled rg flag withholds the pattern target",
			command: "rg --future-limit 10M TODO src",
			want:    []string{"search.query"},
		},
		{
			name:    "command substitution is not a search pattern target",
			command: `rg "$(printf needle)" .`,
			want:    []string{"search.query"},
		},
		{
			name:    "unexpanded glob is not a search pattern target",
			command: `rg "*.secret" .`,
			want:    []string{"search.query"},
		},
		{
			name:    "credential-bearing search pattern is never published",
			command: `rg 'https://alice:s3cr3t@example.com/private' .`,
			want:    []string{"search.query"},
		},
		{name: "rg file listing mode is not a query", command: "rg --files"},
		{name: "rg type listing mode is not a query", command: "rg --type-list"},
		{
			name:    "rg encoding value is not the pattern",
			command: "rg --encoding utf-16 TODO internal/digest",
			want:    []string{"search.query"},
		},
		{
			name:    "rg attached encoding value is not the pattern",
			command: "rg --encoding=utf-16 TODO internal/digest",
			want:    []string{"search.query"},
		},
		{
			name:    "rg attached short encoding value is not the pattern",
			command: "rg -Eutf-16 TODO internal/digest",
			want:    []string{"search.query"},
		},
		{name: "rg help runs no search", command: "rg --help"},
		{
			name:    "grep attached long regexp is the pattern",
			command: "grep --regexp=TODO src/main.go",
			want:    []string{"search.query"},
		},
		{
			name:    "grep attached short regexp is the pattern",
			command: "grep -eTODO src/main.go",
			want:    []string{"search.query"},
		},
		{
			name:    "explicitly empty regexp is still a query",
			command: "grep -e '' src/main.go",
			want:    []string{"search.query"},
		},
		// Negatives: a search scoped to one file, whose output actually proves
		// content came back, is a file read (retrievalFromCommand), not a query.
		{
			name:    "rg scoped to a single file",
			command: "rg TODO internal/digest/trace.go",
			output:  "10:// TODO fix this",
		},
		{
			name:    "grep scoped to a single file",
			command: "grep -n TODO internal/digest/trace.go",
			output:  "10:// TODO fix this",
		},
		{name: "grep downstream of a pipe", command: "git log --oneline | grep fix"},
		{name: "echoed rg", command: "echo rg TODO internal"},
		{name: "bare grep has no query", command: "grep", failed: true},
		{name: "bare rg has no query", command: "rg", failed: true},
		// Regression: retrievalFromCommand additionally requires
		// searchCommandCanExposeFileContent before it credits a single-file
		// scope as a read. When that predicate does not hold, nothing else
		// credits the search, so execSearch must fall through and credit
		// search.query rather than let the command vanish entirely.
		{
			name:    "count flag suppresses the file read so the search is credited instead",
			command: "grep -c TODO internal/digest/trace.go",
			output:  "3",
			want:    []string{"search.query"},
		},
		{
			name:    "files-with-matches flag suppresses the file read so the search is credited instead",
			command: "rg -l TODO internal/digest/trace.go",
			output:  "internal/digest/trace.go",
			want:    []string{"search.query"},
		},
		{
			name:    "a real search with no hits produced no output to prove a read",
			command: "grep -n TODO internal/digest/trace.go",
			output:  "",
			want:    []string{"search.query"},
		},
		// Regression: with -f/--file the pattern list lives in a file, so there
		// is no pattern operand at all. execSearchPattern used to skip -f as a
		// value flag and return the next non-flag argument — a search PATH —
		// publishing it as though it were the literal pattern searched for.
		{
			name:    "grep -f reads patterns from a file, not the command line",
			command: "grep -f patterns.txt notes.txt",
			want:    []string{"search.query"},
		},
		{
			name:    "rg -f reads patterns from a file, not the command line",
			command: "rg -f patterns.txt src/",
			want:    []string{"search.query"},
		},
		{
			name:    "grep --file= spelling is recognised the same way",
			command: "grep --file=patterns.txt notes.txt",
			want:    []string{"search.query"},
		},
	})
}

func TestClassifyExecContainerAndBackground(t *testing.T) {
	runExecCases(t, []execCase{
		{name: "docker build", command: "docker build -t acta .", want: []string{"container.run"}},
		{name: "podman exec", command: "podman exec acta ls", want: []string{"container.run"}},
		{
			name:    "detached compose is both",
			command: "docker compose up -d",
			want:    []string{"container.run", "process.background"},
		},
		{name: "nohup", command: "nohup python server.py", want: []string{"process.background"}},
		{name: "nohup help starts nothing", command: "nohup --help"},
		{name: "tmux", command: "tmux new -d -s build", want: []string{"process.background"}},
		{name: "screen version starts no background process", command: "screen -v"},
		{
			name:    "trailing ampersand",
			command: "go test ./... &",
			want:    []string{"process.background", "verify.run"},
		},
		// Negatives.
		{name: "docker ps is not in the table", command: "docker ps"},
		{name: "failed docker build", command: "docker build -t acta .", failed: true},
		{name: "docker build help runs no container action", command: "docker build --help"},
		{name: "foreground compose", command: "docker compose up", want: []string{"container.run"}},
		{name: "chained commands are not backgrounded", command: "go build ./... && go test ./...", want: []string{"verify.run"}},
		{
			// Regression: shellTokens strips quotes, so a quoted "&" argument was
			// indistinguishable from the real detach operator once the check only
			// looked at the token list. Nothing here runs in the background.
			name:    "quoted ampersand argument is not a detach",
			command: `echo "&"`,
		},
		{
			// fsOwnArgs (separately from execTrailingAmpersand) also treats a
			// bare "&" argument as the control token and truncates the command's
			// own args there, so the pattern is not recovered — a miss, not a
			// mislabel, which is the correct trade per the "prove it or credit
			// nothing" rule. It must still not be credited process.background.
			name:    "quoted ampersand argument to rg is not a detach",
			command: "rg '&'",
		},
		{
			// Regression: a backslash-escaped "&" is a literal argument
			// character, not the detach operator — nothing was left running in
			// the background.
			name:    "escaped ampersand is not a detach",
			command: `echo a\&`,
		},
		{
			// git is not in execRules at all (that word belongs to the vcs
			// classifier); this only proves the exec classifier's own
			// process.background rule stays silent on the escaped "&".
			name:    "escaped ampersand after a non-exec command is not a detach",
			command: `git commit -m x\&`,
		},
		{
			// An even run of backslashes before the "&" leaves it live: each
			// pair collapses to one literal backslash, so the "&" is unescaped.
			name:    "doubly-escaped backslash leaves the ampersand live",
			command: `echo a\\&`,
			want:    []string{"process.background"},
		},
	})
}

func TestClassifyExecArchiveAndPermission(t *testing.T) {
	runExecCases(t, []execCase{
		{name: "tar", command: "tar -xzf release.tgz", want: []string{"archive.extract"}},
		{name: "unzip", command: "unzip bundle.zip", want: []string{"archive.extract"}},
		{name: "gunzip", command: "gunzip dump.sql.gz", want: []string{"archive.extract"}},
		{
			name:    "curl to a file",
			command: "curl -o tool.tgz https://example.com/tool.tgz",
			want:    []string{"archive.extract", "network.egress"},
			targets: urlTarget("https://example.com"),
		},
		// Regression: `curl -o /dev/null -s -w '%{http_code}' <url>` is the
		// standard health-check idiom — nothing lands on disk, so
		// archive.extract must not be credited even though -o is present.
		{
			name:    "curl -o /dev/null is a status probe, not an extract",
			command: "curl -s -o /dev/null -w '%{http_code}' https://api.example.com/health",
			want:    []string{"network.egress"},
			targets: urlTarget("https://api.example.com"),
		},
		{
			name:    "curl -o /dev/zero is not an extract",
			command: "curl -o /dev/zero https://example.com/tool.tgz",
			want:    []string{"network.egress"},
			targets: urlTarget("https://example.com"),
		},
		{
			name:    "cleaned device alias is not an extract",
			command: "curl -o /dev/../dev/null https://example.com/tool.tgz",
			want:    []string{"network.egress"},
			targets: urlTarget("https://example.com"),
		},
		{
			name:    "outside absolute output escapes",
			command: "curl -o /tmp/tool.tgz https://example.com/tool.tgz",
			want:    []string{"network.egress", "workspace.escape"},
			targets: urlTarget("https://example.com"),
		},
		{
			name:    "absolute workspace output is an extract",
			command: "curl -o /repo/tool.tgz https://example.com/tool.tgz",
			want:    []string{"archive.extract", "network.egress"},
			targets: urlTarget("https://example.com"),
		},
		{name: "tar outside destination escapes the workspace", command: "tar -C /tmp -xf release.tgz", want: []string{"workspace.escape"}},
		{name: "tar attached outside destination escapes the workspace", command: "tar -C/tmp -xf release.tgz", want: []string{"workspace.escape"}},
		{name: "tar long outside destination escapes the workspace", command: "tar --directory=/tmp -xf release.tgz", want: []string{"workspace.escape"}},
		{name: "tar traversal destination escapes the workspace", command: "tar -C ../other -xf release.tgz", want: []string{"workspace.escape"}},
		{name: "tar later outside destination escapes the workspace", command: "tar -C build -C /tmp -xf release.tgz", want: []string{"workspace.escape"}},
		{name: "tar repeated relative destinations return to workspace", command: "tar -C build -C .. -xf release.tgz", want: []string{"archive.extract"}},
		{name: "tar repeated relative destinations after archive return to workspace", command: "tar -xf release.tgz -C build -C ..", want: []string{"archive.extract"}},
		{name: "tar repeated relative destinations leave workspace", command: "tar -C build -C ../.. -xf release.tgz", want: []string{"workspace.escape"}},
		{name: "tar old-style options bind directory before archive", command: "tar xCf /tmp release.tgz", want: []string{"workspace.escape"}},
		{name: "unzip outside destination escapes the workspace", command: "unzip bundle.zip -d /tmp/out", want: []string{"workspace.escape"}},
		{name: "unzip attached outside destination escapes the workspace", command: "unzip bundle.zip -d/tmp/out", want: []string{"workspace.escape"}},
		{name: "unzip traversal destination escapes the workspace", command: "unzip bundle.zip -d ../other", want: []string{"workspace.escape"}},
		{name: "tar workspace destination is an extract", command: "tar -C build -xf release.tgz", want: []string{"archive.extract"}},
		{name: "unzip workspace destination is an extract", command: "unzip bundle.zip -d build", want: []string{"archive.extract"}},
		{
			name:    "remote-name output is not a provable workspace file",
			command: "curl -O https://example.com/tool.tgz",
			want:    []string{"network.egress"},
			targets: urlTarget("https://example.com"),
		},
		{
			name:    "curl -o - streams to stdout, not an extract",
			command: "curl -o - https://example.com/tool.tgz",
			want:    []string{"network.egress"},
			targets: urlTarget("https://example.com"),
		},
		{
			name:    "wget -O /dev/null is a status probe, not an extract",
			command: "wget -O /dev/null https://example.com/health",
			want:    []string{"network.egress"},
			targets: urlTarget("https://example.com"),
		},
		{
			name:    "curl stdout device is not an extract",
			command: "curl -o /dev/stdout https://example.com/tool.tgz",
			want:    []string{"network.egress"},
			targets: urlTarget("https://example.com"),
		},
		{
			name:    "curl stderr device is not an extract",
			command: "curl -o /dev/stderr https://example.com/tool.tgz",
			want:    []string{"network.egress"},
			targets: urlTarget("https://example.com"),
		},
		{
			name:    "curl file descriptor is not an extract",
			command: "curl -o /dev/fd/12 https://example.com/tool.tgz",
			want:    []string{"network.egress"},
			targets: urlTarget("https://example.com"),
		},
		{
			name:    "wget stdout device is not an extract",
			command: "wget -O /dev/stdout https://example.com/tool.tgz",
			want:    []string{"network.egress"},
			targets: urlTarget("https://example.com"),
		},
		{name: "chmod", command: "chmod +x scripts/run.sh", want: []string{"permission.changed"}, targets: []CommandTarget{{Kind: "path", Value: "scripts/run.sh"}}},
		{name: "sudo chown", command: "sudo chown acta:acta /srv/app", want: []string{"workspace.escape"}},
		{name: "chgrp", command: "chgrp staff notes.md", want: []string{"permission.changed"}, targets: []CommandTarget{{Kind: "path", Value: "notes.md"}}},
		// Negatives.
		{name: "failed tar extracted nothing", command: "tar -xzf release.tgz", failed: true},
		{name: "failed chmod changed nothing", command: "chmod +x scripts/run.sh", failed: true},
		{name: "tar create is not an extract", command: "tar -czf dist/bundle.tgz dist"},
		{name: "tar attached directory value is not mode text", command: "tar -Cexamples -cf /dev/null digest.v3.json"},
		{name: "tar attached archive name is not mode text", command: "tar -fexample.tar -c input.txt"},
		{name: "tar value-taking option before mode letters proves no extract", command: "tar -Cxf archive.tgz"},
		{name: "tar list is not an extract", command: "tar -tzf release.tgz"},
		{name: "unzip list is not an extract", command: "unzip -l bundle.zip"},
		{name: "unzip no-overwrite mode proves no write", command: "unzip -n bundle.zip"},
		{name: "unzip freshen mode proves no write", command: "unzip -f bundle.zip"},
		{name: "unzip update mode proves no write", command: "unzip -u bundle.zip"},
		{name: "unzip without an archive is not an extract", command: "unzip"},
		{name: "unzip timestamp mode is not an extract", command: "unzip -T bundle.zip"},
		{name: "tar short stdout mode is not an extract", command: "tar -xOf release.tar notes.txt"},
		{name: "tar long stdout mode is not an extract", command: "tar --to-stdout -xf release.tar notes.txt"},
		{name: "tar to-command mode is not an extract", command: "tar -xf release.tar --to-command='cat >/dev/null'"},
		{name: "tar bare clustered stdout mode is not an extract", command: "tar xOf release.tar notes.txt"},
		{name: "unzip crt stdout mode is not an extract", command: "unzip -c bundle.zip config.json"},
		{name: "unzip comment mode is not an extract", command: "unzip -z bundle.zip"},
		{name: "gunzip version is not an extract", command: "gunzip --version"},
		{name: "gunzip short version is not an extract", command: "gunzip -V"},
		{name: "gunzip clustered short version is not an extract", command: "gunzip -qV missing.gz"},
		{name: "gunzip help is not an extract", command: "gunzip --help"},
		{name: "unzip clustered short help is not an extract", command: "unzip -qh missing.zip"},
		{name: "gunzip without an input file is not an extract", command: "gunzip"},
		// Regression: gunzip's list and test modes read an existing archive and
		// write nothing, the same as tar -t and unzip -l.
		{name: "gunzip list is not an extract", command: "gunzip -l dump.sql.gz"},
		{name: "gunzip long-flag list is not an extract", command: "gunzip --list dump.sql.gz"},
		{name: "gunzip test is not an extract", command: "gunzip -t dump.sql.gz"},
		{name: "gunzip long-flag test is not an extract", command: "gunzip --test dump.sql.gz"},
		// Regression: -p/-c/--stdout/--to-stdout stream the archive's content to
		// stdout and land nothing on disk, the same as a list or test mode.
		{name: "unzip stream-to-stdout is not an extract", command: "unzip -p bundle.zip config.json"},
		{name: "gunzip stream-to-stdout is not an extract", command: "gunzip -c dump.sql.gz"},
		{name: "gunzip long-flag stdout is not an extract", command: "gunzip --stdout dump.sql.gz"},
		{name: "gunzip long-flag to-stdout is not an extract", command: "gunzip --to-stdout dump.sql.gz"},
		{name: "unzip zipinfo mode is not an extract", command: "unzip -Z bundle.zip"},
		// Regression: execHasFlag only matched a mode letter written as its own
		// exact token, so a short-flag cluster containing a listing or
		// stdout-mode letter fell through and archive.extract was credited for
		// a command that wrote nothing to disk.
		{name: "unzip clustered quiet-list is not an extract", command: "unzip -qql bundle.zip"},
		{name: "unzip clustered list-verbose is not an extract", command: "unzip -lv bundle.zip"},
		{name: "unzip clustered zipinfo mode is not an extract", command: "unzip -Z1 bundle.zip"},
		{name: "gunzip clustered keep-stdout is not an extract", command: "gunzip -kc dump.sql.gz"},
		{name: "gunzip clustered stdout-force is not an extract", command: "gunzip -cf dump.sql.gz"},
		{name: "opaque curl cluster cannot prove an extract", command: "curl -kV -O https://never.invalid"},
		{name: "chmod help changes no permissions", command: "chmod --help +x scripts/run.sh"},
		{name: "chmod dry run changes no permissions", command: "chmod --dry-run +x scripts/run.sh"},
		{name: "curl attached data is not an output file", command: "curl -dfoo https://example.com", want: []string{"network.egress"}, targets: urlTarget("https://example.com")},
		{
			name:    "curl without an output file",
			command: "curl https://example.com/tool.tgz",
			want:    []string{"network.egress"},
			targets: urlTarget("https://example.com"),
		},
	})
}

func TestClassifyCommandPreservesPathOperandWhitespace(t *testing.T) {
	tests := []struct {
		name    string
		command string
		path    string
	}{
		{name: "trailing space", command: "rm 'victim '", path: "victim "},
		{name: "leading space", command: "rm ' victim'", path: " victim"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			facts := classifyCommand(tt.command, "", true, testWorkspace())
			wantTargets := []CommandTarget{{Kind: "path", Value: tt.path}}
			wantMutations := []ShellMutation{{Kind: "delete", Path: tt.path}}
			if facts == nil || !reflect.DeepEqual(facts.categories, []string{"fs.delete"}) ||
				!reflect.DeepEqual(facts.targets, wantTargets) || !reflect.DeepEqual(facts.mutations, wantMutations) {
				t.Fatalf("classifyCommand(%q) = %+v, want path %q", tt.command, facts, tt.path)
			}
		})
	}
}

func TestClassifyCommandWithholdsUnprovenPackageInstalls(t *testing.T) {
	for _, command := range []string{
		"npm install left-pad | tee install.log",
		"pip install ruff 2>&1 | tee install.log",
	} {
		t.Run(command, func(t *testing.T) {
			facts := classifyCommand(command, "", true, testWorkspace())
			if facts != nil {
				t.Fatalf("classifyCommand(%q) = %+v, want no facts", command, facts)
			}
		})
	}
}

func TestClassifyExecEnvInspect(t *testing.T) {
	runExecCases(t, []execCase{
		{name: "bare env", command: "env", want: []string{"env.inspect"}},
		{name: "env piped to grep", command: "env | grep API", want: []string{"env.inspect"}},
		{name: "printenv", command: "printenv PATH", want: []string{"env.inspect"}},
		{name: "bare set", command: "set", want: []string{"env.inspect"}},
		{name: "reading a dotenv file", command: "cat .env", want: []string{"env.inspect"}},
		{name: "reading a nested dotenv file", command: "cat config/.env.local", want: []string{"env.inspect"}},
		// Negatives.
		{name: "set -e configures the shell", command: "set -e"},
		{name: "env as an assignment prefix", command: "env GOFLAGS=-mod=mod go build ./...", want: []string{"verify.run"}},
		{name: "reading an ordinary file", command: "cat README.md"},
	})
}

// env.inspect must never carry a target: the whole point of the category is to
// record that the environment was read without echoing anything it contained.
func TestClassifyExecEnvInspectNeverCarriesValues(t *testing.T) {
	for _, command := range []string{"env", "printenv AWS_SECRET_ACCESS_KEY", "cat .env", "set"} {
		facts := execClassify(command, true, "")
		if len(facts.targets) != 0 {
			t.Errorf("%q credited targets %+v, want none", command, facts.targets)
		}
	}
}

func TestClassifyExecCommandInteractive(t *testing.T) {
	runExecCases(t, []execCase{
		{name: "vim", command: "vim notes.md", want: []string{"command.interactive"}},
		{name: "nano", command: "nano notes.md", want: []string{"command.interactive"}},
		{name: "htop", command: "htop", want: []string{"command.interactive"}},
		{name: "less", command: "less build.log", want: []string{"command.interactive"}},
		{name: "interactive rebase", command: "git rebase -i HEAD~3", want: []string{"command.interactive"}},
		{name: "interactive add", command: "git add -i", want: []string{"command.interactive"}},
		{name: "failed interactive rebase still waited for a human", command: "git rebase -i HEAD~3", failed: true, want: []string{"command.interactive"}},
		// Negatives.
		{name: "non-interactive rebase", command: "git rebase --continue"},
		{name: "non-interactive add", command: "git add -A"},
		{name: "pager downstream of a pipe", command: "git log --oneline | less"},
		{name: "vim named as an argument", command: "echo vim notes.md"},
	})
}
