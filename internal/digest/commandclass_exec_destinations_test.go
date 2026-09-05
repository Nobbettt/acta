package digest

import "testing"

func TestClassifyExecArchiveDestinations(t *testing.T) {
	runExecCases(t, []execCase{
		{
			name:    "curl outside output escapes",
			command: "curl -o /tmp/tool.tgz https://example.com/tool.tgz",
			want:    []string{"network.egress", "workspace.escape"},
			targets: urlTarget("https://example.com"),
		},
		{
			name:    "wget outside output escapes",
			command: "wget -O ../tool.tgz https://example.com/tool.tgz",
			want:    []string{"network.egress", "workspace.escape"},
			targets: urlTarget("https://example.com"),
		},
		{name: "gunzip outside operand escapes", command: "gunzip /tmp/dump.sql.gz", want: []string{"workspace.escape"}},
		{name: "tar long extract", command: "tar --extract --file=release.tgz", want: []string{"archive.extract"}},
		{name: "tar long create is not extract", command: "tar --create --file=release.tgz files"},
		{name: "tar long list is not extract", command: "tar --list --file=release.tgz"},
		{name: "missing curl output value is not a destination", command: "curl -o"},
	})
}

func TestClassifyExecPermissionDestinations(t *testing.T) {
	runExecCases(t, []execCase{
		{
			name:    "chmod workspace path",
			command: "chmod 600 config/settings.json",
			want:    []string{"permission.changed"},
			targets: []CommandTarget{{Kind: "path", Value: "config/settings.json"}},
		},
		{name: "chmod outside path escapes", command: "chmod 777 /etc/passwd", want: []string{"workspace.escape"}},
		{name: "sudo chown outside path escapes", command: "sudo chown acta:acta /srv/app", want: []string{"workspace.escape"}},
		{name: "permission path expression is unprovable", command: `chmod 600 "$TARGET"`},
		{name: "unknown permission flag is unprovable", command: "chown --future acta:acta config/settings.json"},
	})
}

func TestClassifyExecPackageDestinations(t *testing.T) {
	runExecCases(t, []execCase{
		{
			name:    "pip outside target escapes",
			command: "pip install --target /tmp/vendor requests",
			want:    []string{"package.install", "workspace.escape"},
			targets: []CommandTarget{{Kind: "package", Value: "requests"}},
		},
		{
			name:    "npm outside prefix escapes",
			command: "npm install --prefix ../outside left-pad",
			want:    []string{"package.install", "workspace.escape"},
			targets: []CommandTarget{{Kind: "package", Value: "left-pad"}},
		},
		{
			name:    "cargo outside manifest escapes",
			command: "cargo add --manifest-path /tmp/Cargo.toml serde",
			want:    []string{"package.install", "workspace.escape"},
			targets: []CommandTarget{{Kind: "package", Value: "serde"}},
		},
		{
			name:    "pip workspace target stays inside",
			command: "pip install --target vendor requests",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "requests"}},
		},
		{
			name:    "package destination expression is unprovable",
			command: `pip install --target "$DEST" requests`,
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "requests"}},
		},
		{
			name:    "relative package destination after cd is unprovable",
			command: "cd subdir && pip install --target ../vendor requests",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "requests"}},
		},
	})
}
