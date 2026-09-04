package digest

import "testing"

func TestClassifyExecRepeatedDownloadOutputs(t *testing.T) {
	runExecCases(t, []execCase{
		{
			name:    "wget last output escapes",
			command: "wget -O inside.tgz -O /tmp/out.tgz https://example.com/a",
			want:    []string{"network.egress", "workspace.escape"},
			targets: urlTarget("https://example.com"),
		},
		{
			name:    "wget last output returns inside",
			command: "wget -O /tmp/out.tgz -O inside.tgz https://example.com/a",
			want:    []string{"archive.extract", "network.egress"},
			targets: urlTarget("https://example.com"),
		},
		{
			name:    "curl checks every paired output",
			command: "curl -o inside.tgz https://example.com/a -o /tmp/out.tgz https://example.com/b",
			want:    []string{"archive.extract", "network.egress", "workspace.escape"},
			targets: urlTarget("https://example.com"),
		},
		{
			name:    "curl ignores an unpaired extra output",
			command: "curl -o inside.tgz -o /tmp/out.tgz https://example.com/a",
			want:    []string{"archive.extract", "network.egress"},
			targets: urlTarget("https://example.com"),
		},
	})
}

func TestClassifyExecConditionalOwnerChanges(t *testing.T) {
	runExecCases(t, []execCase{
		{name: "chown from predicate", command: "chown --from=+12345:+12345 +12345:+12345 marker"},
		{name: "chown from predicate outside", command: "chown --from=old:new new:new /tmp/marker"},
		{name: "chgrp from predicate", command: "chgrp --from=old new marker"},
	})
}

func TestClassifyExecPipReportDestinations(t *testing.T) {
	runExecCases(t, []execCase{
		{
			name:    "pip report outside workspace",
			command: "pip install --report /tmp/report.json requests",
			want:    []string{"package.install", "workspace.escape"},
			targets: []CommandTarget{{Kind: "package", Value: "requests"}},
		},
		{
			name:    "pip attached report outside workspace",
			command: "pip install --report=/tmp/report.json requests",
			want:    []string{"package.install", "workspace.escape"},
			targets: []CommandTarget{{Kind: "package", Value: "requests"}},
		},
		{
			name:    "pip report to stdout is not a destination",
			command: "pip install --report /dev/stdout requests",
			want:    []string{"package.install"},
			targets: []CommandTarget{{Kind: "package", Value: "requests"}},
		},
	})
}

func TestClassifyExecRejectsPostLoaderSegments(t *testing.T) {
	for _, command := range []string{
		"eval exit; curl https://example.com",
		"source setup.sh; nohup server &",
	} {
		if facts := classifyCommand(command, "", true, testWorkspace()); facts != nil {
			t.Errorf("classifyCommand(%q) = %+v, want nil", command, facts)
		}
	}
}

func TestClassifyExecKeepsActionsWithUncertainCWD(t *testing.T) {
	runExecCases(t, []execCase{
		{
			name:    "relative chmod after cd",
			command: "cd subdir && chmod 600 marker",
			want:    []string{"permission.changed"},
		},
		{
			name:    "relative gunzip after cd",
			command: "cd subdir && gunzip dump.sql.gz",
			want:    []string{"archive.extract"},
		},
		{
			name:    "relative curl output after cd",
			command: "cd subdir && curl -o tool.tgz https://example.com/tool.tgz",
			want:    []string{"archive.extract", "network.egress"},
			targets: urlTarget("https://example.com"),
		},
	})
}

func TestClassifyExecGitConfigEditIsNotAWrite(t *testing.T) {
	runExecCases(t, []execCase{
		{name: "long edit", command: "git config --global --edit"},
		{name: "short edit", command: "git config --global -e"},
	})
}

func TestClassifyExecTarFilesFromIsUnprovable(t *testing.T) {
	runExecCases(t, []execCase{
		{name: "short files from", command: "tar -xf archive.tar -T names.txt"},
		{name: "long files from", command: "tar -xf archive.tar --files-from names.txt"},
	})
}

func TestClassifyExecSearchRequiresFlagValue(t *testing.T) {
	runExecCases(t, []execCase{
		{name: "grep missing short regexp", command: "grep -e", failed: true},
		{name: "grep missing long regexp", command: "grep --regexp", failed: true},
		{name: "grep missing pattern file", command: "grep -f", failed: true},
	})
}
