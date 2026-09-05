package digest

import (
	"slices"
	"strings"
	"testing"
)

func TestCodexNullExitCodeDoesNotCreditDelete(t *testing.T) {
	raw := `{"type":"thread.started","thread_id":"t"}
{"type":"turn.started"}
{"type":"item.completed","item":{"id":"c","type":"command_execution","command":"rm victim.txt","status":"completed","exit_code":null,"aggregated_output":""}}
{"type":"turn.completed","usage":{"input_tokens":0,"output_tokens":0}}
`
	d, err := parseCodex(strings.NewReader(raw), newWorkspace(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Timeline) != 4 {
		t.Fatalf("timeline = %d events, want 4", len(d.Timeline))
	}
	e := d.Timeline[2]
	if !e.IsError {
		t.Fatal("null exit code must fail closed")
	}
	if slices.Contains(e.Categories, "fs.delete") {
		t.Fatalf("categories = %v, want no fs.delete", e.Categories)
	}
	for _, target := range e.Targets {
		if target.Kind == "path" && target.Value == "victim.txt" {
			t.Fatalf("targets = %v, want no victim.txt target", e.Targets)
		}
	}
	if len(e.ShellMutations) != 0 {
		t.Fatalf("shell mutations = %+v, want none", e.ShellMutations)
	}
}

func TestCodexExitCodeOutcomeKeepsOrdinaryCases(t *testing.T) {
	for _, tc := range []struct {
		name           string
		exitCode       string
		wantDeleteFact bool
	}{
		{name: "lowercase zero succeeds", exitCode: `,"exit_code":0`, wantDeleteFact: true},
		{name: "lowercase nonzero fails", exitCode: `,"exit_code":1`, wantDeleteFact: false},
		{name: "absent stays successful", exitCode: "", wantDeleteFact: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := `{"type":"thread.started","thread_id":"t"}
{"type":"turn.started"}
{"type":"item.completed","item":{"id":"c","type":"command_execution","command":"rm victim.txt","status":"completed"` + tc.exitCode + `,"aggregated_output":""}}
{"type":"turn.completed","usage":{"input_tokens":0,"output_tokens":0}}
`
			d, err := parseCodex(strings.NewReader(raw), newWorkspace(""))
			if err != nil {
				t.Fatal(err)
			}
			e := d.Timeline[2]
			if got := slices.Contains(e.Categories, "fs.delete"); got != tc.wantDeleteFact {
				t.Fatalf("fs.delete = %t, want %t", got, tc.wantDeleteFact)
			}
		})
	}
}
