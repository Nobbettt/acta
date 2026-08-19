package digest

import (
	"strings"
	"testing"
)

// observed_at must mean call START for codex (the item.started arrival), to
// match claude (tool_use line) and the OTLP span start. The event is built on
// item.completed, so its srcLine must point back at the started line.
func TestCodexObservedAtUsesStartLine(t *testing.T) {
	lines := []string{
		`{"type":"thread.started","thread_id":"t-1"}`,
		`{"type":"turn.started"}`,
		`{"type":"item.started","item":{"id":"i1","type":"command_execution","command":"ls"}}`,
		`{"type":"item.completed","item":{"id":"i1","type":"command_execution","command":"ls","status":"completed","exit_code":0,"aggregated_output":"a\n"}}`,
		`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`,
	}
	d, err := parseCodex(strings.NewReader(strings.Join(lines, "\n")+"\n"), newWorkspace(""))
	if err != nil {
		t.Fatal(err)
	}
	var command *Event
	for index := range d.Timeline {
		if d.Timeline[index].Kind == KindCommand {
			command = &d.Timeline[index]
			break
		}
	}
	if command == nil || command.srcLine != 3 {
		t.Fatalf("command = %+v, want item.started source line 3", command)
	}
}
