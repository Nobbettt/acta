package actaevents

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/nobbettt/acta/internal/digest"
	"github.com/nobbettt/acta/internal/runrecord"
)

// derivedFilePayload covers both derived file payloads at once, so one
// helper can read whichever of them an event carries.
type derivedFilePayload struct {
	Path                string `json:"path"`
	From                string `json:"from"`
	To                  string `json:"to"`
	SourceEventSequence int    `json:"source_event_sequence"`
	Command             string `json:"command"`
}

// A shell command that changed the workspace reaches the file timeline the same
// way a read does: one derived event per proven change, in a reproducible
// order, each pointing back at the sequence of the command that proved it.
func TestBuildDerivesFileEventsFromShellMutations(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		wantTypes []string
		want      []derivedFilePayload
	}{
		{
			name:      "delete and move, in command order",
			command:   "rm z.txt a.txt && mv src/old.go src/new.go",
			wantTypes: []string{TypeFileDeleted, TypeFileDeleted, TypeFileMoved},
			want: []derivedFilePayload{
				{Path: "z.txt"},
				{Path: "a.txt"},
				{From: "src/old.go", To: "src/new.go"},
			},
		},
		{
			// A delete-then-move atomic replace: b.txt is deleted, then a.txt takes
			// its name. Sorting by path across kinds would place the move (From:
			// a.txt) before the delete (Path: b.txt), making a consumer that
			// replays the file timeline in sequence order believe b.txt was created
			// by the move and later deleted, when in fact b.txt survives holding
			// a.txt's content and a.txt is what is gone.
			name:      "delete-then-move atomic replace keeps command order",
			command:   "rm b.txt && mv a.txt b.txt",
			wantTypes: []string{TypeFileDeleted, TypeFileMoved},
			want: []derivedFilePayload{
				{Path: "b.txt"},
				{From: "a.txt", To: "b.txt"},
			},
		},
		{
			// Two chained moves: sorting by From path across the two mutations
			// ("a.txt" < "b.txt") would emit a.txt->b.txt before b.txt->c.txt,
			// which reads as a straight a.txt->c.txt rename. Command order is the
			// only order that reflects what actually happened: b.txt->c.txt first
			// (freeing the name b.txt), then a.txt->b.txt.
			name:      "chained moves keep command order, not path order",
			command:   "mv b.txt c.txt && mv a.txt b.txt",
			wantTypes: []string{TypeFileMoved, TypeFileMoved},
			want: []derivedFilePayload{
				{From: "b.txt", To: "c.txt"},
				{From: "a.txt", To: "b.txt"},
			},
		},
		{
			name:    "a command that changed nothing derives nothing",
			command: "git status",
		},
		{
			// The rewritten files live in the patch body, which the digest never
			// sees. The fs.patch category on the command carries that alone.
			name:    "a patch with no proven path derives nothing",
			command: "git apply fix.diff",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			commandSeq := 0
			var (
				types    []string
				payloads []derivedFilePayload
			)
			for _, event := range codexCommandEvents(t, test.command) {
				if err := ValidateEvent(event, "run-mutations", event.Sequence); err != nil {
					t.Fatalf("event %d does not validate: %v", event.Sequence, err)
				}
				switch event.Type {
				case TypeShellCommandComplete:
					commandSeq = event.Sequence
				case TypeFileDeleted, TypeFileMoved:
					var payload derivedFilePayload
					if err := json.Unmarshal(event.Payload, &payload); err != nil {
						t.Fatal(err)
					}
					types = append(types, event.Type)
					payloads = append(payloads, payload)
				}
			}
			if commandSeq == 0 {
				t.Fatal("the codex stream produced no shell command event")
			}
			if len(types) != len(test.wantTypes) {
				t.Fatalf("derived events = %v %+v, want %v", types, payloads, test.wantTypes)
			}
			for i, want := range test.want {
				want.SourceEventSequence = commandSeq
				want.Command = test.command
				if types[i] != test.wantTypes[i] || payloads[i] != want {
					t.Fatalf("derived event %d = %s %+v, want %s %+v", i, types[i], payloads[i], test.wantTypes[i], want)
				}
			}
		})
	}
}

func TestFilePatchedIsNotAPublishedType(t *testing.T) {
	if IsKnownType("file.patched") {
		t.Fatal("patches are category-only, so file.patched must not remain in the event vocabulary")
	}
}

// The classification of a shell command has to survive the projection: the
// categories and targets the digest credited ride on the timeline payload.
func TestBuildCarriesCommandCategoriesAndTargets(t *testing.T) {
	for _, event := range codexCommandEvents(t, "rm z.txt a.txt && mv src/old.go src/new.go") {
		if event.Type != TypeShellCommandComplete {
			continue
		}
		var payload struct {
			Categories []string               `json:"categories"`
			Targets    []digest.CommandTarget `json:"targets"`
		}
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		wantCategories := []string{"fs.delete", "fs.move"}
		if !reflect.DeepEqual(payload.Categories, wantCategories) {
			t.Fatalf("categories = %v, want %v", payload.Categories, wantCategories)
		}
		wantTargets := []digest.CommandTarget{
			{Kind: "path", Value: "z.txt"}, {Kind: "path", Value: "a.txt"},
			{Kind: "path", Value: "src/old.go"}, {Kind: "path", Value: "src/new.go"},
		}
		if !reflect.DeepEqual(payload.Targets, wantTargets) {
			t.Fatalf("targets = %+v, want %+v", payload.Targets, wantTargets)
		}
		return
	}
	t.Fatal("the projection omitted the shell command event")
}

// codexCommandEvents runs one successful command through a real codex stream
// and returns the events the run projects to.
func codexCommandEvents(t *testing.T, command string) []Event {
	t.Helper()
	started := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	digester, err := digest.NewStreamDigesterWithOptions("codex", t.TempDir(), digest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	item, err := json.Marshal(map[string]any{
		"type": "item.completed",
		"item": map[string]any{
			"id": "cmd-1", "type": "command_execution", "command": command,
			"status": "completed", "exit_code": 0, "aggregated_output": "",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	digester.Line([]byte(`{"type":"thread.started","thread_id":"thread-mutations"}`), started)
	digester.Line([]byte(`{"type":"turn.started"}`), started)
	digester.Line(item, started)
	digester.Line([]byte(`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`), started)
	record := &runrecord.Record{
		Producer: runrecord.Producer{Name: "acta", Version: "test"},
		ID:       "run-mutations", Agent: "codex", StartedAt: started, CompletedAt: started, OK: true,
	}
	d := digester.Finalize(record, "")
	events, err := Build(record, d)
	if err != nil {
		t.Fatal(err)
	}
	return events
}
