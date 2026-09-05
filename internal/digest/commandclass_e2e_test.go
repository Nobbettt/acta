package digest_test

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/nobbettt/acta/internal/actaevents"
	"github.com/nobbettt/acta/internal/digest"
	"github.com/nobbettt/acta/internal/runrecord"
)

// Classification has to survive the whole chain, not just the classifier: a
// real codex command_execution is classified as the stream is parsed, the
// categories ride the digest timeline, and the projection carries them onto the
// shell.command.completed payload a consumer actually reads.
func TestCodexCommandIsClassifiedFromStreamToEventPayload(t *testing.T) {
	started := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	digester, err := digest.NewStreamDigesterWithOptions("codex", t.TempDir(), digest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{
		`{"type":"thread.started","thread_id":"thread-classify"}`,
		`{"type":"turn.started"}`,
		`{"type":"item.completed","item":{"id":"c1","type":"command_execution","command":"git status","status":"completed","exit_code":0,"aggregated_output":"nothing to commit\n"}}`,
		`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`,
	}
	for _, line := range lines {
		digester.Line([]byte(line), started)
	}
	record := &runrecord.Record{
		Producer: runrecord.Producer{Name: "acta", Version: "test"},
		ID:       "run-classify", Agent: "codex", StartedAt: started, CompletedAt: started, OK: true,
	}
	d := digester.Finalize(record, "")

	want := []string{"vcs.read"}
	var commands int
	for _, event := range d.Timeline {
		if event.Kind != digest.KindCommand {
			continue
		}
		commands++
		if !reflect.DeepEqual(event.Categories, want) {
			t.Errorf("timeline categories = %v, want %v", event.Categories, want)
		}
	}
	if commands != 1 {
		t.Fatalf("got %d command events, want 1", commands)
	}

	events, err := actaevents.Build(record, d)
	if err != nil {
		t.Fatal(err)
	}
	var payloads int
	for _, event := range events {
		if event.Type != actaevents.TypeShellCommandComplete {
			continue
		}
		if err := actaevents.ValidateEvent(event, record.ID, event.Sequence); err != nil {
			t.Fatalf("event %d does not validate: %v", event.Sequence, err)
		}
		var payload struct {
			Categories []string `json:"categories"`
		}
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		payloads++
		if !reflect.DeepEqual(payload.Categories, want) {
			t.Errorf("shell.command.completed categories = %v, want %v", payload.Categories, want)
		}
	}
	if payloads != 1 {
		t.Fatalf("got %d shell.command.completed events, want 1", payloads)
	}
}

func TestCodexHeredocBodyDoesNotBecomeAReadEvent(t *testing.T) {
	started := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	digester, err := digest.NewStreamDigesterWithOptions("codex", t.TempDir(), digest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	command := "cat <<EOF\ncat README.md\nEOF"
	item, err := json.Marshal(map[string]any{
		"type": "item.completed",
		"item": map[string]any{
			"id": "c1", "type": "command_execution", "command": command,
			"status": "completed", "exit_code": 0, "aggregated_output": "cat README.md\n",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range [][]byte{
		[]byte(`{"type":"thread.started","thread_id":"thread-heredoc"}`),
		[]byte(`{"type":"turn.started"}`), item,
		[]byte(`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`),
	} {
		digester.Line(line, started)
	}
	record := &runrecord.Record{
		Producer: runrecord.Producer{Name: "acta", Version: "test"},
		ID:       "run-heredoc", Agent: "codex", StartedAt: started, CompletedAt: started, OK: true,
	}
	d := digester.Finalize(record, "")
	for _, event := range d.Timeline {
		if event.Kind != digest.KindCommand {
			continue
		}
		if len(event.Files) != 0 {
			t.Errorf("command files = %v, want none", event.Files)
		}
		for _, category := range event.Categories {
			if category == "instructions.read" {
				t.Errorf("command categories = %v, must not include instructions.read", event.Categories)
			}
		}
	}
	events, err := actaevents.Build(record, d)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Type == actaevents.TypeFileRead {
			t.Errorf("unexpected file.read event: %+v", event)
		}
	}
}

func TestCodexWrappedInformationalReadDoesNotBecomeAReadEvent(t *testing.T) {
	started := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	digester, err := digest.NewStreamDigesterWithOptions("codex", t.TempDir(), digest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	item, err := json.Marshal(map[string]any{
		"type": "item.completed",
		"item": map[string]any{
			"id": "c1", "type": "command_execution", "command": "/bin/sh -lc 'command cat --help .env.production'",
			"status": "completed", "exit_code": 0, "aggregated_output": "Usage: cat [OPTION]... [FILE]...\n",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range [][]byte{
		[]byte(`{"type":"thread.started","thread_id":"thread-help"}`),
		[]byte(`{"type":"turn.started"}`), item,
		[]byte(`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`),
	} {
		digester.Line(line, started)
	}
	record := &runrecord.Record{
		Producer: runrecord.Producer{Name: "acta", Version: "test"},
		ID:       "run-help", Agent: "codex", StartedAt: started, CompletedAt: started, OK: true,
	}
	d := digester.Finalize(record, "")
	for _, event := range d.Timeline {
		if event.Kind == digest.KindCommand && (len(event.Files) != 0 || len(event.Categories) != 0) {
			t.Errorf("informational command credited files/categories: files=%v categories=%v", event.Files, event.Categories)
		}
	}
	events, err := actaevents.Build(record, d)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Type == actaevents.TypeFileRead {
			t.Errorf("unexpected file.read event: %+v", event)
		}
	}
}
