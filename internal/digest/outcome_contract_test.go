package digest

import (
	"strings"
	"testing"

	"github.com/nobbettt/acta/internal/runrecord"
)

func TestCodexTurnFailedOverridesZeroExit(t *testing.T) {
	raw := strings.Join([]string{
		`{"type":"thread.started","thread_id":"t-1"}`,
		`{"type":"turn.started"}`,
		`{"type":"turn.failed","error":{"message":"provider rejected turn","code":"turn_rejected"}}`,
	}, "\n") + "\n"
	d, err := parseCodex(strings.NewReader(raw), newWorkspace(""))
	if err != nil {
		t.Fatal(err)
	}
	exit := 0
	record := &runrecord.Record{ID: "r-1", OK: true, ExitCode: &exit, TerminationReason: OutcomeCompleted}
	ReconcileRecord(record, d)
	if record.OK || record.TerminationReason != OutcomeFailed || d.Status != StatusError {
		t.Fatalf("record=%+v digest status=%q termination=%+v", record, d.Status, d.Termination)
	}
}

func TestClaudeUnderspecifiedResultIsProviderError(t *testing.T) {
	d, err := parseClaude(strings.NewReader(`{"type":"result","session_id":"s-1"}`+"\n"), newWorkspace(""))
	if err == nil || !strings.Contains(err.Error(), "recognized subtype") {
		t.Fatalf("semantic error = %v, want invalid-result failure", err)
	}
	if d.Termination.Outcome != OutcomeError || d.Termination.ProviderReason != "invalid_result" {
		t.Fatalf("termination = %+v", d.Termination)
	}
}

func TestFinalizePreservesInterruptedProviderOutcome(t *testing.T) {
	d := &Digest{Termination: Termination{Outcome: OutcomeInterrupted, ProviderReason: "stream_interrupted"}}
	record := &runrecord.Record{ID: "r-1", OK: false, TerminationReason: OutcomeInterrupted}
	applyRecord(d, record, t.TempDir())
	if d.Termination.Outcome != OutcomeInterrupted || d.Status != StatusDegraded {
		t.Fatalf("digest status=%q termination=%+v", d.Status, d.Termination)
	}
}

func TestNormalizeEventBoundsEveryFreeFormField(t *testing.T) {
	large := strings.Repeat("ø", MaxEventTextBytes)
	d := &Digest{}
	if !d.appendEvent(Event{Kind: KindMessage, Text: large, Command: large, ErrorMessage: large}) {
		t.Fatal("bounded event was unexpectedly dropped")
	}
	got := d.Timeline[0]
	for name, value := range map[string]string{"text": got.Text, "command": got.Command, "error": got.ErrorMessage} {
		if len(value) > MaxEventTextBytes {
			t.Fatalf("%s retained %d bytes", name, len(value))
		}
	}
}

func FuzzProviderParsersDoNotPanic(f *testing.F) {
	f.Add([]byte(`{"type":"turn.completed"}` + "\n"))
	f.Add([]byte(`{"type":"result","subtype":"success"}` + "\n"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 1<<20 {
			t.Skip()
		}
		_, _ = parseCodex(strings.NewReader(string(payload)), newWorkspace(""))
		_, _ = parseClaude(strings.NewReader(string(payload)), newWorkspace(""))
	})
}
