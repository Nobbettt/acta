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

func TestReconcileRecordCopiesFinalOTLPResultAndStampsCurrentSchema(t *testing.T) {
	record := &runrecord.Record{
		OK:                true,
		TerminationReason: OutcomeCompleted,
		OTLPStatus:        "failed",
		OTLPError:         "flush failed",
	}
	d := &Digest{
		SchemaVersion: MinSchemaVersion,
		Status:        StatusOK,
		OTLPStatus:    "exported",
		Termination:   Termination{Outcome: OutcomeCompleted},
	}

	ReconcileRecord(record, d)

	if d.SchemaVersion != SchemaVersion || d.OTLPStatus != record.OTLPStatus || d.OTLPError != record.OTLPError {
		t.Fatalf("reconciled digest = schema %d, OTLP %q/%q; want schema %d, OTLP %q/%q",
			d.SchemaVersion, d.OTLPStatus, d.OTLPError, SchemaVersion, record.OTLPStatus, record.OTLPError)
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

func TestNormalizeEventBoundsClassificationFields(t *testing.T) {
	large := strings.Repeat("x", MaxEventTextBytes)
	manyCategories := make([]string, 2048)
	manyTargets := make([]CommandTarget, 2048)
	manyMutations := make([]ShellMutation, 2048)
	for i := range manyCategories {
		manyCategories[i] = large
	}
	for i := range manyTargets {
		manyTargets[i] = CommandTarget{Kind: large, Value: large}
	}
	for i := range manyMutations {
		manyMutations[i] = ShellMutation{Kind: "move", Path: large, From: large, To: large}
	}
	d := &Digest{}
	if !d.appendEvent(Event{Kind: KindCommand, Categories: manyCategories, Targets: manyTargets, ShellMutations: manyMutations}) {
		t.Fatal("bounded event was unexpectedly dropped")
	}
	got := d.Timeline[0]
	if len(got.Categories) > 1024 || len(got.Targets) > 1024 || len(got.ShellMutations) > 1024 {
		t.Fatalf("classification fields not capped: categories=%d targets=%d mutations=%d",
			len(got.Categories), len(got.Targets), len(got.ShellMutations))
	}
	for _, category := range got.Categories {
		if len(category) > 4096 {
			t.Fatalf("category retained %d bytes", len(category))
		}
	}
	for _, target := range got.Targets {
		if len(target.Value) > 4096 {
			t.Fatalf("target value retained %d bytes", len(target.Value))
		}
	}
	for _, mutation := range got.ShellMutations {
		if len(mutation.Path) > 4096 || len(mutation.From) > 4096 || len(mutation.To) > 4096 {
			t.Fatalf("shell mutation retained oversized field: %+v", mutation)
		}
	}
}

func TestProjectionBudgetIncludesLocalReasoning(t *testing.T) {
	// Quotes exercise JSON expansion as well as the retained string bytes. The
	// event stream must fit the same projection budget after reasoning is copied
	// into its text field.
	reasoning := strings.Repeat(`"`, MaxEventTextBytes)
	d := &Digest{}
	attempted := MaxProjectionBytes/MaxEventTextBytes + 256
	for range attempted {
		d.appendEvent(Event{Kind: KindReasoning, localReasoningText: reasoning})
	}
	if !d.Metrics.ProjectionTruncated || d.Metrics.DroppedEvents == 0 {
		t.Fatalf("projection metrics = %+v, want dropped reasoning events", d.Metrics)
	}
	if d.projectionBytes > MaxProjectionBytes {
		t.Fatalf("projection retained %d bytes, maximum is %d", d.projectionBytes, MaxProjectionBytes)
	}

	accounted := 0
	for _, event := range d.Timeline {
		eventBytes, err := eventProjectionBytes(event)
		if err != nil {
			t.Fatal(err)
		}
		accounted += eventBytes
		if len(event.LocalReasoningText()) != MaxEventTextBytes {
			t.Fatalf("reasoning event retained %d bytes, want %d", len(event.LocalReasoningText()), MaxEventTextBytes)
		}
	}
	if accounted != d.projectionBytes {
		t.Fatalf("accounted projection bytes = %d, digest tracks %d", accounted, d.projectionBytes)
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
