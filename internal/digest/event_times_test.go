package digest

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestApplyEventTimesJoinsWantedLines(t *testing.T) {
	dir := t.TempDir()
	sidecar := `{"line":1,"t":"2026-07-01T12:00:00Z"}
{"line":2,"t":"2026-07-01T12:00:05Z"}
{"line":3,"t":"2026-07-01T12:00:09Z"}
`
	if err := os.WriteFile(filepath.Join(dir, "event-times.jsonl"), []byte(sidecar), 0o644); err != nil {
		t.Fatal(err)
	}
	// Two events share a source line (split content on one stream line); both
	// must get the timestamp.
	tl := []Event{{srcLine: 2}, {srcLine: 2}}
	if err := applyEventTimes(dir, tl); err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 7, 1, 12, 0, 5, 0, time.UTC)
	for i, e := range tl {
		if e.ObservedAt == nil || !e.ObservedAt.Equal(want) {
			t.Fatalf("event %d ObservedAt = %v, want %v", i, e.ObservedAt, want)
		}
	}
}

func TestApplyEventTimesMissingIsBenign(t *testing.T) {
	if err := applyEventTimes(t.TempDir(), []Event{{srcLine: 1}}); err != nil {
		t.Fatalf("missing sidecar must be benign, got %v", err)
	}
}

func TestApplyEventTimesSurfacesReadError(t *testing.T) {
	dir := t.TempDir()
	// A directory in place of the sidecar file: open succeeds, read fails —
	// that error must be surfaced, not swallowed like the missing-file case.
	if err := os.Mkdir(filepath.Join(dir, "event-times.jsonl"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := applyEventTimes(dir, []Event{{srcLine: 1}}); err == nil {
		t.Fatal("a sidecar read error must be surfaced, got nil")
	}
}

func TestApplyEventTimesSurfacesMalformedSidecar(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "event-times.jsonl"), []byte("not json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applyEventTimes(dir, []Event{{srcLine: 1}}); err == nil {
		t.Fatal("malformed sidecar must be surfaced")
	}
}
