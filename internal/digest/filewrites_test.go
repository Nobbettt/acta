package digest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRestoreCapturedFilePatches(t *testing.T) {
	dir := t.TempDir()
	prior := Digest{SchemaVersion: SchemaVersion, Timeline: []Event{{
		Kind: KindFileEdit, ProviderEvent: "file_change", ID: "write-1",
		FilePatches: []FilePatch{{Path: "src/clock.ts", Patch: "diff --git a/src/clock.ts b/src/clock.ts\n"}},
	}}}
	payload, err := json.Marshal(prior)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "digest.json"), payload, 0o644); err != nil {
		t.Fatal(err)
	}

	replayed := Digest{Timeline: []Event{{Kind: KindFileEdit, ProviderEvent: "file_change", ID: "write-1"}}}
	if err := restoreCapturedFilePatches(context.Background(), dir, &replayed); err != nil {
		t.Fatal(err)
	}
	if len(replayed.Timeline[0].FilePatches) != 1 || replayed.Timeline[0].FilePatches[0].Path != "src/clock.ts" {
		t.Fatalf("restored patches = %#v", replayed.Timeline[0].FilePatches)
	}
}

func TestWriteTrackerExcludesPrivateControlFiles(t *testing.T) {
	dir := t.TempDir()
	tracker := newFileWriteTracker(newWorkspace(dir), ".stage-control", ".acta/runs")
	tracker.start("write-1", []string{".stage-control/private.json", ".acta/runs/private.json"})
	if snapshots := tracker.finish("write-1", []string{".stage-control/private.json", ".acta/runs/private.json"}); len(snapshots) != 0 {
		t.Fatalf("private control snapshots = %#v", snapshots)
	}
}

func TestWriteTrackerCapturesModeOnlyExecutableChange(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows chmod does not expose a Unix executable bit through os.FileMode")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "tool.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tracker := newFileWriteTracker(newWorkspace(dir))
	tracker.start("write-1", []string{"tool.sh"})
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	snapshots := tracker.finish("write-1", []string{"tool.sh"})
	d := &Digest{Timeline: []Event{{Kind: KindFileEdit, ID: "write-1", fileSnapshots: snapshots}}}
	attachCapturedFilePatches(d)
	if len(d.Timeline[0].FilePatches) != 1 || !strings.Contains(d.Timeline[0].FilePatches[0].Patch, "old mode 100644") || !strings.Contains(d.Timeline[0].FilePatches[0].Patch, "new mode 100755") {
		t.Fatalf("mode-only evidence = %+v", d.Timeline[0])
	}
}

func TestWriteTrackerIgnoresNonGitPermissionChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tracker := newFileWriteTracker(newWorkspace(dir))
	tracker.start("write-1", []string{"tool.sh"})
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if snapshots := tracker.finish("write-1", []string{"tool.sh"}); len(snapshots) != 0 {
		t.Fatalf("non-executable permission-only change produced evidence: %+v", snapshots)
	}
}

func TestWriteTrackerDoesNotBroadlyExcludeNamedDirectories(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{".acta/config", ".stage-control/user.txt"} {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("before\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		tracker := newFileWriteTracker(newWorkspace(dir))
		tracker.start(name, []string{name})
		if err := os.WriteFile(path, []byte("after\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if snapshots := tracker.finish(name, []string{name}); len(snapshots) != 1 {
			t.Fatalf("%s snapshots = %+v", name, snapshots)
		}
	}
}

func TestWriteTrackerSurfacesAggregateSnapshotBudget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.go")
	if err := os.WriteFile(path, []byte("before\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tracker := newFileWriteTracker(newWorkspace(dir))
	tracker.writeEvidenceLimit = 1
	tracker.start("write-1", []string{"main.go"})
	if err := os.WriteFile(path, []byte("after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshots := tracker.finish("write-1", []string{"main.go"})
	if len(snapshots) != 0 || !tracker.writeCapExhausted {
		t.Fatalf("snapshots=%v cap_exhausted=%v", snapshots, tracker.writeCapExhausted)
	}
	d := &Digest{Timeline: []Event{{Kind: KindFileEdit}}}
	if err := tracker.evidenceError(d); err == nil || !strings.Contains(err.Error(), "per-write snapshots exceeded") {
		t.Fatalf("evidence error = %v", err)
	}
}

func TestAttachPatchesHonorsFinalProjectionBudget(t *testing.T) {
	snapshot := fileWriteSnapshot{
		path:   "main.go",
		before: capturedFileVersion{exists: true, content: []byte(strings.Repeat("before", 128) + "\n"), mode: 0o644},
		after:  capturedFileVersion{exists: true, content: []byte(strings.Repeat("after", 128) + "\n"), mode: 0o644},
	}
	event := Event{Kind: KindFileEdit, ID: "write-1", fileSnapshots: []fileWriteSnapshot{snapshot}}
	base, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	d := &Digest{Timeline: []Event{event}, projectionLimitBytes: len(base) + 256}
	attachCapturedFilePatches(d)
	got := d.Timeline[0]
	if len(got.FilePatches) != 0 || got.FilePatchStatus != "unavailable" || len(got.FilePatchErrors) == 0 || !strings.Contains(got.FilePatchErrors[0], "projection budget") {
		t.Fatalf("budgeted patch event = %+v", got)
	}
	if d.Termination.Outcome != OutcomeDegraded || !d.Metrics.ProjectionTruncated {
		t.Fatalf("digest did not surface patch-budget degradation: metrics=%+v termination=%+v", d.Metrics, d.Termination)
	}
}
