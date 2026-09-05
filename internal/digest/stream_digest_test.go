package digest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nobbettt/acta/internal/runrecord"
)

// The live StreamDigester (fed from the tee during `acta run`) must produce a
// digest byte-identical to FromRunDir re-digesting the same bundle — same
// timeline, same observed_at (joined from the sidecar in the re-digest path,
// stamped directly in the live path).
func TestStreamDigesterMatchesFromRunDir(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	lines := []string{
		`{"type":"thread.started","thread_id":"thread-test"}`,
		`{"type":"turn.started"}`,
		`{"type":"item.started","item":{"id":"c1","type":"command_execution","command":"sed -n '1,5p' main.go"}}`,
		`{"type":"item.completed","item":{"id":"c1","type":"command_execution","command":"sed -n '1,5p' main.go","status":"completed","exit_code":0,"aggregated_output":"1\tpackage main\n2\timport x\n"}}`,
		`{"type":"item.completed","item":{"id":"c2","type":"file_change","status":"completed","changes":[{"path":"main.go","kind":"update"}]}}`,
		`{"type":"turn.completed","usage":{"input_tokens":100,"output_tokens":20}}`,
	}
	if err := os.WriteFile(filepath.Join(dir, "codex-events.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	for i := range lines {
		fmt.Fprintf(&sb, "{\"line\":%d,\"t\":%q}\n", i+1, base.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano))
	}
	if err := os.WriteFile(filepath.Join(dir, "event-times.jsonl"), []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := validTestRecord(dir, "codex-events.jsonl")
	payload, _ := json.Marshal(rec)
	if err := os.WriteFile(filepath.Join(dir, "run.json"), payload, 0o644); err != nil {
		t.Fatal(err)
	}

	fromDir, err := FromRunDir(dir, "")
	if err != nil {
		t.Fatal(err)
	}

	sd, err := NewStreamDigester("codex", dir)
	if err != nil {
		t.Fatal(err)
	}
	for i, l := range lines {
		sd.Line([]byte(l), base.Add(time.Duration(i)*time.Second))
	}
	live := sd.Finalize(&rec, dir)
	// Preservation describes an offline re-projection's handling of live-only
	// evidence and is intentionally absent on the original live projection.
	fromDir.PatchPreservation = PatchPreservation{}

	var liveCommand *Event
	for index := range live.Timeline {
		if live.Timeline[index].Kind == KindCommand {
			liveCommand = &live.Timeline[index]
			break
		}
	}
	// The live path must actually stamp times (not leave them nil).
	if liveCommand == nil || liveCommand.ObservedAt == nil {
		t.Fatal("live digest did not stamp observed_at")
	}
	// And observed_at must be the item.started time, not completion.
	wantStarted := base.Add(2 * time.Second)
	if !liveCommand.ObservedAt.Equal(wantStarted) {
		t.Fatalf("observed_at = %v, want %v (item.started)", liveCommand.ObservedAt, wantStarted)
	}
	wantCompleted := base.Add(3 * time.Second)
	if liveCommand.CompletedAt == nil || !liveCommand.CompletedAt.Equal(wantCompleted) {
		t.Fatalf("completed_at = %v, want %v (item.completed)", liveCommand.CompletedAt, wantCompleted)
	}

	a, _ := json.Marshal(fromDir)
	b, _ := json.Marshal(live)
	if string(a) != string(b) {
		t.Fatalf("live digest != re-digest\n  from_run_dir: %s\n  live:         %s", a, b)
	}
}

// Classification must not depend on how the digest was produced. The
// control-plane directory is caller-declared rather than recorded in the
// bundle, so the re-digest has to be given the same one the run ran with —
// that is what FromRunDirWithOptions is for, and with it the two paths credit
// exactly the same categories.
func TestControlPlaneClassificationSurvivesARedigest(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)
	lines := []string{
		`{"type":"thread.started","thread_id":"thread-control"}`,
		`{"type":"turn.started"}`,
		`{"type":"item.completed","item":{"id":"c1","type":"command_execution","command":"rm stage-control/task.json","status":"completed","exit_code":0,"aggregated_output":""}}`,
		`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`,
	}
	if err := os.WriteFile(filepath.Join(dir, "codex-events.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := validTestRecord(dir, "codex-events.jsonl")
	payload, _ := json.Marshal(rec)
	if err := os.WriteFile(filepath.Join(dir, "run.json"), payload, 0o644); err != nil {
		t.Fatal(err)
	}

	options := Options{ControlPlaneDir: "stage-control"}
	sd, err := NewStreamDigesterWithOptions("codex", dir, options)
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range lines {
		sd.Line([]byte(line), base.Add(time.Duration(i)*time.Second))
	}
	live := sd.Finalize(&rec, dir)

	redigested, err := FromRunDirWithOptions(context.Background(), dir, "", options)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"control.access", "fs.delete"}
	if got := commandCategories(t, live); !reflect.DeepEqual(got, want) {
		t.Fatalf("live categories = %v, want %v", got, want)
	}
	if got := commandCategories(t, redigested); !reflect.DeepEqual(got, want) {
		t.Fatalf("re-digest categories = %v, want %v", got, want)
	}

	// And without the declaration the category is simply never credited, so the
	// option is what carries it rather than something the bundle leaks.
	plain, err := FromRunDir(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := commandCategories(t, plain); !reflect.DeepEqual(got, []string{"fs.delete"}) {
		t.Fatalf("undeclared re-digest categories = %v, want [fs.delete]", got)
	}
}

func TestRedigestIsIndependentOfProcessWorkingDirectoryAndRejectsUnrecordedAlias(t *testing.T) {
	root := t.TempDir()
	workspaceDir := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspaceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "agent-cwd")
	if err := os.Symlink(workspaceDir, alias); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(root, "run")
	if err := os.Mkdir(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	lines := []string{
		`{"type":"thread.started","thread_id":"thread-alias"}`,
		`{"type":"turn.started"}`,
		`{"type":"item.completed","item":{"id":"f1","type":"file_change","status":"completed","changes":[{"path":"` + filepath.ToSlash(filepath.Join(alias, "sample.txt")) + `","kind":"update"}]}}`,
		`{"type":"item.completed","item":{"id":"c1","type":"command_execution","command":"rm stage-control/task.json","status":"completed","exit_code":0,"aggregated_output":""}}`,
		`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`,
	}
	rawName := "codex-events.jsonl"
	if err := os.WriteFile(filepath.Join(runDir, rawName), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := validTestRecord(workspaceDir, rawName)
	rec.RunDir = runDir
	rec.RawStdoutPath = filepath.Join(runDir, rawName)
	rec.RawStderrPath = filepath.Join(runDir, "agent.stderr.log")
	writeRecord(t, runDir, rec)
	options := Options{ControlPlaneDir: filepath.Join(alias, "stage-control")}

	t.Chdir(alias)
	fromAlias, err := FromRunDirWithOptions(context.Background(), runDir, "", options)
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	fromOther, err := FromRunDirWithOptions(context.Background(), runDir, "", options)
	if err != nil {
		t.Fatal(err)
	}

	a, _ := json.Marshal(fromAlias)
	b, _ := json.Marshal(fromOther)
	if string(a) != string(b) {
		t.Fatalf("re-digest depends on process cwd\n  alias cwd: %s\n  other cwd: %s", a, b)
	}
	if len(fromOther.Files) != 0 {
		t.Fatalf("unrecorded alias leaked into files: %+v", fromOther.Files)
	}
	if got := commandCategories(t, fromOther); !reflect.DeepEqual(got, []string{"fs.delete"}) {
		t.Fatalf("categories = %v, want [fs.delete]", got)
	}
}

func commandCategories(t *testing.T, d *Digest) []string {
	t.Helper()
	for _, event := range d.Timeline {
		if event.Kind == KindCommand {
			return event.Categories
		}
	}
	t.Fatal("digest has no command event")
	return nil
}

func TestStreamDigesterCapturesExactPerWritePatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "src", "clock.ts")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("export const cycle = 'h12';\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	sd, err := NewStreamDigester("codex", dir)
	if err != nil {
		t.Fatal(err)
	}
	started := `{"type":"item.started","item":{"id":"write-1","type":"file_change","changes":[{"path":"src/clock.ts","kind":"update"}]}}`
	completed := `{"type":"item.completed","item":{"id":"write-1","type":"file_change","status":"completed","changes":[{"path":"src/clock.ts","kind":"update"}]}}`
	sd.Line([]byte(started), time.Now())
	if err := os.WriteFile(path, []byte("export const cycle = 'h23';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sd.Line([]byte(completed), time.Now())
	d := sd.Finalize(&runrecord.Record{ID: "write-run", Agent: "codex", CWD: dir, RunDir: dir, OK: true}, dir)

	if len(d.Timeline) != 1 || len(d.Timeline[0].FilePatches) != 1 {
		t.Fatalf("captured timeline = %#v", d.Timeline)
	}
	patch := d.Timeline[0].FilePatches[0]
	if patch.Path != "src/clock.ts" || !strings.Contains(patch.Patch, "-export const cycle = 'h12';") || !strings.Contains(patch.Patch, "+export const cycle = 'h23';") {
		t.Fatalf("captured patch = %#v", patch)
	}
}

func TestStreamDigesterCapturesCodexPatchWhenPathArrivesAtCompletion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.go")
	if err := os.WriteFile(path, []byte("package twelve\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "main.go"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, output)
		}
	}

	sd, err := NewStreamDigester("codex", dir)
	if err != nil {
		t.Fatal(err)
	}
	sd.Line([]byte(`{"type":"item.started","item":{"id":"write-1","type":"file_change"}}`), time.Now())
	if err := os.WriteFile(path, []byte("package twentyfour\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sd.Line([]byte(`{"type":"item.completed","item":{"id":"write-1","type":"file_change","status":"completed","changes":[{"path":"main.go","kind":"update"}]}}`), time.Now())
	d := sd.Finalize(&runrecord.Record{ID: "write-run", Agent: "codex", CWD: dir, RunDir: dir, OK: true}, dir)

	if len(d.Timeline) != 1 || len(d.Timeline[0].FilePatches) != 1 {
		t.Fatalf("captured timeline = %#v", d.Timeline)
	}
	patch := d.Timeline[0].FilePatches[0].Patch
	if !strings.Contains(patch, "-package twelve") || !strings.Contains(patch, "+package twentyfour") {
		t.Fatalf("captured patch = %q", patch)
	}
}

func TestStreamDigesterCapturesClaudeExactPerWritePatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "src", "clock.ts")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("export const cycle = 'h12';\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	sd, err := NewStreamDigester("claude", dir)
	if err != nil {
		t.Fatal(err)
	}
	started := `{"type":"assistant","message":{"id":"message-1","content":[{"type":"tool_use","id":"write-1","name":"Edit","input":{"file_path":"src/clock.ts","old_string":"h12","new_string":"h23"}}]}}`
	completed := `{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"write-1","content":"Updated src/clock.ts"}]}}`
	sd.Line([]byte(started), time.Now())
	if err := os.WriteFile(path, []byte("export const cycle = 'h23';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sd.Line([]byte(completed), time.Now())
	d := sd.Finalize(&runrecord.Record{ID: "write-run", Agent: "claude", CWD: dir, RunDir: dir, OK: true}, dir)

	if len(d.Timeline) != 1 || len(d.Timeline[0].FilePatches) != 1 {
		t.Fatalf("captured timeline = %#v", d.Timeline)
	}
	patch := d.Timeline[0].FilePatches[0]
	if patch.Path != "src/clock.ts" || !strings.Contains(patch.Patch, "-export const cycle = 'h12';") || !strings.Contains(patch.Patch, "+export const cycle = 'h23';") {
		t.Fatalf("captured patch = %#v", patch)
	}
}
