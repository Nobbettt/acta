package digest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nobbettt/acta/internal/gitdiff"
	"github.com/nobbettt/acta/internal/securefile"
)

const (
	maxCapturedWriteFileBytes = 2 << 20
	maxCapturedWorkspaceBytes = 64 << 20
	maxCapturedRunWriteBytes  = 64 << 20
	maxWritePatchBytes        = 2 << 20
	workspaceListingTimeout   = 30 * time.Second
)

type capturedFileVersion struct {
	exists  bool
	content []byte
	mode    os.FileMode
}

type fileWriteSnapshot struct {
	path   string
	before capturedFileVersion
	after  capturedFileVersion
}

type fileWriteTracker struct {
	workspace          *workspace
	before             map[string]map[string]capturedFileVersion
	current            map[string]capturedFileVersion
	exclusions         []string
	initialError       string
	workspaceIsRepo    bool
	capExhausted       bool
	writeCapExhausted  bool
	writeEvidenceBytes int64
	writeEvidenceLimit int64
}

func (tracker *fileWriteTracker) evidenceError(d *Digest) error {
	if tracker == nil || d == nil || (tracker.initialError == "" && !tracker.capExhausted && !tracker.writeCapExhausted) {
		return nil
	}
	hasFileEdit := false
	for _, event := range d.Timeline {
		if event.Kind == KindFileEdit {
			hasFileEdit = true
			break
		}
	}
	if !hasFileEdit {
		return nil
	}
	parts := []string{}
	if tracker.initialError != "" {
		parts = append(parts, tracker.initialError)
	}
	if tracker.capExhausted {
		parts = append(parts, fmt.Sprintf("initial workspace snapshot exceeded %d bytes", maxCapturedWorkspaceBytes))
	}
	if tracker.writeCapExhausted {
		parts = append(parts, fmt.Sprintf("per-write snapshots exceeded %d bytes for this run", maxCapturedRunWriteBytes))
	}
	return errors.New(strings.Join(parts, "; "))
}

func newFileWriteTracker(workspace *workspace, exclusions ...string) *fileWriteTracker {
	return newFileWriteTrackerForWorkspace(workspace, false, exclusions...)
}

func newFileWriteTrackerForWorkspace(workspace *workspace, workspaceIsRepo bool, exclusions ...string) *fileWriteTracker {
	tracker := &fileWriteTracker{
		workspace:          workspace,
		before:             map[string]map[string]capturedFileVersion{},
		current:            map[string]capturedFileVersion{},
		exclusions:         append([]string(nil), exclusions...),
		workspaceIsRepo:    workspaceIsRepo,
		writeEvidenceLimit: maxCapturedRunWriteBytes,
	}
	if workspaceIsRepo {
		tracker.captureInitialWorkspace()
	}
	return tracker
}

func (tracker *fileWriteTracker) captureInitialWorkspace() {
	if tracker == nil || tracker.workspace == nil || tracker.workspace.root == "" {
		return
	}
	root := tracker.workspace.root
	ctx, cancel := context.WithTimeout(context.Background(), workspaceListingTimeout)
	defer cancel()
	files, err := gitdiff.WorkspaceFiles(ctx, root)
	if err != nil {
		tracker.initialError = "initial workspace listing failed: " + err.Error()
		return
	}
	totalBytes := 0
	for _, name := range files {
		path := filepath.ToSlash(name)
		if path == "" || tracker.excluded(path) {
			continue
		}
		version, ok := tracker.read(path)
		if !ok || !version.exists {
			continue
		}
		if totalBytes+len(version.content) > maxCapturedWorkspaceBytes {
			tracker.capExhausted = true
			continue
		}
		tracker.current[path] = version
		totalBytes += len(version.content)
	}
}

func (tracker *fileWriteTracker) excluded(path string) bool {
	if path == ".git" || strings.HasPrefix(path, ".git/") {
		return true
	}
	for _, exclusion := range tracker.exclusions {
		exclusion = strings.Trim(strings.TrimSpace(filepath.ToSlash(exclusion)), "/")
		if exclusion != "" && (path == exclusion || strings.HasPrefix(path, exclusion+"/")) {
			return true
		}
	}
	return false
}

func (tracker *fileWriteTracker) read(path string) (capturedFileVersion, bool) {
	if tracker == nil || tracker.workspace == nil || tracker.workspace.root == "" || tracker.excluded(path) {
		return capturedFileVersion{}, false
	}
	root := tracker.workspace.root
	target := filepath.Join(root, filepath.FromSlash(path))
	info, err := os.Lstat(target)
	if os.IsNotExist(err) {
		return capturedFileVersion{}, true
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxCapturedWriteFileBytes {
		return capturedFileVersion{}, false
	}
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return capturedFileVersion{}, false
	}
	if _, ok := tracker.workspace.rel(resolved); !ok {
		return capturedFileVersion{}, false
	}
	content, err := os.ReadFile(resolved)
	if err != nil || len(content) > maxCapturedWriteFileBytes || bytes.IndexByte(content, 0) >= 0 {
		return capturedFileVersion{}, false
	}
	return capturedFileVersion{exists: true, content: content, mode: info.Mode()}, true
}

func (tracker *fileWriteTracker) start(id string, paths []string) {
	if tracker == nil || strings.TrimSpace(id) == "" {
		return
	}
	if _, exists := tracker.before[id]; exists {
		return
	}
	versions := map[string]capturedFileVersion{}
	for _, path := range paths {
		if version, ok := tracker.read(path); ok {
			versions[path] = version
		}
	}
	if len(versions) > 0 {
		tracker.before[id] = versions
	}
}

func (tracker *fileWriteTracker) assumeMissing(id string, paths []string) {
	if tracker == nil || id == "" || len(paths) == 0 {
		return
	}
	if tracker.before[id] == nil {
		tracker.before[id] = map[string]capturedFileVersion{}
	}
	for _, path := range paths {
		if _, captured := tracker.before[id][path]; !captured {
			if _, existedAtStart := tracker.current[path]; !existedAtStart {
				tracker.before[id][path] = capturedFileVersion{}
			}
		}
	}
}

func (tracker *fileWriteTracker) finish(id string, paths []string) []fileWriteSnapshot {
	if tracker == nil {
		return nil
	}
	before := tracker.before[id]
	delete(tracker.before, id)
	var snapshots []fileWriteSnapshot
	for _, path := range paths {
		beforeVersion, beforeKnown := before[path]
		if !beforeKnown {
			beforeVersion, beforeKnown = tracker.current[path]
		}
		afterVersion, afterKnown := tracker.read(path)
		if !afterKnown {
			continue
		}
		tracker.current[path] = afterVersion
		beforeExecutable := beforeVersion.mode.Perm()&0o111 != 0
		afterExecutable := afterVersion.mode.Perm()&0o111 != 0
		if !beforeKnown || (beforeVersion.exists == afterVersion.exists && beforeExecutable == afterExecutable && bytes.Equal(beforeVersion.content, afterVersion.content)) {
			continue
		}
		snapshotBytes := int64(len(beforeVersion.content) + len(afterVersion.content))
		if tracker.writeEvidenceBytes+snapshotBytes > tracker.writeEvidenceLimit {
			tracker.writeCapExhausted = true
			continue
		}
		tracker.writeEvidenceBytes += snapshotBytes
		snapshots = append(snapshots, fileWriteSnapshot{path: path, before: beforeVersion, after: afterVersion})
	}
	return snapshots
}

func attachCapturedFilePatches(d *Digest) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Recalculate from exported fields so tests/offline callers which construct a
	// Digest directly get the same exact budget accounting as the live builder.
	d.projectionBytes = 0
	for index := range d.Timeline {
		eventBytes, _ := eventProjectionBytes(d.Timeline[index])
		d.projectionBytes += eventBytes
	}
	for index := range d.Timeline {
		event := &d.Timeline[index]
		if event.Kind != KindFileEdit {
			continue
		}
		originalBytes, _ := eventProjectionBytes(*event)
		if len(event.fileSnapshots) == 0 {
			event.FilePatchStatus = "unavailable"
			event.FilePatchErrors = append(event.FilePatchErrors, "write snapshot was unavailable or no content change was observed")
			finalBytes, _ := eventProjectionBytes(*event)
			d.projectionBytes = d.projectionBytes - originalBytes + finalBytes
			continue
		}
		totalBytes := 0
		for _, snapshot := range event.fileSnapshots {
			patch, err := gitdiff.FilePatch(ctx, snapshot.path,
				gitdiff.FileVersion{Exists: snapshot.before.exists, Content: snapshot.before.content, Mode: snapshot.before.mode},
				gitdiff.FileVersion{Exists: snapshot.after.exists, Content: snapshot.after.content, Mode: snapshot.after.mode},
			)
			if err != nil {
				event.FilePatchErrors = append(event.FilePatchErrors, fmt.Sprintf("%s: %v", snapshot.path, err))
				continue
			}
			if patch == "" {
				event.FilePatchErrors = append(event.FilePatchErrors, snapshot.path+": patch was empty")
				continue
			}
			if len(patch) > maxWritePatchBytes || totalBytes+len(patch) > maxWritePatchBytes {
				event.FilePatchErrors = append(event.FilePatchErrors, snapshot.path+": patch exceeded the per-event evidence limit")
				continue
			}
			event.FilePatches = append(event.FilePatches, FilePatch{Path: snapshot.path, Patch: patch})
			totalBytes += len(patch)
		}
		switch {
		case len(event.FilePatches) > 0 && len(event.FilePatchErrors) == 0:
			event.FilePatchStatus = "captured"
		case len(event.FilePatches) > 0:
			event.FilePatchStatus = "partial"
		default:
			event.FilePatchStatus = "unavailable"
		}
		finalBytes, marshalErr := eventProjectionBytes(*event)
		if marshalErr != nil || d.projectionBytes-originalBytes+finalBytes > d.projectionLimit() {
			event.FilePatches = nil
			event.FilePatchStatus = "unavailable"
			event.FilePatchErrors = []string{"patch evidence exceeded the normalized projection budget"}
			finalBytes, _ = eventProjectionBytes(*event)
			d.Metrics.ProjectionTruncated = true
			d.Termination.Outcome = OutcomeDegraded
			d.Termination.ProviderReason = "write_evidence_projection_limit"
			d.Termination.ErrorMessage = "per-write patch evidence exceeded the normalized projection budget"
			if d.projectionBytes-originalBytes+finalBytes > d.projectionLimit() {
				event.FilePatchStatus = ""
				event.FilePatchErrors = nil
				finalBytes = originalBytes
			}
		}
		d.projectionBytes = d.projectionBytes - originalBytes + finalBytes
		event.fileSnapshots = nil
	}
}

func markUnavailableFilePatches(d *Digest) {
	for index := range d.Timeline {
		event := &d.Timeline[index]
		if event.Kind == KindFileEdit && len(event.FilePatches) == 0 && event.FilePatchStatus == "" {
			event.FilePatchStatus = "unavailable"
			event.FilePatchErrors = []string{"write snapshot was unavailable or no content change was observed"}
		}
	}
}

func filePatchIdentity(event Event) string {
	if event.ID != "" {
		return event.ProviderEvent + ":" + event.ID
	}
	return fmt.Sprintf("%s:%v", event.ProviderEvent, event.RawEventLines)
}

// restoreCapturedFilePatches keeps live-only write evidence when `acta
// digest` replays the immutable provider stream after the workspace has
// already reached its final state.
func restoreCapturedFilePatches(ctx context.Context, runDir string, d *Digest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path := filepath.Join(runDir, "digest.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		d.PatchPreservation.Status = "not_available"
		return nil
	} else if err != nil {
		d.PatchPreservation = PatchPreservation{Status: "invalid", Error: err.Error()}
		return fmt.Errorf("inspect prior digest for write evidence: %w", err)
	}
	payload, err := securefile.ReadRegularFile(runDir, path, 64<<20)
	if err != nil {
		d.PatchPreservation = PatchPreservation{Status: "invalid", Error: err.Error()}
		return fmt.Errorf("read prior digest for write evidence: %w", err)
	}
	var prior Digest
	if err := json.Unmarshal(payload, &prior); err != nil {
		d.PatchPreservation = PatchPreservation{Status: "invalid", Error: err.Error()}
		return fmt.Errorf("parse prior digest for write evidence: %w", err)
	}
	if prior.SchemaVersion < MinSchemaVersion || prior.SchemaVersion > SchemaVersion {
		err := fmt.Errorf("unsupported prior digest schema_version %d", prior.SchemaVersion)
		d.PatchPreservation = PatchPreservation{Status: "invalid", Error: err.Error()}
		return err
	}
	patches := map[string][]FilePatch{}
	priorPatchEvents := 0
	priorPatchBytes := 0
	identities := map[string]bool{}
	for _, event := range prior.Timeline {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(event.FilePatches) > 0 {
			if event.Kind != KindFileEdit {
				return invalidPatchPreservation(d, "prior write evidence is attached to a non-file-edit event")
			}
			identity := filePatchIdentity(event)
			if identities[identity] {
				return invalidPatchPreservation(d, "prior write evidence contains duplicate event identity "+identity)
			}
			identities[identity] = true
			for _, evidence := range event.FilePatches {
				if err := validatePreservedPatch(evidence); err != nil {
					return invalidPatchPreservation(d, err.Error())
				}
				priorPatchBytes += len(evidence.Patch)
				if priorPatchBytes > maxCapturedWorkspaceBytes {
					return invalidPatchPreservation(d, "prior write evidence exceeds aggregate size limit")
				}
			}
			patches[identity] = event.FilePatches
			priorPatchEvents++
		}
	}
	if priorPatchEvents == 0 {
		d.PatchPreservation.Status = "not_available"
		return nil
	}
	preserved := 0
	for index := range d.Timeline {
		if err := ctx.Err(); err != nil {
			return err
		}
		if retained := patches[filePatchIdentity(d.Timeline[index])]; len(retained) > 0 {
			d.Timeline[index].FilePatches = retained
			d.Timeline[index].FilePatchStatus = "preserved"
			preserved++
		}
	}
	d.PatchPreservation.Preserved = preserved
	d.PatchPreservation.Missing = priorPatchEvents - preserved
	if preserved == priorPatchEvents {
		d.PatchPreservation.Status = "preserved"
		return nil
	}
	d.PatchPreservation.Status = "partial"
	d.PatchPreservation.Error = fmt.Sprintf("%d of %d write-evidence event(s) could not be matched", priorPatchEvents-preserved, priorPatchEvents)
	return errors.New(d.PatchPreservation.Error)
}

func invalidPatchPreservation(d *Digest, message string) error {
	d.PatchPreservation = PatchPreservation{Status: "invalid", Error: message}
	return errors.New(message)
}

func validatePreservedPatch(evidence FilePatch) error {
	path := filepath.ToSlash(strings.TrimSpace(evidence.Path))
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if path == "" || clean != path || path == "." || path == ".." || strings.HasPrefix(path, "../") || filepath.IsAbs(filepath.FromSlash(path)) || strings.Contains(path, `\`) {
		return fmt.Errorf("prior write evidence has unsafe path %q", evidence.Path)
	}
	if len(evidence.Patch) == 0 || len(evidence.Patch) > maxWritePatchBytes || strings.IndexByte(evidence.Patch, 0) >= 0 {
		return fmt.Errorf("prior write evidence for %q has invalid patch size or content", path)
	}
	header := "diff --git a/" + path + " b/" + path + "\n"
	quotedHeader := "diff --git " + strconv.Quote("a/"+path) + " " + strconv.Quote("b/"+path) + "\n"
	if !strings.HasPrefix(evidence.Patch, header) && !strings.HasPrefix(evidence.Patch, quotedHeader) {
		return fmt.Errorf("prior write evidence for %q has a mismatched diff header", path)
	}
	return nil
}
