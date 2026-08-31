package reporting

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/nobbettt/acta/internal/actaevents"
	"github.com/nobbettt/acta/internal/digest"
	"github.com/nobbettt/acta/internal/runrecord"
	"github.com/nobbettt/acta/internal/schemaversion"
	"github.com/nobbettt/acta/internal/securefile"
)

func TestWriterEventBudgetFitsUploadEnvelope(t *testing.T) {
	if got := eventsEnvelopeBytes + actaevents.MaxEventBytes - 1; got > maxEventsRequestBytes {
		t.Fatalf("writer-valid event plus upload envelope = %d, request maximum = %d", got, maxEventsRequestBytes)
	}
}

func TestUploadRunPostsRunEventsArtifactsAndCompletion(t *testing.T) {
	runDir := writeBundle(t)
	record := testRecord(runDir)

	var paths []string
	var sawAuth bool
	var artifactFilename string
	var eventArtifactSchemaVersion string
	var artifactChecks int
	var createStatus string
	var createOrganizationID string
	var createRepositoryID string
	var createMetadata runMetadataPayload
	var sawEvents bool
	var completeStatus string
	var completeMetadata completionMetadata
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("Authorization") == "Bearer secret-token" {
			sawAuth = true
		}
		if r.URL.Path == "/api/ingest/runs" {
			var req createRunRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode create run request: %v", err)
			}
			createStatus = req.Status
			createOrganizationID = req.OrganizationID
			createRepositoryID = req.RepositoryID
			createMetadata = req.Metadata
		}
		if r.URL.Path == "/api/ingest/runs/run-1/events" {
			var req eventsRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode events request: %v", err)
			}
			if len(req.Events) == 0 {
				t.Fatal("events request had no events")
			}
			for _, event := range req.Events {
				if event.RunID != "run-1" {
					t.Fatalf("event run_id = %q, want run-1", event.RunID)
				}
			}
			sawEvents = true
		}
		if r.URL.Path == "/api/ingest/runs/run-1/artifacts" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read artifact body: %v", err)
			}
			if len(body) == 0 {
				t.Fatal("artifact request had empty body")
			}
			sizeBytes, err := strconv.ParseInt(r.URL.Query().Get("size_bytes"), 10, 64)
			if err != nil {
				t.Fatalf("artifact request had invalid size_bytes query parameter: %v", err)
			}
			if sizeBytes != int64(len(body)) {
				t.Fatalf("artifact size_bytes = %d, body length = %d", sizeBytes, len(body))
			}
			if artifactFilename == "" {
				artifactFilename = r.URL.Query().Get("filename")
			}
			if r.URL.Query().Get("filename") == actaevents.Filename {
				eventArtifactSchemaVersion = r.URL.Query().Get("schema_version")
			}
			if r.URL.Query().Get("kind") == "" {
				t.Fatal("artifact request had empty kind query parameter")
			}
			if r.URL.Query().Get("filename") == "" {
				t.Fatal("artifact request had empty filename query parameter")
			}
			if r.URL.Query().Get("content_type") == "" {
				t.Fatal("artifact request had empty content_type query parameter")
			}
			sum := sha256.Sum256(body)
			if got, want := r.URL.Query().Get("sha256"), hex.EncodeToString(sum[:]); got != want {
				t.Fatalf("artifact sha256 = %q, want %q", got, want)
			}
			artifactChecks++
		}
		if r.URL.Path == "/api/ingest/runs/run-1/complete" {
			var req completeRunRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode complete request: %v", err)
			}
			completeStatus = req.Status
			completeMetadata = req.Metadata
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := UploadRun(context.Background(), Config{
		BackendURL:     server.URL,
		ReportToken:    "secret-token",
		OrganizationID: "11111111-1111-1111-1111-111111111111",
		RepositoryID:   "22222222-2222-2222-2222-222222222222",
		HTTPClient:     server.Client(),
		RetryDelays:    []time.Duration{},
	}, record); err != nil {
		t.Fatalf("UploadRun() error = %v", err)
	}

	want := []string{
		"/api/ingest/runs",
		"/api/ingest/runs/run-1/events",
		"/api/ingest/runs/run-1/artifacts",
		"/api/ingest/runs/run-1/artifacts",
		"/api/ingest/runs/run-1/artifacts",
		"/api/ingest/runs/run-1/complete",
	}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	if !sawAuth {
		t.Fatal("Authorization bearer token was not sent")
	}
	if artifactFilename != "run.json" {
		t.Fatalf("first artifact filename = %q, want run.json", artifactFilename)
	}
	if artifactChecks != 3 {
		t.Fatalf("artifact checks = %d, want 3", artifactChecks)
	}
	if eventArtifactSchemaVersion != "2" {
		t.Fatalf("v2 event artifact schema_version metadata = %q, want 2", eventArtifactSchemaVersion)
	}
	if createStatus != "running" {
		t.Fatalf("create status = %q, want running", createStatus)
	}
	if !sawEvents {
		t.Fatal("events request was not validated")
	}
	if completeStatus != "completed" {
		t.Fatalf("complete status = %q, want completed", completeStatus)
	}
	if createOrganizationID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("create organization_id = %q, want scoped id", createOrganizationID)
	}
	if createRepositoryID != "22222222-2222-2222-2222-222222222222" {
		t.Fatalf("create repository_id = %q, want scoped id", createRepositoryID)
	}
	if createMetadata.Repository != "example-org/example-repo" {
		t.Fatalf("metadata repository = %#v, want example-org/example-repo", createMetadata.Repository)
	}
	if createMetadata.IssueTitle != "Upload run bundles" {
		t.Fatalf("metadata issue_title = %#v, want Upload run bundles", createMetadata.IssueTitle)
	}
	if createMetadata.IssueBody == nil || *createMetadata.IssueBody != "## Issue basis\n\nUpload this bundle.\n" {
		t.Fatalf("metadata issue_body = %#v, want issue body", createMetadata.IssueBody)
	}
	if createMetadata.TaskTitle != "Upload run bundles" {
		t.Fatalf("metadata title = %#v, want Upload run bundles", createMetadata.TaskTitle)
	}
	if createMetadata.IssueNumber != 42 {
		t.Fatalf("metadata issue_number = %#v, want 42", createMetadata.IssueNumber)
	}
	if createMetadata.TerminationReason != "completed" {
		t.Fatalf("metadata termination_reason = %#v, want completed", createMetadata.TerminationReason)
	}
	if !createMetadata.PromptCaptured {
		t.Fatal("metadata prompt_captured = false, want true")
	}
	if completeMetadata.TerminationReason != "completed" {
		t.Fatalf("completion termination_reason = %#v, want completed", completeMetadata.TerminationReason)
	}
}

func TestUploadRunRetriesChangedProjectionGeneration(t *testing.T) {
	runDir := writeBundle(t)
	oldDigest := readTestFile(t, filepath.Join(runDir, "digest.json"))
	oldEvents := readTestFile(t, filepath.Join(runDir, actaevents.Filename))
	writeProjectionGeneration(t, runDir, "100", oldDigest, oldEvents)

	newDigest := `{"run_id":"run-1","generation":"new"}` + "\n"
	newEvents := strings.Replace(oldEvents, `"duration_ms":1000`, `"duration_ms":2000`, 1)
	var attempts []int
	var uploadedDigest string
	var uploadedDuration int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/ingest/runs/run-1/events" {
			var body eventsRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			for _, event := range body.Events {
				if event.Type == actaevents.TypeRunCompleted {
					var payload struct {
						DurationMillis int64 `json:"duration_ms"`
					}
					if err := json.Unmarshal(event.Payload, &payload); err != nil {
						t.Error(err)
					}
					uploadedDuration = payload.DurationMillis
				}
			}
		}
		if request.URL.Path == "/api/ingest/runs/run-1/artifacts" && request.URL.Query().Get("filename") == "digest.json" {
			payload, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			uploadedDigest = string(payload)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
		AllowUnredactedRemoteReasoning: true,
		projectionSnapshotHook: func(attempt int) {
			attempts = append(attempts, attempt)
			if attempt == 1 {
				writeProjectionGeneration(t, runDir, "200", newDigest, newEvents)
			}
		},
	}, testRecord(runDir))
	if err != nil {
		t.Fatalf("UploadRun() error = %v", err)
	}
	if len(attempts) != 2 {
		t.Fatalf("projection snapshot attempts = %v, want [1 2]", attempts)
	}
	if uploadedDigest != newDigest || uploadedDuration != 2000 {
		t.Fatalf("uploaded generation digest/duration = %q/%d, want new generation %q/2000", uploadedDigest, uploadedDuration, newDigest)
	}
}

func TestManifestedProjectionUsesDeleteSharedOpenSeam(t *testing.T) {
	runDir := writeBundle(t)
	digestPayload := readTestFile(t, filepath.Join(runDir, "digest.json"))
	eventsPayload := readTestFile(t, filepath.Join(runDir, actaevents.Filename))
	writeProjectionGeneration(t, runDir, "100", digestPayload, eventsPayload)

	originalOpen := openManifestedProjectionRegular
	opened := make(map[string]int)
	openManifestedProjectionRegular = func(root, path string) (*os.File, error) {
		opened[filepath.Base(path)]++
		return originalOpen(root, path)
	}
	t.Cleanup(func() { openManifestedProjectionRegular = originalOpen })

	snapshots, manifested, retry, err := snapshotProjectionArtifactsContext(context.Background(), runDir, DefaultMaxUploadBytes, 1, nil)
	if err != nil || !manifested || retry {
		closeArtifactSnapshots(snapshots)
		t.Fatalf("manifested snapshot = manifested %v, retry %v, error %v", manifested, retry, err)
	}
	closeArtifactSnapshots(snapshots)
	if opened["projection.json"] != 2 || opened["digest.json"] != 1 || opened[actaevents.Filename] != 1 {
		t.Fatalf("delete-shared secure opens = %v, want manifest twice and each projection source once", opened)
	}
}

func TestProjectionSnapshotsShareCumulativeBudget(t *testing.T) {
	const sourceSize int64 = 96
	payload := strings.Repeat("x", int(sourceSize))
	tests := []struct {
		name        string
		manifested  bool
		sourceNames []string
	}{
		{name: "manifested", manifested: true, sourceNames: []string{actaevents.Filename, "run.json", "digest.json"}},
		{name: "legacy", sourceNames: []string{actaevents.Filename, "digest.json"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runDir := t.TempDir()
			for _, name := range test.sourceNames {
				writeFile(t, filepath.Join(runDir, name), payload)
			}
			if test.manifested {
				hash := fmt.Sprintf("%x", sha256.Sum256([]byte(payload)))
				manifestPayload, err := json.Marshal(projectionManifest{
					SchemaVersion: actaevents.ProjectionSchemaVersion,
					Producer:      runrecord.Producer{Name: "acta", Version: "test"},
					Generation:    "1",
					RunSHA256:     hash,
					DigestSHA256:  hash,
					EventsSHA256:  hash,
				})
				if err != nil {
					t.Fatal(err)
				}
				writeFile(t, filepath.Join(runDir, "projection.json"), string(manifestPayload)+"\n")
			}

			t.Run("over budget", func(t *testing.T) {
				tempDir := useSnapshotTempDir(t)
				maxBytes := sourceSize + 1
				snapshots, manifested, retry, err := snapshotProjectionArtifactsContext(context.Background(), runDir, maxBytes, 1, nil)
				closeArtifactSnapshots(snapshots)
				if err == nil || !strings.Contains(err.Error(), "remaining upload snapshot maximum") {
					t.Fatalf("snapshot error = %v, want existing over-budget classification", err)
				}
				if manifested != test.manifested || retry {
					t.Fatalf("snapshot = manifested %v, retry %v; want manifested %v, retry false", manifested, retry, test.manifested)
				}
				assertDirectoryEmpty(t, tempDir)
			})

			t.Run("within budget", func(t *testing.T) {
				tempDir := useSnapshotTempDir(t)
				maxBytes := sourceSize * int64(len(test.sourceNames))
				snapshots, manifested, retry, err := snapshotProjectionArtifactsContext(context.Background(), runDir, maxBytes, 1, nil)
				if err != nil || manifested != test.manifested || retry {
					closeArtifactSnapshots(snapshots)
					t.Fatalf("snapshot = manifested %v, retry %v, error %v; want manifested %v, retry false", manifested, retry, err, test.manifested)
				}
				if len(snapshots) != len(test.sourceNames) {
					closeArtifactSnapshots(snapshots)
					t.Fatalf("snapshot count = %d, want %d", len(snapshots), len(test.sourceNames))
				}
				for _, name := range test.sourceNames {
					info, statErr := snapshots[name].File.Stat()
					if statErr != nil {
						closeArtifactSnapshots(snapshots)
						t.Fatalf("stat snapshot %s: %v", name, statErr)
					}
					if info.Size() != sourceSize {
						closeArtifactSnapshots(snapshots)
						t.Fatalf("snapshot %s size = %d, want %d", name, info.Size(), sourceSize)
					}
				}
				closeArtifactSnapshots(snapshots)
				assertDirectoryEmpty(t, tempDir)
			})
		})
	}
}

func TestUploadRunRejectsRepeatedlyChangingProjectionBeforeUpload(t *testing.T) {
	runDir := writeBundle(t)
	events := readTestFile(t, filepath.Join(runDir, actaevents.Filename))
	writeProjectionGeneration(t, runDir, "100", readTestFile(t, filepath.Join(runDir, "digest.json")), events)

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	var attempts []int
	err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
		AllowUnredactedRemoteReasoning: true,
		projectionSnapshotHook: func(attempt int) {
			attempts = append(attempts, attempt)
			digestPayload := fmt.Sprintf("{\"run_id\":\"run-1\",\"attempt\":%d}\n", attempt)
			writeProjectionGeneration(t, runDir, strconv.Itoa(100+attempt), digestPayload, events)
		},
	}, testRecord(runDir))
	if err == nil || !strings.Contains(err.Error(), "torn bundle") || !strings.Contains(err.Error(), "after 3 attempts") {
		t.Fatalf("UploadRun() error = %v, want bounded torn-bundle error", err)
	}
	if len(attempts) != maxProjectionSnapshotAttempts {
		t.Fatalf("projection snapshot attempts = %v, want %d attempts", attempts, maxProjectionSnapshotAttempts)
	}
	if requests != 0 {
		t.Fatalf("torn bundle issued %d upload requests, want none", requests)
	}
}

func TestUploadRunSteadyProjectionUsesSinglePass(t *testing.T) {
	runDir := writeBundle(t)
	digestPayload := readTestFile(t, filepath.Join(runDir, "digest.json"))
	eventsPayload := readTestFile(t, filepath.Join(runDir, actaevents.Filename))
	writeProjectionGeneration(t, runDir, "100", digestPayload, eventsPayload)

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
		AllowUnredactedRemoteReasoning: true,
		projectionSnapshotHook: func(int) {
			attempts++
		},
	}, testRecord(runDir))
	if err != nil {
		t.Fatalf("UploadRun() error = %v", err)
	}
	if attempts != 1 {
		t.Fatalf("projection snapshot passes = %d, want 1", attempts)
	}
}

func TestUploadRunLegacyProjectionUsesSingleLockedSnapshot(t *testing.T) {
	runDir := writeBundle(t)
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := os.Stat(filepath.Join(runDir, ".projection.lock")); err != nil {
			t.Errorf("writable legacy upload did not create projection lock: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
		AllowUnredactedRemoteReasoning: true,
		projectionSnapshotHook: func(int) {
			attempts++
		},
	}, testRecord(runDir))
	if err != nil {
		t.Fatalf("UploadRun() error = %v", err)
	}
	if attempts != 1 {
		t.Fatalf("legacy projection snapshot passes = %d, want 1", attempts)
	}
}

func TestUploadRunLegacyProjectionReadOnlyBundleUsesLockFreeSnapshot(t *testing.T) {
	runDir := writeBundle(t)
	makeBundleDirectoryReadOnly(t, runDir)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
		AllowUnredactedRemoteReasoning: true,
	}, testRecord(runDir))
	if err != nil {
		t.Fatalf("UploadRun() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(runDir, ".projection.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only legacy upload created projection lock, stat error = %v", err)
	}
}

func TestProjectionDirectoryWritableProbe(t *testing.T) {
	t.Run("writable directory", func(t *testing.T) {
		dir := t.TempDir()
		writable, err := probeProjectionDirectoryWritable(dir, securefile.CreateTemp, os.Remove, func(error) bool { return false })
		if err != nil || !writable {
			t.Fatalf("writability probe = %v, %v; want writable", writable, err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("writability probe left files behind: %v", entries)
		}
	})

	t.Run("access denied selects read-only path", func(t *testing.T) {
		accessDenied := errors.New("simulated access denied")
		probe := func(path string) (bool, error) {
			return probeProjectionDirectoryWritable(path, func(string, string) (*os.File, error) {
				return nil, accessDenied
			}, os.Remove, func(err error) bool { return errors.Is(err, accessDenied) })
		}
		allowed, err := legacyProjectionLockFreeAllowedWithProbe("unused", syscall.EACCES, probe)
		if err != nil || !allowed {
			t.Fatalf("lock-free decision = %v, %v; want allowed for read-only bundle", allowed, err)
		}
	})

	t.Run("unexpected probe error propagates", func(t *testing.T) {
		unexpected := errors.New("unexpected probe failure")
		allowed, err := legacyProjectionLockFreeAllowedWithProbe("unused", syscall.EACCES, func(string) (bool, error) {
			return false, unexpected
		})
		if allowed || !errors.Is(err, unexpected) {
			t.Fatalf("lock-free decision = %v, %v; want unexpected error", allowed, err)
		}
	})
}

func TestUploadRunLegacyProjectionLockFreeSnapshotStillDetectsTornGeneration(t *testing.T) {
	runDir := writeBundle(t)
	events := readTestFile(t, filepath.Join(runDir, actaevents.Filename))
	originalMode := makeBundleDirectoryReadOnly(t, runDir)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
		AllowUnredactedRemoteReasoning: true,
		projectionSnapshotHook: func(attempt int) {
			if err := os.Chmod(runDir, originalMode); err != nil {
				t.Fatal(err)
			}
			digestPayload := fmt.Sprintf("{\"run_id\":\"run-1\",\"attempt\":%d}\n", attempt)
			writeProjectionGeneration(t, runDir, strconv.Itoa(100+attempt), digestPayload, events)
			if err := os.Chmod(runDir, 0o555); err != nil {
				t.Fatal(err)
			}
		},
	}, testRecord(runDir))
	if err == nil || !strings.Contains(err.Error(), "torn bundle") || !strings.Contains(err.Error(), "after 3 attempts") {
		t.Fatalf("UploadRun() error = %v, want bounded torn-bundle error", err)
	}
	if requests != 0 {
		t.Fatalf("torn lock-free bundle issued %d upload requests, want none", requests)
	}
	if _, err := os.Stat(filepath.Join(runDir, ".projection.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock-free torn-generation check created projection lock, stat error = %v", err)
	}
}

func TestUploadRunProjectionLockWaitHonorsContext(t *testing.T) {
	runDir := writeBundle(t)
	lock, err := actaevents.AcquireProjectionLock(runDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = UploadRun(ctx, Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
		AllowUnredactedRemoteReasoning: true,
	}, testRecord(runDir))
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "projection lock held; upload cancelled/timed out") {
		t.Fatalf("UploadRun() error = %v, want projection-lock upload timeout", err)
	}
	if elapsed := time.Since(started); elapsed >= 2*time.Second {
		t.Fatalf("UploadRun() returned after %s, want under 2s", elapsed)
	}
	if requests != 0 {
		t.Fatalf("timed-out lock wait issued %d upload requests, want none", requests)
	}
}

func TestUploadRunWaitsForFirstProjectionCommit(t *testing.T) {
	runDir := writeBundle(t)
	oldEvents := readTestFile(t, filepath.Join(runDir, actaevents.Filename))
	newDigest := `{"run_id":"run-1","generation":"new"}` + "\n"
	newEvents := strings.Replace(oldEvents, `"duration_ms":1000`, `"duration_ms":2000`, 1)

	lock, err := actaevents.AcquireProjectionLock(runDir)
	if err != nil {
		t.Fatal(err)
	}
	lockHeld := true
	t.Cleanup(func() {
		if lockHeld {
			_ = lock.Close()
		}
	})
	writeProjectionGeneration(t, runDir, "200", newDigest, newEvents)
	if err := os.Remove(filepath.Join(runDir, "projection.json")); err != nil {
		t.Fatal(err)
	}

	var uploadedDigest string
	var uploadedDuration int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/ingest/runs/run-1/events" {
			var body eventsRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			for _, event := range body.Events {
				if event.Type == actaevents.TypeRunCompleted {
					var payload struct {
						DurationMillis int64 `json:"duration_ms"`
					}
					if err := json.Unmarshal(event.Payload, &payload); err != nil {
						t.Error(err)
					}
					uploadedDuration = payload.DurationMillis
				}
			}
		}
		if request.URL.Path == "/api/ingest/runs/run-1/artifacts" && request.URL.Query().Get("filename") == "digest.json" {
			payload, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			uploadedDigest = string(payload)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	uploadDone := make(chan error, 1)
	go func() {
		uploadDone <- UploadRun(context.Background(), Config{
			BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
			AllowUnredactedRemoteReasoning: true,
		}, testRecord(runDir))
	}()
	select {
	case err := <-uploadDone:
		t.Fatalf("UploadRun() returned while projection commit lock was held: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	writeProjectionGeneration(t, runDir, "200", newDigest, newEvents)
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	lockHeld = false
	select {
	case err := <-uploadDone:
		if err != nil {
			t.Fatalf("UploadRun() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("UploadRun() did not resume after projection commit completed")
	}
	if uploadedDigest != newDigest || uploadedDuration != 2000 {
		t.Fatalf("uploaded generation digest/duration = %q/%d, want new generation %q/2000", uploadedDigest, uploadedDuration, newDigest)
	}
}

func TestUploadRunAcceptsRedigestedV2EventsWithProducerProvenance(t *testing.T) {
	runDir := t.TempDir()
	rawName := "codex-events.jsonl"
	stderrName := "codex.stderr.log"
	writeFile(t, filepath.Join(runDir, rawName), strings.Join([]string{
		`{"type":"thread.started","thread_id":"thread-v2"}`,
		`{"type":"turn.started"}`,
		`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`,
		"",
	}, "\n"))
	writeFile(t, filepath.Join(runDir, stderrName), "")

	exitCode := 0
	started := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	originalProducer := runrecord.Producer{Name: "acta", Version: "v2-original", Commit: "original-commit"}
	record := &runrecord.Record{
		SchemaVersion:      2,
		Producer:           originalProducer,
		ID:                 "run-v2-redigested",
		Agent:              "codex",
		AgentVersion:       "0.147.0",
		CWD:                runDir,
		RunDir:             runDir,
		Command:            []string{"codex", "exec"},
		StartedAt:          started,
		CompletedAt:        started.Add(time.Second),
		DurationMillis:     1000,
		ExitCode:           &exitCode,
		OK:                 true,
		TerminationReason:  "completed",
		RawStdoutPath:      filepath.Join(runDir, rawName),
		RawStderrPath:      filepath.Join(runDir, stderrName),
		RawStdoutArtifact:  rawName,
		RawStderrArtifact:  stderrName,
		PromptSource:       "test",
		OTLPStatus:         "not_configured",
		ProcessContainment: "direct_process",
		AgentConfigMode:    "ambient_ephemeral",
	}
	recordPayload, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(runDir, "run.json"), string(recordPayload)+"\n")

	d, err := digest.FromRunDir(runDir, "")
	if err != nil {
		t.Fatalf("re-digest v2 bundle: %v", err)
	}
	regenerator := runrecord.CurrentProducer()
	if d.Producer != regenerator || d.Producer == originalProducer {
		t.Fatalf("digest producer = %+v, regenerating producer = %+v, original producer = %+v", d.Producer, regenerator, originalProducer)
	}
	if err := actaevents.WriteProjectionForRunDir(runDir, d); err != nil {
		t.Fatalf("write regenerated projection: %v", err)
	}

	var localEvents []actaevents.Event
	if _, err := scanEvents(runDir, record.ID, func(event actaevents.Event) error {
		localEvents = append(localEvents, event)
		return nil
	}); err != nil {
		t.Fatalf("validate regenerated events: %v", err)
	}
	assertEventProducerProvenance(t, localEvents, originalProducer, regenerator)

	var uploadedEvents []actaevents.Event
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/ingest/runs/"+record.ID+"/events" {
			var body eventsRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			uploadedEvents = append(uploadedEvents, body.Events...)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
	}, record); err != nil {
		t.Fatalf("upload re-digested v2 bundle: %v", err)
	}
	assertEventProducerProvenance(t, uploadedEvents, originalProducer, regenerator)
}

func assertEventProducerProvenance(t *testing.T, events []actaevents.Event, original, regenerator runrecord.Producer) {
	t.Helper()
	if len(events) == 0 {
		t.Fatal("event stream is empty")
	}
	for _, event := range events {
		if event.SchemaVersion != actaevents.SchemaVersion {
			t.Fatalf("event sequence %d schema_version = %d, want %d", event.Sequence, event.SchemaVersion, actaevents.SchemaVersion)
		}
		if event.Producer != original {
			t.Fatalf("event sequence %d producer = %+v, want original %+v", event.Sequence, event.Producer, original)
		}
		if event.RegeneratedBy == nil || *event.RegeneratedBy != regenerator {
			t.Fatalf("event sequence %d regenerated_by = %+v, want %+v", event.Sequence, event.RegeneratedBy, regenerator)
		}
	}
}

func TestUploadRunLegacyRecordUsesMetadataOrExplicitSchemaUpgrade(t *testing.T) {
	legacyBody := readTestFile(t, filepath.Join("..", "..", "schemas", "examples", "run-record.v2.json"))
	const secret = "legacy-run-record-reasoning-6204"
	legacyWithReasoning := strings.TrimSuffix(strings.TrimSpace(legacyBody), "}") +
		`,"reasoning":"` + secret + `"}` + "\n"
	legacyWithPublishedBundle := strings.TrimSuffix(strings.TrimSpace(legacyBody), "}") +
		`,"published_bundle":{"artifact_id":"bundle-1","sha256":"` + strings.Repeat("a", 64) + `"}}` + "\n"

	tests := []struct {
		name                string
		body                string
		wantByteExact       bool
		wantSchema          float64
		wantReasoning       any
		wantBodyState       any
		wantPublishedBundle bool
	}{
		{
			name:          "metadata only when body needs no content redaction",
			body:          legacyBody,
			wantByteExact: true,
		},
		{
			name:          "upgrade to v3 when body content is redacted",
			body:          legacyWithReasoning,
			wantSchema:    runrecord.SchemaVersion,
			wantReasoning: reasoningRedactionMarker,
			wantBodyState: "redacted",
		},
		{
			name:                "upgrade v2 label when a v3-only field is already present",
			body:                legacyWithPublishedBundle,
			wantSchema:          runrecord.SchemaVersion,
			wantBodyState:       "redacted",
			wantPublishedBundle: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runDir := writeBundle(t)
			writeFile(t, filepath.Join(runDir, "run.json"), test.body)

			var uploadedBody string
			var uploadedState string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/api/ingest/runs/run-1/artifacts" && request.URL.Query().Get("filename") == "run.json" {
					body, err := io.ReadAll(request.Body)
					if err != nil {
						t.Error(err)
					}
					uploadedBody = string(body)
					uploadedState = request.URL.Query().Get("redaction_state")
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			if err := UploadRun(context.Background(), Config{
				BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
			}, testRecord(runDir)); err != nil {
				t.Fatal(err)
			}
			if uploadedState != "redacted" {
				t.Fatalf("run record redaction_state metadata = %q, want redacted", uploadedState)
			}
			if local := readTestFile(t, filepath.Join(runDir, "run.json")); local != test.body {
				t.Fatal("upload redaction modified the local legacy run record")
			}
			if test.wantByteExact {
				if uploadedBody != test.body {
					t.Fatalf("content-safe v2 upload body changed:\n%s", uploadedBody)
				}
				return
			}
			if strings.Contains(uploadedBody, secret) {
				t.Fatalf("rewritten legacy upload retained reasoning: %s", uploadedBody)
			}
			var uploaded map[string]any
			if err := json.Unmarshal([]byte(uploadedBody), &uploaded); err != nil {
				t.Fatal(err)
			}
			if uploaded["schema_version"] != test.wantSchema || uploaded["reasoning"] != test.wantReasoning || uploaded["reasoning_redaction_state"] != test.wantBodyState {
				t.Fatalf("rewritten legacy run record = %#v", uploaded)
			}
			if _, present := uploaded["published_bundle"]; present != test.wantPublishedBundle {
				t.Fatalf("rewritten legacy run record published_bundle presence = %v, want %v", present, test.wantPublishedBundle)
			}
		})
	}
}

func TestV2RewritePathsEmitByteIdenticalV2OrSchemaV3(t *testing.T) {
	const (
		producer = `"producer":{"name":"acta","version":"test"}`
		started  = `{"schema_version":2,` + producer + `,"run_id":"run-1","sequence":1,"timestamp":"2026-07-06T12:00:00Z","source":"acta","type":"run.started","payload":{"agent":"codex","cwd":"/workspace","run_dir":"/workspace/.acta/runs/run-1"}}`
		terminal = `"payload":{"status":"ok","ok":true,"timeout":false,"duration_ms":1000}`
	)
	reasoningStream := strings.Join([]string{
		started,
		`{"schema_version":2,` + producer + `,"run_id":"run-1","sequence":2,"timestamp":"2026-07-06T12:00:00.5Z","source":"acta","type":"agent.reasoning","payload":{"kind":"reasoning","text":"private"}}`,
		`{"schema_version":2,` + producer + `,"run_id":"run-1","sequence":3,"timestamp":"2026-07-06T12:00:01Z","source":"acta","type":"run.completed",` + terminal + `}`,
		"",
	}, "\n")
	withheldStream := strings.Join([]string{
		started,
		`{"schema_version":2,` + producer + `,"run_id":"run-1","sequence":2,"timestamp":"2026-07-06T12:00:01Z","source":"acta","type":"run.completed",` + terminal + `,"artifact_refs":[{"kind":"raw_stderr","path":"agent.stderr.log"}]}`,
		"",
	}, "\n")

	tests := []struct {
		name            string
		input           string
		requiresRewrite bool
		rewrite         func(*os.File) error
	}{
		{
			name:  "content-safe run record stays byte-identical",
			input: `{"schema_version":2,"id":"run-1"}` + "\n",
			rewrite: func(file *os.File) error {
				return redactRunRecordSnapshot(context.Background(), file)
			},
		},
		{
			name:            "run record reasoning redaction",
			input:           `{"schema_version":2,"id":"run-1","reasoning":"private"}` + "\n",
			requiresRewrite: true,
			rewrite: func(file *os.File) error {
				return redactRunRecordSnapshot(context.Background(), file)
			},
		},
		{
			name:            "legacy digest reasoning redaction",
			input:           `{"schema_version":2,"run_id":"run-1","timeline":[{"kind":"reasoning","text":"private"}]}` + "\n",
			requiresRewrite: true,
			rewrite: func(file *os.File) error {
				return redactDigestSnapshot(context.Background(), file)
			},
		},
		{
			name:            "remote event reasoning redaction",
			input:           reasoningStream,
			requiresRewrite: true,
			rewrite: func(file *os.File) error {
				return redactActaEventSnapshot(context.Background(), file, DefaultMaxRedactionLineBytes)
			},
		},
		{
			name:            "remote withheld reference annotation",
			input:           withheldStream,
			requiresRewrite: true,
			rewrite: func(file *os.File) error {
				_, err := annotateWithheldArtifactRefsContext(context.Background(), file, "run-1", []artifactUpload{{
					Kind: "raw_stderr", Filename: "agent.stderr.log", RedactionState: "unverified", Withheld: true,
				}})
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file := writeSnapshotFile(t, test.input)
			if err := test.rewrite(file); err != nil {
				t.Fatal(err)
			}
			assertV2RewriteOutput(t, test.input, readOpenFile(t, file), test.requiresRewrite)
		})
	}
}

func TestSchemaStampingUsesV3OnlyFieldRegistry(t *testing.T) {
	tests := []struct {
		name         string
		documentType schemaversion.DocumentType
		document     map[string]any
	}{
		{name: "run record", documentType: schemaversion.RunRecord, document: map[string]any{
			"schema_version": 2, "reasoning_redaction_state": "redacted",
		}},
		{name: "digest", documentType: schemaversion.Digest, document: map[string]any{
			"schema_version": 2, "timeline": []any{map[string]any{"kind": "reasoning", "redacted": true}},
		}},
		{name: "event", documentType: schemaversion.Event, document: map[string]any{
			"schema_version": 2, "payload": map[string]any{"reasoning_redaction_state": "redacted"},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stamped, err := stampRewrittenDocumentSchemaVersion(test.documentType, test.document, false)
			if err != nil {
				t.Fatal(err)
			}
			if !stamped || test.document["schema_version"] != runrecord.SchemaVersion {
				t.Fatalf("stamped/schema_version = %v/%v, want true/%d", stamped, test.document["schema_version"], runrecord.SchemaVersion)
			}
		})
	}
}

func assertV2RewriteOutput(t *testing.T, original, emitted string, requiresRewrite bool) {
	t.Helper()
	if emitted == original {
		if requiresRewrite {
			t.Fatal("fixture requiring rewrite was emitted unchanged")
		}
		return
	}
	if !requiresRewrite {
		t.Fatalf("content-safe fixture changed unexpectedly:\n%s", emitted)
	}
	for lineNumber, line := range strings.Split(strings.TrimSpace(emitted), "\n") {
		var document map[string]any
		if err := json.Unmarshal([]byte(line), &document); err != nil {
			t.Fatalf("decode emitted document %d: %v", lineNumber+1, err)
		}
		if document["schema_version"] != float64(3) {
			t.Fatalf("rewritten document %d retained schema_version %#v:\n%s", lineNumber+1, document["schema_version"], emitted)
		}
	}
}

func TestUploadRunPreservesPlainTextStderr(t *testing.T) {
	const original = "warning: retrying provider request\n"
	if uploaded := uploadBundleStderr(t, original); uploaded != original {
		t.Fatalf("uploaded stderr = %q, want byte-identical %q", uploaded, original)
	}
}

func TestUploadRunWithholdsAmbiguousOpaqueStderrByDefault(t *testing.T) {
	const secret = "pretty-printed-private-thinking-7041"
	runDir := writeBundle(t)
	const stderrName = "agent.stderr.log"
	writeFile(t, filepath.Join(runDir, stderrName), "provider diagnostic\n"+strings.Join([]string{
		"{",
		`  "type": "thinking",`,
		`  "thinking": "` + secret + `"`,
		"}",
		"",
	}, "\n"))
	addArtifactRef(t, runDir, `{"kind":"raw_stderr","path":"`+stderrName+`"}`)
	eventFile, eventTempPath, err := snapshotEventStreamLimit(context.Background(), runDir, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(eventTempPath)
	refs, err := terminalArtifactRefsFromFile(context.Background(), eventFile, testRecord(runDir))
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := buildArtifactsContext(context.Background(), runDir, refs, eventFile, eventTempPath, nil, 0, true, DefaultMaxRedactionLineBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer closeArtifacts(artifacts)
	foundUnverified := false
	for _, artifact := range artifacts {
		if artifact.Filename == stderrName {
			foundUnverified = artifact.Withheld && artifact.RedactionState == "unverified"
		}
	}
	if !foundUnverified {
		t.Fatalf("ambiguous opaque stderr was not classified as withheld/unverified: %#v", artifacts)
	}

	uploaded := map[string]bool{}
	var remoteEvents []actaevents.Event
	var eventArtifactSchemaVersion string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/ingest/runs/run-1/events":
			var body eventsRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			remoteEvents = append(remoteEvents, body.Events...)
		case "/api/ingest/runs/run-1/artifacts":
			filename := request.URL.Query().Get("filename")
			uploaded[filename] = true
			if filename == actaevents.Filename {
				eventArtifactSchemaVersion = request.URL.Query().Get("schema_version")
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
	}, testRecord(runDir)); err != nil {
		t.Fatal(err)
	}
	if uploaded[stderrName] {
		t.Fatal("ambiguous opaque stderr was uploaded by default")
	}
	if eventArtifactSchemaVersion != "3" {
		t.Fatalf("rewritten event artifact schema_version metadata = %q, want 3", eventArtifactSchemaVersion)
	}
	var terminalRefs []actaevents.ArtifactRef
	for _, event := range remoteEvents {
		if event.SchemaVersion != actaevents.SchemaVersion {
			t.Errorf("rewritten remote event sequence %d schema_version = %d, want %d", event.Sequence, event.SchemaVersion, actaevents.SchemaVersion)
		}
		if event.Type == actaevents.TypeRunCompleted {
			terminalRefs = event.ArtifactRefs
		}
	}
	if len(terminalRefs) == 0 {
		t.Fatal("uploaded replay stream has no terminal artifact manifest")
	}
	foundWithheld := false
	for _, ref := range terminalRefs {
		if ref.Path == stderrName {
			foundWithheld = ref.Status == actaevents.ArtifactStatusWithheld && ref.Reason == withheldArtifactReason && ref.RedactionState == actaevents.ArtifactRedactionStateUnverified
			continue
		}
		if ref.Status == "" && !uploaded[ref.Path] {
			t.Errorf("uploaded event stream has dangling artifact reference %#v", ref)
		}
	}
	if !foundWithheld {
		t.Fatalf("remote terminal manifest did not mark ambiguous stderr withheld: %#v", terminalRefs)
	}
	var replay strings.Builder
	for _, event := range remoteEvents {
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		replay.Write(encoded)
		replay.WriteByte('\n')
	}
	replayFile := writeSnapshotFile(t, replay.String())
	if _, err := scanEventsFile(context.Background(), replayFile, "run-1", nil); err != nil {
		t.Fatalf("replay tooling rejected remote withheld-artifact manifest: %v", err)
	}

	file := writeSnapshotFile(t, "provider diagnostic\n{\n  \"thinking\": \""+secret+"\"\n}\n")
	verified, err := redactArtifactSnapshot(context.Background(), file, "raw_stderr", stderrName, DefaultMaxRedactionLineBytes)
	if err != nil {
		t.Fatal(err)
	}
	if verified {
		t.Fatal("ambiguous opaque stderr was classified as verified")
	}
}

func TestUploadRunConservativelyRedactsValidUnknownStderrJSON(t *testing.T) {
	const secret = "ambiguous private reasoning"
	uploaded := uploadBundleStderr(t, `{"metadata":{"label":"kept","reasoning":"`+secret+`"}}`+"\n")
	if strings.Contains(uploaded, secret) {
		t.Fatalf("uploaded valid unknown JSON retained reasoning: %s", uploaded)
	}
	var value map[string]any
	if err := json.Unmarshal([]byte(uploaded), &value); err != nil {
		t.Fatal(err)
	}
	metadata, ok := value["metadata"].(map[string]any)
	if !ok || metadata["label"] != "kept" || metadata["reasoning"] != reasoningRedactionMarker {
		t.Fatalf("valid unknown JSON did not receive conservative redaction: %#v", value)
	}
}

func TestUploadRunDoesNotTrustBareUnsupportedKind(t *testing.T) {
	runDir := writeBundle(t)
	const stderrName = "agent.stderr.log"
	writeFile(t, filepath.Join(runDir, stderrName), `{"kind":"unsupported","details":"diagnostic"}`+"\n")
	addArtifactRef(t, runDir, `{"kind":"raw_stderr","path":"`+stderrName+`"}`)

	uploaded := map[string]bool{}
	var remoteEvents []actaevents.Event
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/ingest/runs/run-1/events":
			var body eventsRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			remoteEvents = append(remoteEvents, body.Events...)
		case "/api/ingest/runs/run-1/artifacts":
			uploaded[request.URL.Query().Get("filename")] = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
	}, testRecord(runDir)); err != nil {
		t.Fatalf("UploadRun() rejected an unverifiable opaque JSON line: %v", err)
	}
	if !uploaded[stderrName] {
		t.Fatalf("inspectable raw provider object was withheld based on its bare kind: %#v", remoteEvents)
	}
}

func TestRedactArtifactSnapshotWithholdsTruncatedOpaqueReasoningMember(t *testing.T) {
	const original = "diagnostic: {\n\"thinking\":"
	ambiguousLines := append(strings.Split(original, "\n"), `"private reasoning"`, "type: thinking")
	for _, line := range ambiguousLines {
		if !opaqueLineHasJSONAmbiguity([]byte(line)) {
			t.Errorf("opaque line %q was not classified as ambiguous", line)
		}
	}
	file := writeSnapshotFile(t, original)
	verified, err := redactArtifactSnapshot(context.Background(), file, "raw_stderr", "agent.stderr.log", DefaultMaxRedactionLineBytes)
	if err != nil {
		t.Fatal(err)
	}
	if verified {
		t.Fatal("truncated opaque reasoning member was classified as verified")
	}
	if got := readOpenFile(t, file); got != original {
		t.Fatalf("withheld opaque snapshot changed = %q, want %q", got, original)
	}
}

func TestUploadRunRedactsRemoteReasoningByDefaultForEveryAgentShape(t *testing.T) {
	const secret = "private-remote-reasoning-57291"
	tests := map[string]string{
		"codex":  `{"type":"item.completed","item":{"id":"reason-1","type":"reasoning","text":"` + secret + `"}}` + "\n",
		"claude": `{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"` + secret + `"}]}}` + "\n",
	}
	for agent, raw := range tests {
		t.Run(agent, func(t *testing.T) {
			runDir := t.TempDir()
			rawName := "codex-events.jsonl"
			if agent == "claude" {
				rawName = "claude-output.jsonl"
			}
			writeFile(t, filepath.Join(runDir, rawName), raw)
			writeFile(t, filepath.Join(runDir, "run.json"), `{"id":"run-1","reasoning_redaction_state":"retained_local"}`+"\n")
			writeFile(t, filepath.Join(runDir, "digest.json"), `{"run_id":"run-1"}`+"\n")
			writeFile(t, filepath.Join(runDir, actaevents.Filename), strings.Join([]string{
				`{"schema_version":3,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":1,"timestamp":"2026-07-06T12:00:00Z","source":"acta","type":"run.started","payload":{"agent":"` + agent + `","cwd":"/workspace","run_dir":"/workspace/.acta/runs/run-1","reasoning_redaction_state":"retained_local"}}`,
				`{"schema_version":3,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":2,"timestamp":"2026-07-06T12:00:00.5Z","source":"acta","type":"agent.reasoning","payload":{"kind":"reasoning","provider_event":"private","text":"` + secret + `"}}`,
				`{"schema_version":3,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":3,"timestamp":"2026-07-06T12:00:01Z","source":"acta","type":"run.completed","payload":{"status":"ok","ok":true,"timeout":false,"duration_ms":1000},"artifact_refs":[{"kind":"run_record","path":"run.json"},{"kind":"raw_stdout","path":"` + rawName + `"},{"kind":"digest","path":"digest.json"},{"kind":"event_stream","path":"acta-events.jsonl"}]}`,
				"",
			}, "\n"))
			record := testRecord(runDir)
			record.Agent = agent
			record.ReasoningRedactionState = "retained_local"

			var remote bytes.Buffer
			var remoteEvents []actaevents.Event
			redactionStates := map[string]string{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/api/ingest/runs/run-1/events" || request.URL.Path == "/api/ingest/runs/run-1/artifacts" {
					payload, err := io.ReadAll(request.Body)
					if err != nil {
						t.Error(err)
					}
					remote.Write(payload)
					if request.URL.Path == "/api/ingest/runs/run-1/events" {
						var body eventsRequest
						if err := json.Unmarshal(payload, &body); err != nil {
							t.Error(err)
						}
						remoteEvents = append(remoteEvents, body.Events...)
					}
				}
				if request.URL.Path == "/api/ingest/runs/run-1/artifacts" {
					redactionStates[request.URL.Query().Get("filename")] = request.URL.Query().Get("redaction_state")
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			if err := UploadRun(context.Background(), Config{
				BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
			}, record); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(remote.String(), secret) {
				t.Fatalf("remote upload leaked private reasoning: %s", remote.String())
			}
			wantStates := map[string]string{
				"run.json":          "redacted",
				rawName:             "redacted",
				"digest.json":       "redacted",
				actaevents.Filename: "redacted",
			}
			if len(redactionStates) != len(wantStates) {
				t.Fatalf("uploaded artifact states = %v, want exact set %v", redactionStates, wantStates)
			}
			for filename, want := range wantStates {
				if state, ok := redactionStates[filename]; !ok || state != want {
					t.Errorf("artifact %s redaction_state = %q (present %v), want %s", filename, state, ok, want)
				}
			}
			local, err := os.ReadFile(filepath.Join(runDir, rawName))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(local), secret) {
				t.Fatal("default remote redaction changed the local full-fidelity bundle")
			}
			assertEventProducerProvenance(t, remoteEvents, record.Producer, runrecord.CurrentProducer())
		})
	}
}

func TestUploadRunWithholdsScalarProviderRecords(t *testing.T) {
	tests := map[string]string{
		"string":  `"private reasoning"`,
		"number":  "42",
		"boolean": "true",
	}
	for name, scalar := range tests {
		t.Run(name, func(t *testing.T) {
			runDir := writeBundle(t)
			const rawName = "codex-events.jsonl"
			writeFile(t, filepath.Join(runDir, rawName), scalar+"\n")
			addArtifactRef(t, runDir, `{"kind":"raw_stdout","path":"`+rawName+`"}`)

			uploaded := map[string]bool{}
			var remoteEvents []actaevents.Event
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/api/ingest/runs/run-1/events":
					var body eventsRequest
					if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					remoteEvents = append(remoteEvents, body.Events...)
				case "/api/ingest/runs/run-1/artifacts":
					uploaded[request.URL.Query().Get("filename")] = true
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			if err := UploadRun(context.Background(), Config{
				BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
			}, testRecord(runDir)); err != nil {
				t.Fatalf("UploadRun() rejected an unverifiable provider scalar: %v", err)
			}
			if uploaded[rawName] {
				t.Fatal("provider scalar was uploaded unchanged as redacted")
			}
			for _, event := range remoteEvents {
				for _, ref := range event.ArtifactRefs {
					if ref.Path == rawName && ref.Status == actaevents.ArtifactStatusWithheld &&
						ref.Reason == withheldArtifactReason && ref.RedactionState == actaevents.ArtifactRedactionStateUnverified {
						return
					}
				}
			}
			t.Fatalf("remote manifest did not mark provider scalar withheld/unverified: %#v", remoteEvents)
		})
	}
}

func TestUploadRunRedactsReasoningKindDespiteFutureType(t *testing.T) {
	const (
		rawName = "codex-events.jsonl"
		secret  = "private-conflicting-discriminator-3291"
	)
	runDir := writeBundle(t)
	original := `{"type":"future.event","kind":"reasoning","text":"` + secret + `"}` + "\n"
	writeFile(t, filepath.Join(runDir, rawName), original)
	addArtifactRef(t, runDir, `{"kind":"raw_stdout","path":"`+rawName+`"}`)

	var remoteRaw, remoteState string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/ingest/runs/run-1/artifacts" && request.URL.Query().Get("filename") == rawName {
			payload, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			remoteRaw = string(payload)
			remoteState = request.URL.Query().Get("redaction_state")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
	}, testRecord(runDir)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(remoteRaw, secret) ||
		!strings.Contains(remoteRaw, `"type":"future.event"`) ||
		!strings.Contains(remoteRaw, `"kind":"reasoning"`) ||
		!strings.Contains(remoteRaw, `"redacted":true`) || remoteState != "redacted" {
		t.Fatalf("remote conflicting discriminator body/state = %q / %q", remoteRaw, remoteState)
	}
	if local := readTestFile(t, filepath.Join(runDir, rawName)); local != original {
		t.Fatalf("remote redaction changed local raw stream:\n got %s\nwant %s", local, original)
	}
}

func TestUploadRunDoesNotTrustBareNormalizedKind(t *testing.T) {
	const (
		rawName = "codex-events.jsonl"
		secret  = "private-remote-bare-normalized-kind-6452"
	)
	runDir := writeBundle(t)
	original := `{"kind":"tool_call","input":{"thinking":"` + secret + `"}}` + "\n"
	writeFile(t, filepath.Join(runDir, rawName), original)
	addArtifactRef(t, runDir, `{"kind":"raw_stdout","path":"`+rawName+`"}`)

	var remoteRaw, remoteState string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/ingest/runs/run-1/artifacts" && request.URL.Query().Get("filename") == rawName {
			payload, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			remoteRaw = string(payload)
			remoteState = request.URL.Query().Get("redaction_state")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
	}, testRecord(runDir)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(remoteRaw, secret) ||
		!strings.Contains(remoteRaw, `"kind":"tool_call"`) ||
		!strings.Contains(remoteRaw, `"thinking":"[REDACTED]"`) || remoteState != "redacted" {
		t.Fatalf("remote bare normalized-kind body/state = %q / %q", remoteRaw, remoteState)
	}
	if local := readTestFile(t, filepath.Join(runDir, rawName)); local != original {
		t.Fatalf("remote redaction changed local raw stream:\n got %s\nwant %s", local, original)
	}
}

func TestUploadRunRemoteSnapshotTraversesProviderShapedToolResult(t *testing.T) {
	const (
		rawName     = "codex-events.jsonl"
		fixtureText = "visible-provider-shaped-tool-fixture-9241"
		secret      = "private-top-level-reasoning-7148"
	)
	runDir := writeBundle(t)
	original := strings.Join([]string{
		`{"type":"item.completed","item":{"id":"mcp-1","type":"mcp_tool_call","result":{"type":"item.completed","item":{"type":"reasoning","text":"` + fixtureText + `"}}}}`,
		`{"type":"item.completed","item":{"id":"reason-1","type":"reasoning","text":"` + secret + `"}}`,
		"",
	}, "\n")
	writeFile(t, filepath.Join(runDir, rawName), original)
	addArtifactRef(t, runDir, `{"kind":"raw_stdout","path":"`+rawName+`"}`)

	var remoteRaw string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/ingest/runs/run-1/artifacts" && request.URL.Query().Get("filename") == rawName {
			payload, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			remoteRaw = string(payload)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	record := testRecord(runDir)
	record.ReasoningRedactionState = "retained_local"
	if err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
	}, record); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(remoteRaw, fixtureText) || strings.Contains(remoteRaw, secret) ||
		strings.Count(remoteRaw, `"redacted":true`) != 2 {
		t.Fatalf("remote snapshot did not traverse all raw provider data: %s", remoteRaw)
	}
	if local := readTestFile(t, filepath.Join(runDir, rawName)); local != original {
		t.Fatal("default remote redaction changed the local raw stream")
	}
}

func TestUploadRunRemoteRawReasoningRedigestsWithOriginalMetadata(t *testing.T) {
	reasoningText := strings.Repeat("ø", digest.MaxEventTextBytes/2+17)
	wantChars := utf8.RuneCountInString(reasoningText)
	runDir := writeBundle(t)
	const (
		rawName    = "codex-events.jsonl"
		stderrName = "codex.stderr.log"
	)
	writeFile(t, filepath.Join(runDir, rawName), strings.Join([]string{
		`{"type":"thread.started","thread_id":"thread-1"}`,
		`{"type":"turn.started"}`,
		`{"type":"item.completed","item":{"id":"reason-1","type":"reasoning","text":"` + reasoningText + `"}}`,
		`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`,
		"",
	}, "\n"))
	writeFile(t, filepath.Join(runDir, stderrName), "")
	addArtifactRef(t, runDir, `{"kind":"raw_stdout","path":"`+rawName+`"}`)

	record := testRecord(runDir)
	record.AgentVersion = "test"
	record.CWD = runDir
	record.Command = []string{"codex", "exec"}
	record.RawStdoutPath = filepath.Join(runDir, rawName)
	record.RawStderrPath = filepath.Join(runDir, stderrName)
	record.RawStdoutArtifact = rawName
	record.RawStderrArtifact = stderrName
	record.OTLPStatus = "not_configured"
	record.ProcessContainment = "direct_process"
	record.AgentConfigMode = "ambient_ephemeral"
	record.ReasoningRedactionState = "retained_local"
	writeRecord := func(dir string) {
		t.Helper()
		record.RunDir = dir
		record.RawStdoutPath = filepath.Join(dir, rawName)
		record.RawStderrPath = filepath.Join(dir, stderrName)
		payload, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, "run.json"), string(payload)+"\n")
	}
	writeRecord(runDir)

	var remoteRaw []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/ingest/runs/run-1/artifacts" && request.URL.Query().Get("filename") == rawName {
			payload, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			remoteRaw = payload
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	uploadRecord := testRecord(runDir)
	uploadRecord.ReasoningRedactionState = "retained_local"
	if err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
	}, uploadRecord); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(remoteRaw, []byte(reasoningText)) {
		t.Fatal("remote raw snapshot retained private reasoning")
	}
	var providerEvent struct {
		Item *struct {
			TextChars     int  `json:"text_chars"`
			TextTruncated bool `json:"text_truncated"`
			Redacted      bool `json:"redacted"`
		} `json:"item"`
	}
	for _, line := range bytes.Split(remoteRaw, []byte("\n")) {
		var candidate struct {
			Item *struct {
				TextChars     int  `json:"text_chars"`
				TextTruncated bool `json:"text_truncated"`
				Redacted      bool `json:"redacted"`
			} `json:"item"`
		}
		if len(line) == 0 {
			continue
		}
		if err := json.Unmarshal(line, &candidate); err != nil {
			t.Fatal(err)
		}
		if candidate.Item != nil {
			providerEvent.Item = candidate.Item
			break
		}
	}
	if providerEvent.Item == nil || !providerEvent.Item.Redacted || providerEvent.Item.TextChars != wantChars || !providerEvent.Item.TextTruncated {
		t.Fatalf("remote reasoning metadata = %+v, want redacted chars=%d truncated=true", providerEvent.Item, wantChars)
	}

	remoteDir := t.TempDir()
	writeFile(t, filepath.Join(remoteDir, rawName), string(remoteRaw))
	writeFile(t, filepath.Join(remoteDir, stderrName), "")
	writeRecord(remoteDir)
	redigested, err := digest.FromRunDir(remoteDir, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range redigested.Timeline {
		if event.Kind == digest.KindReasoning {
			if !event.Redacted || event.LocalReasoningText() != "" || event.TextChars != wantChars || !event.TextTruncated {
				t.Fatalf("re-digested reasoning event = %+v / %q, want redacted chars=%d truncated=true", event, event.LocalReasoningText(), wantChars)
			}
			return
		}
	}
	t.Fatalf("re-digested reasoning event missing from timeline: %+v", redigested.Timeline)
}

func TestUploadRunRedactsReasoningFromLegacyDigest(t *testing.T) {
	const secret = "legacy-digest-reasoning-48291"
	runDir := writeBundle(t)
	digestBody := `{"schema_version":2,"producer":{"name":"acta","version":"v0.1"},"run_id":"run-1","timeline":[{"kind":"reasoning","provider_event":"item.reasoning","text":"` + secret + `","raw_event_lines":[17]}],"metrics":{"tokens":{"reasoning":42}}}` + "\n"
	writeFile(t, filepath.Join(runDir, "digest.json"), digestBody)
	record := testRecord(runDir)
	record.ReasoningRedactionState = "retained_local"

	var remoteDigest string
	var remoteState string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/ingest/runs/run-1/artifacts" && request.URL.Query().Get("filename") == "digest.json" {
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			remoteDigest = string(body)
			remoteState = request.URL.Query().Get("redaction_state")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
	}, record); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(remoteDigest, secret) || !strings.Contains(remoteDigest, `"text":"`+reasoningRedactionMarker+`"`) {
		t.Fatalf("remote legacy digest retained reasoning: %s", remoteDigest)
	}
	if !strings.Contains(remoteDigest, `"kind":"reasoning"`) ||
		!strings.Contains(remoteDigest, `"raw_event_lines":[17]`) ||
		!strings.Contains(remoteDigest, `"reasoning":42`) ||
		!strings.Contains(remoteDigest, `"redacted":true`) || remoteState != "redacted" {
		t.Fatalf("remote legacy digest/state lost structural redaction: %s / %q", remoteDigest, remoteState)
	}
	var rewritten digest.Digest
	if err := json.Unmarshal([]byte(remoteDigest), &rewritten); err != nil {
		t.Fatal(err)
	}
	if rewritten.Producer != runrecord.CurrentProducer() {
		t.Fatalf("remote digest producer = %+v, want rewriting producer %+v", rewritten.Producer, runrecord.CurrentProducer())
	}
	if local := readTestFile(t, filepath.Join(runDir, "digest.json")); local != digestBody {
		t.Fatal("upload redaction modified the local legacy digest")
	}
}

func TestUploadRunRedactsManifestPinnedLegacyDigest(t *testing.T) {
	const secret = "manifest-pinned-digest-reasoning-48291"
	tests := []struct {
		name       string
		digestBody string
		wantExact  bool
	}{
		{
			name:       "reasoning is redacted",
			digestBody: `{"schema_version":2,"producer":{"name":"acta","version":"v0.1"},"run_id":"run-1","timeline":[{"kind":"reasoning","text":"` + secret + `"}]}` + "\n",
		},
		{
			name:       "content-safe digest is unchanged",
			digestBody: `{"schema_version":2,"producer":{"name":"acta","version":"v0.1"},"run_id":"run-1","timeline":[]}` + "\n",
			wantExact:  true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runDir := writeBundle(t)
			eventsBody := readTestFile(t, filepath.Join(runDir, actaevents.Filename))
			writeProjectionGeneration(t, runDir, "100", test.digestBody, eventsBody)

			var remoteDigest string
			var remoteState string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/api/ingest/runs/run-1/artifacts" && request.URL.Query().Get("filename") == "digest.json" {
					body, err := io.ReadAll(request.Body)
					if err != nil {
						t.Error(err)
					}
					remoteDigest = string(body)
					remoteState = request.URL.Query().Get("redaction_state")
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			if err := UploadRun(context.Background(), Config{
				BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
			}, testRecord(runDir)); err != nil {
				t.Fatal(err)
			}
			if remoteState != "redacted" {
				t.Fatalf("manifest-pinned digest redaction_state = %q, want redacted", remoteState)
			}
			if test.wantExact {
				if remoteDigest != test.digestBody {
					t.Fatalf("content-safe manifest-pinned digest changed:\n%s", remoteDigest)
				}
				return
			}
			if strings.Contains(remoteDigest, secret) || !strings.Contains(remoteDigest, `"text":"`+reasoningRedactionMarker+`"`) || !strings.Contains(remoteDigest, `"redacted":true`) {
				t.Fatalf("manifest-pinned digest was uploaded without structural redaction: %s", remoteDigest)
			}
		})
	}
}

func TestUploadRunRedactsJSONLDespiteMismatchedDigestKind(t *testing.T) {
	const secret = "mismatched-kind-reasoning-19571"
	runDir := writeBundle(t)
	rawName := "codex-events.jsonl"
	writeFile(t, filepath.Join(runDir, rawName), `{"type":"item.completed","item":{"id":"reason-1","type":"reasoning","text":"`+secret+`"}}`+"\n")
	eventsPath := filepath.Join(runDir, actaevents.Filename)
	events := readTestFile(t, eventsPath)
	events = strings.Replace(events, `{"kind":"event_stream","path":"acta-events.jsonl"}`, `{"kind":"digest","path":"codex-events.jsonl"},{"kind":"event_stream","path":"acta-events.jsonl"}`, 1)
	writeFile(t, eventsPath, events)
	record := testRecord(runDir)
	record.ReasoningRedactionState = "retained_local"

	var remoteRaw string
	var remoteKind string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/ingest/runs/run-1/artifacts" && request.URL.Query().Get("filename") == rawName {
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			remoteRaw = string(body)
			remoteKind = request.URL.Query().Get("kind")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
	}, record); err != nil {
		t.Fatal(err)
	}
	if remoteKind != "digest" {
		t.Fatalf("test did not exercise mismatched declared kind: %q", remoteKind)
	}
	if strings.Contains(remoteRaw, secret) || !strings.Contains(remoteRaw, `"redacted":true`) {
		t.Fatalf("mismatched kind bypassed conservative JSONL redaction: %s", remoteRaw)
	}
}

func TestUploadRunRedactsUnsupportedClaudeDetailsByDefault(t *testing.T) {
	const secret = "private-redacted-thinking-48301"
	runDir := t.TempDir()
	rawName := "claude-output.jsonl"
	writeFile(t, filepath.Join(runDir, rawName), `{"type":"assistant","message":{"content":[{"type":"redacted_thinking","data":"`+secret+`"}]}}`+"\n")
	writeFile(t, filepath.Join(runDir, "run.json"), `{"id":"run-1","reasoning_redaction_state":"retained_local"}`+"\n")
	writeFile(t, filepath.Join(runDir, "digest.json"), `{"run_id":"run-1"}`+"\n")
	writeFile(t, filepath.Join(runDir, actaevents.Filename), strings.Join([]string{
		`{"schema_version":3,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":1,"timestamp":"2026-07-06T12:00:00Z","source":"acta","type":"run.started","payload":{"agent":"claude","cwd":"/workspace","run_dir":"/workspace/.acta/runs/run-1","reasoning_redaction_state":"retained_local"}}`,
		`{"schema_version":3,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":2,"timestamp":"2026-07-06T12:00:00.5Z","source":"acta","type":"agent.event.unsupported","payload":{"kind":"unsupported","provider_event":"assistant.redacted_thinking","details":{"type":"redacted_thinking","data":"` + secret + `"},"raw_event_lines":[1]},"artifact_refs":[{"kind":"raw_stdout","path":"` + rawName + `","lines":[1]}]}`,
		`{"schema_version":3,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":3,"timestamp":"2026-07-06T12:00:01Z","source":"acta","type":"run.completed","payload":{"status":"ok","ok":true,"timeout":false,"duration_ms":1000},"artifact_refs":[{"kind":"run_record","path":"run.json"},{"kind":"raw_stdout","path":"` + rawName + `"},{"kind":"digest","path":"digest.json"},{"kind":"event_stream","path":"acta-events.jsonl"}]}`,
		"",
	}, "\n"))
	record := testRecord(runDir)
	record.Agent = "claude"
	record.ReasoningRedactionState = "retained_local"

	var remote bytes.Buffer
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/ingest/runs/run-1/events" || request.URL.Path == "/api/ingest/runs/run-1/artifacts" {
			payload, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			remote.Write(payload)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
	}, record); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(remote.String(), secret) || !strings.Contains(remote.String(), `"details":{}`) {
		t.Fatalf("remote upload retained unsupported reasoning details: %s", remote.String())
	}
	if !strings.Contains(remote.String(), `"provider_event":"assistant.redacted_thinking"`) ||
		!strings.Contains(remote.String(), `"raw_event_lines":[1]`) ||
		!strings.Contains(remote.String(), `"redacted":true`) {
		t.Fatalf("remote upload lost structural unsupported-event references: %s", remote.String())
	}
}

func TestUploadRunRedactsUnsupportedFutureMapDetailsByDefault(t *testing.T) {
	const secret = "future-event-private-thinking-23091"
	runDir := t.TempDir()
	writeFile(t, filepath.Join(runDir, "run.json"), `{"id":"run-1"}`+"\n")
	writeFile(t, filepath.Join(runDir, "digest.json"), `{"run_id":"run-1"}`+"\n")
	writeFile(t, filepath.Join(runDir, actaevents.Filename), strings.Join([]string{
		`{"schema_version":3,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":1,"timestamp":"2026-07-06T12:00:00Z","source":"acta","type":"run.started","payload":{"agent":"codex","cwd":"/workspace","run_dir":"/workspace/.acta/runs/run-1"}}`,
		`{"schema_version":3,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":2,"timestamp":"2026-07-06T12:00:00.5Z","source":"acta","type":"agent.event.unsupported","payload":{"kind":"unsupported","provider_event":"future.event","details":{"type":"future.event","thinking":"` + secret + `"},"raw_event_lines":[1]}}`,
		`{"schema_version":3,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":3,"timestamp":"2026-07-06T12:00:01Z","source":"acta","type":"run.completed","payload":{"status":"ok","ok":true,"timeout":false,"duration_ms":1000},"artifact_refs":[{"kind":"run_record","path":"run.json"},{"kind":"digest","path":"digest.json"},{"kind":"event_stream","path":"acta-events.jsonl"}]}`,
		"",
	}, "\n"))

	var remote bytes.Buffer
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/ingest/runs/run-1/events" ||
			request.URL.Path == "/api/ingest/runs/run-1/artifacts" && request.URL.Query().Get("filename") == actaevents.Filename {
			payload, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			remote.Write(payload)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
	}, testRecord(runDir)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(remote.String(), secret) || !strings.Contains(remote.String(), `"thinking":"`+reasoningRedactionMarker+`"`) {
		t.Fatalf("remote upload did not redact unsupported future map details: %s", remote.String())
	}
	if !strings.Contains(remote.String(), `"type":"future.event"`) || !strings.Contains(remote.String(), `"redacted":true`) {
		t.Fatalf("remote upload lost unsupported future event structure: %s", remote.String())
	}
}

func TestRemoteRedactionScrubsIDLessUnsupportedCodexReasoning(t *testing.T) {
	const secret = "private-idless-remote-reasoning-4826"

	t.Run("Acta event", func(t *testing.T) {
		original := []byte(`{"type":"agent.event.unsupported","payload":{"kind":"unsupported","provider_event":"item.completed","details":{"type":"item.completed","item":{"type":"reasoning","text":"` + secret + `","summary":["private"]}},"raw_event_lines":[3]}}` + "\n")
		redacted, err := redactActaReasoningEventLine(original)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(redacted, []byte(secret)) ||
			!bytes.Contains(redacted, []byte(`"text":"[REDACTED]"`)) ||
			!bytes.Contains(redacted, []byte(`"summary":[]`)) ||
			!bytes.Contains(redacted, []byte(`"raw_event_lines":[3]`)) ||
			!bytes.Contains(redacted, []byte(`"redacted":true`)) {
			t.Fatalf("unsupported Acta event was not safely redacted: %s", redacted)
		}
	})

	t.Run("standalone Claude block in details array", func(t *testing.T) {
		original := []byte(`{"type":"agent.event.unsupported","payload":{"kind":"unsupported","provider_event":"assistant.redacted_thinking","details":[{"type":"redacted_thinking","data":"` + secret + `"}],"raw_event_lines":[4]}}` + "\n")
		redacted, err := redactActaReasoningEventLine(original)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(redacted, []byte(secret)) ||
			!bytes.Contains(redacted, []byte(`"details":[{"data":"[REDACTED]","redacted":true,"type":"redacted_thinking"}]`)) ||
			!bytes.Contains(redacted, []byte(`"raw_event_lines":[4]`)) ||
			!bytes.Contains(redacted, []byte(`"redacted":true`)) {
			t.Fatalf("array-shaped unsupported details were not safely redacted: %s", redacted)
		}
	})

	t.Run("digest", func(t *testing.T) {
		file := writeSnapshotFile(t, `{"schema_version":3,"timeline":[{"kind":"unsupported","provider_event":"item.completed","details":{"type":"item.completed","item":{"type":"reasoning","text":"`+secret+`"}}}]}`+"\n")
		if err := redactDigestSnapshot(context.Background(), file); err != nil {
			t.Fatal(err)
		}
		redacted := readOpenFile(t, file)
		if strings.Contains(redacted, secret) || !strings.Contains(redacted, `"text":"[REDACTED]"`) ||
			!strings.Contains(redacted, `"redacted":true`) {
			t.Fatalf("unsupported digest event was not safely redacted: %s", redacted)
		}
		var document struct {
			Timeline []struct {
				Redacted bool `json:"redacted"`
			} `json:"timeline"`
		}
		if err := json.Unmarshal([]byte(redacted), &document); err != nil {
			t.Fatal(err)
		}
		if len(document.Timeline) != 1 || !document.Timeline[0].Redacted {
			t.Fatalf("unsupported digest timeline provenance = %#v, want redacted", document.Timeline)
		}
	})
}

func TestRemoteRedactionPreservesUnsupportedNonReasoningDetails(t *testing.T) {
	t.Run("Acta event", func(t *testing.T) {
		original := []byte(`{"type":"agent.event.unsupported","payload":{"kind":"unsupported","provider_event":"rethinking","details":{"type":"rethinking","diagnostic":"keep this payload"},"raw_event_lines":[7]}}` + "\n")
		redacted, err := redactActaReasoningEventLine(original)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(redacted, original) {
			t.Fatalf("legitimate unsupported payload changed:\n got %s\nwant %s", redacted, original)
		}
	})

	t.Run("digest", func(t *testing.T) {
		original := `{"schema_version":3,"timeline":[{"kind":"unsupported","provider_event":"rethinking","details":{"type":"rethinking","diagnostic":"keep this payload"}}]}` + "\n"
		file := writeSnapshotFile(t, original)
		if err := redactDigestSnapshot(context.Background(), file); err != nil {
			t.Fatal(err)
		}
		if redacted := readOpenFile(t, file); redacted != original {
			t.Fatalf("legitimate unsupported digest payload changed:\n got %s\nwant %s", redacted, original)
		}
	})
}

func TestUnsupportedUninspectableDetailsAreUnverified(t *testing.T) {
	tests := map[string]any{
		"scalar":       "opaque private details",
		"array scalar": []any{map[string]any{"type": "redacted_thinking", "data": "private"}, "opaque private details"},
	}
	for name, details := range tests {
		t.Run(name, func(t *testing.T) {
			event := map[string]any{
				"type": actaevents.TypeAgentEventUnsupported,
				"payload": map[string]any{
					"kind":           "unsupported",
					"provider_event": "future.provider.event",
					"details":        details,
				},
			}
			_, verified := inspectActaEventValue(event)
			if verified {
				t.Fatal("uninspectable unsupported details were treated as verified")
			}
		})
	}
}

func TestUploadRunRedactsEvenWhenRunRecordClaimsRedacted(t *testing.T) {
	const secret = "tampered-redaction-state-secret-8901"
	runDir := writeBundle(t)
	rawName := "codex-events.jsonl"
	writeFile(t, filepath.Join(runDir, rawName), `{"type":"item.completed","item":{"type":"reasoning","text":"`+secret+`"}}`+"\n")
	writeFile(t, filepath.Join(runDir, "run.json"), `{"id":"run-1","reasoning_redaction_state":"redacted"}`+"\n")
	eventsPath := filepath.Join(runDir, actaevents.Filename)
	events := readTestFile(t, eventsPath)
	events = strings.Replace(events, `{"kind":"event_stream","path":"acta-events.jsonl"}`, `{"kind":"raw_stdout","path":"codex-events.jsonl"},{"kind":"event_stream","path":"acta-events.jsonl"}`, 1)
	writeFile(t, eventsPath, events)
	record := testRecord(runDir)
	record.ReasoningRedactionState = "redacted"

	var remote bytes.Buffer
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/ingest/runs/run-1/artifacts" {
			payload, _ := io.ReadAll(request.Body)
			remote.Write(payload)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
	}, record); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(remote.String(), secret) {
		t.Fatalf("mutable redaction-state claim bypassed upload redaction: %s", remote.String())
	}
	if local := readTestFile(t, filepath.Join(runDir, rawName)); !strings.Contains(local, secret) {
		t.Fatal("upload redaction rewrote the local artifact")
	}
}

func TestRewriteJSONLSnapshotRejectsOversizedLineWithoutMutation(t *testing.T) {
	const original = `{"type":"thinking","thinking":"private"}` + "\n"
	file := writeSnapshotFile(t, original)
	err := rewriteJSONLSnapshot(context.Background(), file, 16, redactProviderReasoningLine)
	if err == nil || !strings.Contains(err.Error(), "line 1 exceeds maximum") {
		t.Fatalf("rewrite error = %v, want explicit oversized-line error", err)
	}
	if got := readOpenFile(t, file); got != original {
		t.Fatalf("oversized redaction changed snapshot = %q, want %q", got, original)
	}
}

func TestRedactArtifactSnapshotProcessesJSONLAfterLeadingBlankLines(t *testing.T) {
	const secret = "reasoning-after-blank-line-4812"
	file := writeSnapshotFile(t, "\n \t\n"+`{"type":"thinking","thinking":"`+secret+`"}`+"\n")
	verified, err := redactArtifactSnapshot(context.Background(), file, "stderr", "agent.stderr.log", DefaultMaxRedactionLineBytes)
	if err != nil {
		t.Fatal(err)
	}
	redacted := readOpenFile(t, file)
	if !verified || strings.Contains(redacted, secret) || !strings.Contains(redacted, `"redacted":true`) {
		t.Fatalf("redaction verified=%v snapshot=%q", verified, redacted)
	}
}

func TestRedactArtifactSnapshotProcessesJSONAfterManyDiagnosticLines(t *testing.T) {
	const secret = "reasoning-after-sixteen-plain-lines-8402"
	var original strings.Builder
	for i := 0; i < 32; i++ {
		fmt.Fprintf(&original, "diagnostic line %d\n", i+1)
	}
	original.WriteString(`{"type":"thinking","thinking":"` + secret + `"}` + "\n")

	file := writeSnapshotFile(t, original.String())
	verified, err := redactArtifactSnapshot(context.Background(), file, "stderr", "agent.stderr.log", DefaultMaxRedactionLineBytes)
	if err != nil {
		t.Fatal(err)
	}
	redacted := readOpenFile(t, file)
	if !verified || strings.Contains(redacted, secret) || !strings.Contains(redacted, `"thinking":"`+reasoningRedactionMarker+`"`) {
		t.Fatalf("redaction verified=%v snapshot=%q", verified, redacted)
	}
	if !strings.HasPrefix(redacted, "diagnostic line 1\n") || !strings.Contains(redacted, "diagnostic line 32\n") {
		t.Fatalf("plain diagnostic lines changed: %q", redacted)
	}
}

func TestRedactWorkspaceDiffPreservesJSONContextLineMarker(t *testing.T) {
	const secret = "private-reasoning-in-diff-context-4821"
	jsonLine := `{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"` + secret + `"}]}}`
	original := "diff --git a/event.json b/event.json\n" +
		"--- a/event.json\n" +
		"+++ b/event.json\n" +
		"@@ -1 +1 @@\n" +
		" " + jsonLine + "  \n"
	file := writeSnapshotFile(t, original)

	verified, err := redactArtifactSnapshot(context.Background(), file, "workspace_diff", "workspace.diff", DefaultMaxRedactionLineBytes)
	if err != nil {
		t.Fatal(err)
	}
	redacted := readOpenFile(t, file)
	if !verified || strings.Contains(redacted, secret) {
		t.Fatalf("workspace diff redaction verified=%v snapshot=%q", verified, redacted)
	}
	lines := strings.Split(redacted, "\n")
	if len(lines) < 6 || !strings.HasPrefix(lines[4], " {") || !strings.HasSuffix(lines[4], "  ") {
		t.Fatalf("rewritten unified-diff context line lost its exact prefix/suffix: %q", lines[4])
	}
	if strings.Join(lines[:4], "\n") != strings.Join(strings.Split(original, "\n")[:4], "\n") {
		t.Fatalf("workspace diff headers changed:\n%s", redacted)
	}
}

func TestRewriteJSONLSnapshotHonorsCancellationBetweenLines(t *testing.T) {
	const original = "{\"type\":\"first\"}\n{\"type\":\"second\"}\n"
	file := writeSnapshotFile(t, original)
	ctx, cancel := context.WithCancel(context.Background())
	transforms := 0
	err := rewriteJSONLSnapshot(ctx, file, 1024, func(line []byte) ([]byte, error) {
		transforms++
		cancel()
		return line, nil
	})
	if !errors.Is(err, context.Canceled) || transforms != 1 {
		t.Fatalf("rewrite error = %v, transforms = %d; want cancellation after one line", err, transforms)
	}
	if got := readOpenFile(t, file); got != original {
		t.Fatalf("canceled redaction changed snapshot = %q, want %q", got, original)
	}
}

func TestRewriteJSONDocumentSnapshotHonorsCancellationBetweenChunks(t *testing.T) {
	original := `{"thinking":"private","padding":"` + strings.Repeat("x", 512<<10) + `"}` + "\n"
	file := writeSnapshotFile(t, original)
	ctx := &cancelAfterChecksContext{Context: context.Background(), checksRemaining: 3}
	err := rewriteJSONDocumentSnapshot(ctx, file, int64(len(original)+1), func(context.Context, any) (bool, error) {
		t.Fatal("transform ran after cancellation during document read")
		return false, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("rewrite error = %v, want context cancellation", err)
	}
	if got := readOpenFile(t, file); got != original {
		t.Fatal("canceled JSON-document redaction changed the snapshot")
	}
}

func TestCopyContextHonorsCancellationDuringFinalSnapshotCopy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	destination := &cancelAfterWrite{cancel: cancel}
	err := copyContext(ctx, destination, bytes.NewReader(make([]byte, 3*(128<<10))))
	if !errors.Is(err, context.Canceled) || destination.writes != 1 {
		t.Fatalf("copy error = %v, writes = %d; want cancellation after one chunk", err, destination.writes)
	}
}

func TestRedactActaReasoningEventLineRedactsUnknownTypeByDefault(t *testing.T) {
	const secret = "future-private-content-1209"
	original := []byte(`{"type":"agent.future.event","payload":{"kind":"future","provider_event":"future.block","details":{"text":"` + secret + `"},"raw_event_lines":[7]}}` + "\n")
	redacted, err := redactActaReasoningEventLine(original)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(redacted), secret) || !strings.Contains(string(redacted), `"details":{}`) {
		t.Fatalf("unknown event retained free-text payload: %s", redacted)
	}
	if !strings.Contains(string(redacted), `"raw_event_lines":[7]`) || !strings.Contains(string(redacted), `"redacted":true`) {
		t.Fatalf("unknown event lost structural references: %s", redacted)
	}
}

func TestRedactActaReasoningEventLinePreservesSchemaFieldTypes(t *testing.T) {
	original := []byte(`{"schema_version":3,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":1,"timestamp":"2026-08-25T12:00:00Z","source":"acta","type":"agent.reasoning","payload":{"kind":"reasoning","text":"private","files":["a.go"],"spans":{"a.go":[{"start":1,"end":2}]},"action":42,"details":true}}` + "\n")
	redacted, err := redactActaReasoningEventLine(original)
	if err != nil {
		t.Fatal(err)
	}
	var event map[string]any
	if err := json.Unmarshal(redacted, &event); err != nil {
		t.Fatal(err)
	}
	payload, ok := event["payload"].(map[string]any)
	if !ok {
		t.Fatalf("redacted payload = %#v, want object", event["payload"])
	}
	files, filesOK := payload["files"].([]any)
	spans, spansOK := payload["spans"].(map[string]any)
	if payload["text"] != reasoningRedactionMarker || !filesOK || len(files) != 0 || !spansOK || len(spans) != 0 || payload["action"] != float64(0) || payload["details"] != false || payload["redacted"] != true {
		t.Fatalf("redacted payload did not preserve field types: %#v", payload)
	}

	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	const schemaBase = "https://github.com/Nobbettt/acta/schemas/"
	for _, name := range []string{"run-record.schema.json", "acta-event.schema.json"} {
		schemaPayload, err := os.ReadFile(filepath.Join("..", "..", "schemas", name))
		if err != nil {
			t.Fatal(err)
		}
		var document any
		if err := json.Unmarshal(schemaPayload, &document); err != nil {
			t.Fatal(err)
		}
		if err := compiler.AddResource(schemaBase+name, document); err != nil {
			t.Fatal(err)
		}
	}
	schema, err := compiler.Compile(schemaBase + "acta-event.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(event); err != nil {
		t.Fatalf("redacted agent.reasoning event failed schema validation: %v\nJSON: %s", err, redacted)
	}
}

func TestRedactProviderReasoningLinePreservesLargeInteger(t *testing.T) {
	const secret = "private-thinking-with-large-tool-input"
	original := []byte(`{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"` + secret + `"},{"type":"tool_use","input":{"boundary":9007199254740993}}]}}` + "\n")
	redacted, err := redactProviderReasoningLine(original)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(redacted), secret) {
		t.Fatalf("reasoning was not redacted: %s", redacted)
	}
	if !strings.Contains(string(redacted), `"boundary":9007199254740993`) {
		t.Fatalf("large integer changed during redaction: %s", redacted)
	}
	if !strings.Contains(string(redacted), `"thinking":"`+reasoningRedactionMarker+`"`) ||
		!strings.Contains(string(redacted), `"redacted":true`) {
		t.Fatalf("provider thinking block was not fully masked in place: %s", redacted)
	}
}

func TestRedactProviderReasoningLineRejectsDuplicateReasoningKey(t *testing.T) {
	original := []byte(`{"reasoning":"private","reasoning":0}` + "\n")
	redacted, err := redactProviderReasoningLine(original)
	if err == nil || !strings.Contains(err.Error(), `duplicate JSON object key "reasoning"`) {
		t.Fatalf("duplicate-key redaction = %q, error = %v", redacted, err)
	}
}

func TestRedactProviderReasoningMasksMalformedStructuralMetadata(t *testing.T) {
	const secret = "private-content-in-text-chars"
	original := []byte(`{"type":"item.completed","item":{"type":"reasoning","text":"[REDACTED]","text_chars":"` + secret + `","text_truncated":false,"redacted":true}}` + "\n")
	redacted, err := redactProviderReasoningLine(original)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(redacted, []byte(secret)) || !bytes.Contains(redacted, []byte(`"text_chars":"`+reasoningRedactionMarker+`"`)) {
		t.Fatalf("malformed structural metadata was not masked: %s", redacted)
	}
}

func TestRedactProviderReasoningUsesEnvelopeProvenance(t *testing.T) {
	tests := map[string]struct {
		original   []byte
		acta       bool
		wantChange bool
	}{
		"provider tool payload": {
			original:   []byte(`{"type":"item.completed","item":{"type":"mcp_tool_call","arguments":{"reasoning":"input explanation"},"result":{"thinking":"output explanation"}}}` + "\n"),
			wantChange: true,
		},
		"Claude structured output": {
			original:   []byte(`{"type":"result","structured_output":{"reasoning":"final explanation"}}` + "\n"),
			wantChange: true,
		},
		"Acta structured output": {
			original: []byte(`{"type":"agent.output.structured","payload":{"kind":"structured_output","details":{"reasoning":"final explanation"}}}` + "\n"),
			acta:     true,
		},
		"Acta normalized tool call": {
			original: []byte(`{"schema_version":3,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":2,"timestamp":"2026-07-06T12:00:00.5Z","source":"acta","type":"tool.call.completed","payload":{"kind":"tool_call","input":{"thinking":"secret"}}}` + "\n"),
			acta:     true,
		},
		"non-provider discriminator": {
			original: []byte(`{"type":"reasoning_result","text":"visible user data"}` + "\n"),
		},
		"substring-only discriminator": {
			original: []byte(`{"kind":"rethinking","text":"visible user data"}` + "\n"),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var (
				redacted []byte
				err      error
			)
			if test.acta {
				redacted, err = redactActaReasoningEventLine(test.original)
			} else {
				redacted, err = redactProviderReasoningLine(test.original)
			}
			if err != nil {
				t.Fatal(err)
			}
			changed := !bytes.Equal(redacted, test.original)
			if changed != test.wantChange {
				t.Fatalf("payload changed = %v, want %v:\n got %s\nwant %s", changed, test.wantChange, redacted, test.original)
			}
			if test.wantChange && (!bytes.Contains(redacted, []byte(reasoningRedactionMarker)) || bytes.Contains(redacted, []byte("explanation"))) {
				t.Fatalf("raw provider payload was not conservatively redacted: %s", redacted)
			}
		})
	}
}

func TestRedactNormalizedTerminalStructuredOutput(t *testing.T) {
	const (
		structured = `{"answer":"done","reasoning_redaction_state":"keep","thinking":"final explanation"}`
		secret     = "private-terminal-model-reasoning"
	)
	for _, typ := range []string{actaevents.TypeRunCompleted, actaevents.TypeRunFailed} {
		t.Run(typ, func(t *testing.T) {
			original := []byte(`{"type":"` + typ + `","payload":{"structured_output":` + structured + `,"model_usage":{"thinking":"` + secret + `"}}}` + "\n")
			redacted, err := redactActaReasoningEventLine(original)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(redacted, []byte(secret)) || !bytes.Contains(redacted, []byte(`"thinking":"[REDACTED]"`)) {
				t.Fatalf("reasoning outside structured_output was not redacted: %s", redacted)
			}
			var event struct {
				Payload struct {
					StructuredOutput json.RawMessage `json:"structured_output"`
				} `json:"payload"`
			}
			if err := json.Unmarshal(redacted, &event); err != nil {
				t.Fatal(err)
			}
			if string(event.Payload.StructuredOutput) != structured {
				t.Fatalf("structured_output = %s, want %s", event.Payload.StructuredOutput, structured)
			}
		})
	}
}

func TestRedactDigestPreservesStructuredOutputConsistently(t *testing.T) {
	const (
		structured = `{"answer":"done","reasoning_redaction_state":"keep","thinking":"final explanation"}`
		secret     = "private-digest-model-reasoning"
	)
	file := writeSnapshotFile(t, `{"schema_version":3,"structured_output":`+structured+`,"timeline":[{"kind":"structured_output","provider_event":"result.structured_output","details":`+structured+`}],"model_usage":{"thinking":"`+secret+`"}}`+"\n")
	if err := redactDigestSnapshot(context.Background(), file); err != nil {
		t.Fatal(err)
	}
	redacted := readOpenFile(t, file)
	if strings.Contains(redacted, secret) || !strings.Contains(redacted, `"thinking":"[REDACTED]"`) {
		t.Fatalf("reasoning outside digest structured_output was not redacted: %s", redacted)
	}
	var document struct {
		StructuredOutput json.RawMessage `json:"structured_output"`
		Timeline         []struct {
			Details json.RawMessage `json:"details"`
		} `json:"timeline"`
	}
	if err := json.Unmarshal([]byte(redacted), &document); err != nil {
		t.Fatal(err)
	}
	if string(document.StructuredOutput) != structured || len(document.Timeline) != 1 ||
		!bytes.Equal(document.StructuredOutput, document.Timeline[0].Details) {
		t.Fatalf("digest structured outputs diverged: top=%s timeline=%v", document.StructuredOutput, document.Timeline)
	}
}

func TestUploadRunPreservesNormalizedStructuredOutput(t *testing.T) {
	const (
		structured = `{"answer":"done","reasoning_redaction_state":"keep","thinking":"final explanation"}`
		secret     = "private-upload-model-reasoning"
	)
	runDir := t.TempDir()
	writeFile(t, filepath.Join(runDir, "run.json"), `{"id":"run-1"}`+"\n")
	writeFile(t, filepath.Join(runDir, "digest.json"), `{"schema_version":3,"producer":{"name":"acta","version":"test"},"run_id":"run-1","agent":"codex","status":"ok","timeline":[{"kind":"structured_output","provider_event":"result.structured_output","details":`+structured+`}],"metrics":{"duration_ms":1000,"commands":0,"edits":0,"tokens":{"input":0,"output":0,"total":0}},"files":[],"structured_output":`+structured+`,"model_usage":{"thinking":"`+secret+`"},"has_workspace_diff":false}`+"\n")
	writeFile(t, filepath.Join(runDir, actaevents.Filename), strings.Join([]string{
		`{"schema_version":3,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":1,"timestamp":"2026-07-06T12:00:00Z","source":"acta","type":"run.started","payload":{"agent":"codex","cwd":"/workspace","run_dir":"/workspace/.acta/runs/run-1"}}`,
		`{"schema_version":3,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":2,"timestamp":"2026-07-06T12:00:00.5Z","source":"acta","type":"agent.output.structured","payload":{"kind":"structured_output","provider_event":"result.structured_output","details":` + structured + `}}`,
		`{"schema_version":3,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":3,"timestamp":"2026-07-06T12:00:01Z","source":"acta","type":"run.completed","payload":{"status":"ok","ok":true,"timeout":false,"duration_ms":1000,"structured_output":` + structured + `,"model_usage":{"thinking":"` + secret + `"}},"artifact_refs":[{"kind":"run_record","path":"run.json"},{"kind":"digest","path":"digest.json"},{"kind":"event_stream","path":"acta-events.jsonl"}]}`,
		"",
	}, "\n"))

	uploaded := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/ingest/runs/run-1/artifacts" {
			payload, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			uploaded[request.URL.Query().Get("filename")] = string(payload)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
	}, testRecord(runDir)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"digest.json", actaevents.Filename} {
		body := uploaded[name]
		if strings.Contains(body, secret) || !strings.Contains(body, structured) || !strings.Contains(body, `"thinking":"[REDACTED]"`) {
			t.Fatalf("uploaded %s did not preserve structured output and redact outside reasoning: %s", name, body)
		}
	}
}

func TestRedactProviderReasoningMasksAmbiguousFieldWithoutDeletingKey(t *testing.T) {
	original := []byte(`{"metadata":{"reasoning":"ambiguous private text","label":"kept"}}` + "\n")
	redacted, err := redactProviderReasoningLine(original)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(redacted, &value); err != nil {
		t.Fatal(err)
	}
	metadata, ok := value["metadata"].(map[string]any)
	if !ok || metadata["reasoning"] != reasoningRedactionMarker || metadata["label"] != "kept" {
		t.Fatalf("ambiguous reasoning field was not masked in place: %#v", value)
	}
}

func TestUploadRunAllowsExplicitUnredactedRemoteReasoning(t *testing.T) {
	const secret = "explicit-private-reasoning-9012"
	runDir := writeBundle(t)
	writeFile(t, filepath.Join(runDir, "codex-events.jsonl"), `{"type":"item.completed","item":{"type":"reasoning","text":"`+secret+`"}}`+"\n")
	eventsPath := filepath.Join(runDir, actaevents.Filename)
	eventBytes, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatal(err)
	}
	events := strings.Replace(string(eventBytes), `{"kind":"event_stream","path":"acta-events.jsonl"}`, `{"kind":"raw_stdout","path":"codex-events.jsonl"},{"kind":"event_stream","path":"acta-events.jsonl"}`, 1)
	writeFile(t, eventsPath, events)
	record := testRecord(runDir)
	record.ReasoningRedactionState = "retained_local"
	var remote bytes.Buffer
	var rawState string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/ingest/runs/run-1/artifacts" {
			body, _ := io.ReadAll(request.Body)
			remote.Write(body)
			if request.URL.Query().Get("filename") == "codex-events.jsonl" {
				rawState = request.URL.Query().Get("redaction_state")
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
		AllowUnredactedRemoteReasoning: true,
	}, record); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(remote.String(), secret) || rawState != "unredacted" {
		t.Fatalf("explicit upload remote=%q redaction_state=%q", remote.String(), rawState)
	}
}

func TestUploadRunDerivesUnredactedLabelsFromArtifactContent(t *testing.T) {
	const secret = "reasoning-inside-opaque-log-6492"
	runDir := writeBundle(t)
	const logName = "provider.stderr.log"
	const cleanLogName = "provider-clean.stderr.log"
	writeFile(t, filepath.Join(runDir, logName), "provider diagnostic\n"+`{"type":"thinking","thinking":"`+secret+`"}`+"\n")
	writeFile(t, filepath.Join(runDir, cleanLogName), "plain provider diagnostic\n")
	addArtifactRef(t, runDir, `{"kind":"raw_stderr","path":"`+logName+`"}`)
	addArtifactRef(t, runDir, `{"kind":"raw_stderr","path":"`+cleanLogName+`"}`)

	var remoteLog string
	remoteStates := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/ingest/runs/run-1/artifacts" {
			filename := request.URL.Query().Get("filename")
			remoteStates[filename] = request.URL.Query().Get("redaction_state")
			if filename == logName {
				body, err := io.ReadAll(request.Body)
				if err != nil {
					t.Error(err)
				}
				remoteLog = string(body)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
		AllowUnredactedRemoteReasoning: true,
	}, testRecord(runDir)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(remoteLog, secret) || remoteStates[logName] != "unredacted" {
		t.Fatalf("reasoning log body/states = %q / %v, want retained content labeled unredacted", remoteLog, remoteStates)
	}
	if remoteStates[cleanLogName] != "not_required" {
		t.Fatalf("clean log state = %q, want not_required; all states: %v", remoteStates[cleanLogName], remoteStates)
	}
}

func TestUploadRunExplicitlyUploadsAmbiguousOpaqueStderrAsUnredacted(t *testing.T) {
	const secret = "explicit-pretty-private-thinking-8093"
	runDir := writeBundle(t)
	const stderrName = "provider.stderr.log"
	writeFile(t, filepath.Join(runDir, stderrName), "diagnostic\n{\n  \"thinking\": \""+secret+"\"\n}\n")
	addArtifactRef(t, runDir, `{"kind":"raw_stderr","path":"`+stderrName+`"}`)

	var remoteStderr, remoteState string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/ingest/runs/run-1/artifacts" && request.URL.Query().Get("filename") == stderrName {
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			remoteStderr = string(body)
			remoteState = request.URL.Query().Get("redaction_state")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
		AllowUnredactedRemoteReasoning: true,
	}, testRecord(runDir)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(remoteStderr, secret) || remoteState != "unredacted" {
		t.Fatalf("ambiguous stderr body/state = %q / %q, want explicit unredacted upload", remoteStderr, remoteState)
	}
}

func TestUploadRunRefusesPartialLocalReasoningRedactionByDefault(t *testing.T) {
	runDir := writeBundle(t)
	record := testRecord(runDir)
	record.ReasoningRedactionState = "partial"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
	}, record)
	if err == nil || !strings.Contains(err.Error(), "remote upload refused") || requests != 0 {
		t.Fatalf("partial-redaction upload error=%v requests=%d", err, requests)
	}
}

func TestUploadRunRejectsPartialScope(t *testing.T) {
	runDir := writeBundle(t)
	record := testRecord(runDir)

	err := UploadRun(context.Background(), Config{
		BackendURL:     "http://127.0.0.1",
		ReportToken:    "secret-token",
		OrganizationID: "11111111-1111-1111-1111-111111111111",
	}, record)
	if err == nil || !strings.Contains(err.Error(), "must be provided together") {
		t.Fatalf("UploadRun() error = %v, want partial scope error", err)
	}
}

func TestUploadRunRetriesTransientFailures(t *testing.T) {
	runDir := writeBundle(t)
	record := testRecord(runDir)

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := UploadRun(context.Background(), Config{
		BackendURL:  server.URL,
		ReportToken: "secret-token",
		HTTPClient:  server.Client(),
		RetryDelays: []time.Duration{0},
	}, record); err != nil {
		t.Fatalf("UploadRun() error = %v", err)
	}
	if attempts != 7 {
		t.Fatalf("attempts = %d, want 7 total posts with one retried create-run request", attempts)
	}
}

func TestUploadRunMarksPartialUploadFailed(t *testing.T) {
	runDir := writeBundle(t)
	record := testRecord(runDir)

	var markedFailed bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/ingest/runs":
			w.WriteHeader(http.StatusOK)
		case "/api/ingest/runs/run-1/events":
			w.WriteHeader(http.StatusBadGateway)
		case "/api/ingest/runs/run-1/complete":
			var req completeRunRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode complete request: %v", err)
			}
			markedFailed = req.Status == "failed"
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	err := UploadRun(context.Background(), Config{
		BackendURL:  server.URL,
		ReportToken: "secret-token",
		HTTPClient:  server.Client(),
		RetryDelays: []time.Duration{},
	}, record)
	if err == nil || !strings.Contains(err.Error(), "upload events") {
		t.Fatalf("UploadRun() error = %v, want upload events error", err)
	}
	if !markedFailed {
		t.Fatal("partial upload was not marked failed")
	}
}

func TestUploadRunMarksPartialFailureAfterCallerCancellation(t *testing.T) {
	runDir := writeBundle(t)
	record := testRecord(runDir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var markedFailed bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/ingest/runs":
			w.WriteHeader(http.StatusOK)
		case "/api/ingest/runs/run-1/events":
			cancel()
			w.WriteHeader(http.StatusBadGateway)
		case "/api/ingest/runs/run-1/complete":
			var req completeRunRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode complete request: %v", err)
			}
			markedFailed = req.Status == "failed"
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	err := UploadRun(ctx, Config{
		BackendURL:  server.URL,
		ReportToken: "secret-token",
		HTTPClient:  server.Client(),
		RetryDelays: []time.Duration{},
	}, record)
	if err == nil || !strings.Contains(err.Error(), "upload events") {
		t.Fatalf("UploadRun() error = %v, want canceled events upload", err)
	}
	if !markedFailed {
		t.Fatal("detached cleanup did not mark the partial upload failed")
	}
}

func TestUploadRunRejectsUnsafeArtifactPath(t *testing.T) {
	runDir := t.TempDir()
	record := testRecord(runDir)
	writeFile(t, filepath.Join(runDir, "acta-events.jsonl"), strings.Join([]string{
		`{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":1,"timestamp":"2026-07-06T12:00:00Z","source":"acta","type":"run.started","payload":{"agent":"codex","cwd":"/workspace","run_dir":"/workspace/.acta/runs/run-1"}}`,
		`{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":2,"timestamp":"2026-07-06T12:00:01Z","source":"acta","type":"run.completed","payload":{"status":"ok","ok":true,"timeout":false,"duration_ms":1000},"artifact_refs":[{"kind":"run_record","path":"../run.json"}]}`,
		"",
	}, "\n"))

	err := UploadRun(context.Background(), Config{BackendURL: "http://127.0.0.1", ReportToken: "secret-token"}, record)
	if err == nil || !strings.Contains(err.Error(), "unsafe artifact path") {
		t.Fatalf("UploadRun() error = %v, want unsafe artifact path", err)
	}
}

func TestUploadRunRejectsSymlinkArtifact(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges")
	}
	runDir := writeBundle(t)
	target := filepath.Join(t.TempDir(), "outside.txt")
	writeFile(t, target, "private data")
	digestPath := filepath.Join(runDir, "digest.json")
	if err := os.Remove(digestPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, digestPath); err != nil {
		t.Fatal(err)
	}

	err := UploadRun(context.Background(), Config{
		BackendURL: "http://127.0.0.1", ReportToken: "secret-token", RetryDelays: []time.Duration{},
	}, testRecord(runDir))
	if err == nil || !strings.Contains(err.Error(), "not a symlink") {
		t.Fatalf("UploadRun() error = %v, want symlink rejection", err)
	}
}

func TestScanEventsBoundsLineSize(t *testing.T) {
	runDir := t.TempDir()
	writeFile(t, filepath.Join(runDir, "acta-events.jsonl"), strings.Repeat("x", maxEventsRequestBytes+1)+"\n")
	if _, err := scanEvents(runDir, "run-1", nil); err == nil || !strings.Contains(err.Error(), "maximum line size") {
		t.Fatalf("scanEvents() error = %v, want bounded-line error", err)
	}
}

func TestScanEventsRejectsInvalidReplayContract(t *testing.T) {
	started := `{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":1,"timestamp":"2026-07-06T12:00:00Z","source":"acta","type":"run.started","payload":{"agent":"codex","cwd":"/workspace","run_dir":"/workspace/.acta/runs/run-1"}}`
	completed := `{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":2,"timestamp":"2026-07-06T12:00:01Z","source":"acta","type":"run.completed","payload":{"status":"ok","ok":true,"timeout":false,"duration_ms":1000}}`
	cases := map[string][]string{
		"wrong schema":     {strings.Replace(started, `"schema_version":2`, `"schema_version":3`, 1), completed},
		"wrong source":     {strings.Replace(started, `"source":"acta"`, `"source":"other"`, 1), completed},
		"sequence gap":     {started, strings.Replace(completed, `"sequence":2`, `"sequence":3`, 1)},
		"missing terminal": {started},
		"event after terminal": {started, completed,
			`{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":3,"timestamp":"2026-07-06T12:00:02Z","source":"acta","type":"agent.message","payload":{}}`},
	}
	for name, lines := range cases {
		t.Run(name, func(t *testing.T) {
			runDir := t.TempDir()
			writeFile(t, filepath.Join(runDir, "acta-events.jsonl"), strings.Join(lines, "\n")+"\n")
			if _, err := scanEvents(runDir, "run-1", nil); err == nil {
				t.Fatal("invalid replay stream was accepted")
			}
		})
	}
}

func TestUploadRunRejectsUnknownEventFieldsBeforeUpload(t *testing.T) {
	tests := map[string]func(string) string{
		"event envelope": func(events string) string {
			return strings.Replace(events,
				`"payload":{"agent":"codex","cwd":"/workspace","run_dir":"/workspace/.acta/runs/run-1"}}`,
				`"payload":{"agent":"codex","cwd":"/workspace","run_dir":"/workspace/.acta/runs/run-1"},"thinking":"private"}`,
				1,
			)
		},
		"producer": func(events string) string {
			return strings.Replace(events,
				`"producer":{"name":"acta","version":"test"}`,
				`"producer":{"name":"acta","version":"test","thinking":"private"}`,
				1,
			)
		},
		"regenerated_by": func(events string) string {
			return strings.Replace(events,
				`"run_id":"run-1"`,
				`"regenerated_by":{"name":"acta","version":"test","thinking":"private"},"run_id":"run-1"`,
				1,
			)
		},
		"artifact reference": func(events string) string {
			return strings.Replace(events,
				`{"kind":"run_record","path":"run.json"}`,
				`{"kind":"run_record","path":"run.json","thinking":"private"}`,
				1,
			)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			runDir := writeBundle(t)
			eventsPath := filepath.Join(runDir, actaevents.Filename)
			writeFile(t, eventsPath, mutate(readTestFile(t, eventsPath)))

			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests++
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			err := UploadRun(context.Background(), Config{
				BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
			}, testRecord(runDir))
			if err == nil || !strings.Contains(err.Error(), `unknown field "thinking"`) {
				t.Fatalf("UploadRun() error = %v, want unknown-field rejection", err)
			}
			if requests != 0 {
				t.Fatalf("invalid event stream issued %d remote requests, want none", requests)
			}
			if local := readTestFile(t, eventsPath); !strings.Contains(local, `"thinking":"private"`) {
				t.Fatal("upload validation rewrote the local invalid event stream")
			}
		})
	}
}

func TestUploadRunValidatesPublishedEventSchemasBeforeUpload(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(string) string
		wantError bool
	}{
		{
			name:   "valid payloads",
			mutate: func(events string) string { return events },
		},
		{
			name: "string payload",
			mutate: func(events string) string {
				return strings.Replace(events,
					`"payload":{"status":"ok","ok":true,"timeout":false,"duration_ms":1000}`,
					`"payload":"not-an-object"`,
					1,
				)
			},
			wantError: true,
		},
		{
			name: "unknown payload property",
			mutate: func(events string) string {
				return strings.Replace(events,
					`"payload":{"status":"ok","ok":true,"timeout":false,"duration_ms":1000}`,
					`"payload":{"status":"ok","ok":true,"timeout":false,"duration_ms":1000,"future_property":true}`,
					1,
				)
			},
			wantError: true,
		},
		{
			name: "non-positive artifact lines",
			mutate: func(events string) string {
				return strings.Replace(events,
					`{"kind":"run_record","path":"run.json"}`,
					`{"kind":"run_record","path":"run.json","lines":[0,-1]}`,
					1,
				)
			},
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runDir := writeBundle(t)
			eventsPath := filepath.Join(runDir, actaevents.Filename)
			writeFile(t, eventsPath, test.mutate(readTestFile(t, eventsPath)))

			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests++
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			err := UploadRun(context.Background(), Config{
				BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
			}, testRecord(runDir))
			if !test.wantError {
				if err != nil {
					t.Fatalf("UploadRun() rejected valid payloads: %v", err)
				}
				if requests == 0 {
					t.Fatal("valid payloads issued no remote requests")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "does not match the published schema") {
				t.Fatalf("UploadRun() error = %v, want event-schema rejection", err)
			}
			if requests != 0 {
				t.Fatalf("invalid payload issued %d remote requests, want none", requests)
			}
		})
	}
}

func TestUploadRunRejectsFutureEventSchemaBeforeRemoteRewrite(t *testing.T) {
	runDir := writeBundle(t)
	const secret = "future-schema-reasoning"
	futureStream := strings.Join([]string{
		`{"schema_version":4,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":1,"timestamp":"2026-07-06T12:00:00Z","source":"acta","type":"run.started","payload":{"agent":"codex"}}`,
		`{"schema_version":4,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":2,"timestamp":"2026-07-06T12:00:00.5Z","source":"acta","type":"agent.reasoning","payload":{"kind":"reasoning","text":"` + secret + `"}}`,
		`{"schema_version":4,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":3,"timestamp":"2026-07-06T12:00:01Z","source":"acta","type":"run.completed","payload":{"status":"ok"},"artifact_refs":[{"kind":"run_record","path":"run.json"},{"kind":"digest","path":"digest.json"},{"kind":"event_stream","path":"acta-events.jsonl"}]}`,
		"",
	}, "\n")
	eventsPath := filepath.Join(runDir, actaevents.Filename)
	writeFile(t, eventsPath, futureStream)

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
	}, testRecord(runDir))
	if err == nil || !strings.Contains(err.Error(), "unsupported schema_version 4") {
		t.Fatalf("UploadRun() error = %v, want future schema rejection", err)
	}
	if requests != 0 {
		t.Fatalf("future event stream issued %d remote requests, want none", requests)
	}
	if local := readTestFile(t, eventsPath); local != futureStream || !strings.Contains(local, secret) {
		t.Fatalf("future event stream was normalized locally:\n%s", local)
	}
}

func TestUploadRunRejectsFutureDigestSchemaRegardlessOfPrivacyOptIn(t *testing.T) {
	for _, allowUnredacted := range []bool{false, true} {
		t.Run(fmt.Sprintf("allow_unredacted_%t", allowUnredacted), func(t *testing.T) {
			runDir := writeBundle(t)
			writeFile(t, filepath.Join(runDir, "run.json"), `{"schema_version":3,"id":"run-1"}`+"\n")
			const secret = "future-digest-private-reasoning-5217"
			futureDigest := `{"schema_version":4,"run_id":"run-1","timeline":[{"kind":"reasoning","text":"` + secret + `"}],"future_digest_field":{"preserve":true}}` + "\n"
			digestPath := filepath.Join(runDir, "digest.json")
			writeFile(t, digestPath, futureDigest)

			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests++
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			err := UploadRun(context.Background(), Config{
				BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
				AllowUnredactedRemoteReasoning: allowUnredacted,
			}, testRecord(runDir))
			if err == nil || !strings.Contains(err.Error(), "unsupported schema_version 4") {
				t.Fatalf("UploadRun() error = %v, want future digest schema rejection", err)
			}
			if requests != 0 {
				t.Fatalf("future digest issued %d remote requests, want none", requests)
			}
			if local := readTestFile(t, digestPath); local != futureDigest || !strings.Contains(local, secret) {
				t.Fatalf("future digest was transformed or relabeled locally:\n%s", local)
			}
		})
	}
}

func TestScanEventsRejectsMixedSchemaStream(t *testing.T) {
	runDir := t.TempDir()
	writeFile(t, filepath.Join(runDir, actaevents.Filename), strings.Join([]string{
		`{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":1,"timestamp":"2026-07-06T12:00:00Z","source":"acta","type":"run.started","payload":{"agent":"codex","cwd":"/workspace","run_dir":"/workspace/.acta/runs/run-1"}}`,
		`{"schema_version":2,"producer":{"name":"acta","version":"v2"},"run_id":"run-1","sequence":2,"timestamp":"2026-07-06T12:00:01Z","source":"acta","type":"run.completed","payload":{"status":"ok","ok":true,"timeout":false,"duration_ms":1000}}`,
	}, "\n")+"\n")
	if _, err := scanEvents(runDir, "run-1", nil); err == nil || !strings.Contains(err.Error(), "does not match stream") {
		t.Fatalf("scanEvents() error = %v", err)
	}
}

func TestUploadRunEnforcesSnapshotBudget(t *testing.T) {
	runDir := writeBundle(t)
	err := UploadRun(context.Background(), Config{
		BackendURL: "http://127.0.0.1", ReportToken: "token", MaxUploadBytes: 1,
	}, testRecord(runDir))
	if err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("UploadRun() error = %v", err)
	}
}

func TestUploadRunCountsUnreferencedEventSnapshotAtBudgetBoundary(t *testing.T) {
	runDir := writeBundle(t)
	eventsPath := filepath.Join(runDir, actaevents.Filename)
	events := strings.Replace(
		readTestFile(t, eventsPath),
		`,{"kind":"event_stream","path":"acta-events.jsonl"}`,
		"",
		1,
	)
	writeFile(t, eventsPath, events)

	var snapshotBytes int64
	for _, name := range []string{actaevents.Filename, "run.json", "digest.json"} {
		info, err := os.Stat(filepath.Join(runDir, name))
		if err != nil {
			t.Fatal(err)
		}
		snapshotBytes += info.Size()
	}

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	config := Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
		MaxUploadBytes: snapshotBytes - 1,
	}

	err := UploadRun(context.Background(), config, testRecord(runDir))
	if err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("UploadRun() error = %v, want aggregate budget rejection", err)
	}
	if requests != 0 {
		t.Fatalf("over-budget upload issued %d remote requests, want none", requests)
	}

	config.MaxUploadBytes = snapshotBytes
	if err := UploadRun(context.Background(), config, testRecord(runDir)); err != nil {
		t.Fatalf("UploadRun() at exact aggregate budget = %v", err)
	}
	if requests == 0 {
		t.Fatal("exact-budget upload issued no remote requests")
	}
}

func TestUploadRunRejectsTerminalOutcomeMismatch(t *testing.T) {
	runDir := writeBundle(t)
	record := testRecord(runDir)
	record.OK = false
	if err := UploadRun(context.Background(), Config{
		BackendURL: "http://127.0.0.1", ReportToken: "secret-token", RetryDelays: []time.Duration{},
	}, record); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("outcome mismatch error = %v", err)
	}
}

func TestValidateBackendURLRequiresHTTPSOutsideLoopback(t *testing.T) {
	if _, err := ValidateBackendURL("http://backend.example.com", false); err == nil {
		t.Fatal("non-loopback HTTP backend was accepted without opt-in")
	}
	if got, err := ValidateBackendURL("http://backend.example.com/", true); err != nil || got != "http://backend.example.com" {
		t.Fatalf("explicit insecure backend = %q, err = %v", got, err)
	}
	if _, err := ValidateBackendURL("http://127.0.0.1:8080", false); err != nil {
		t.Fatalf("loopback development backend rejected: %v", err)
	}
	if _, err := ValidateBackendURL("https://backend.example.com", false); err != nil {
		t.Fatalf("HTTPS backend rejected: %v", err)
	}
}

func TestClientDoesNotForwardAuthorizationAcrossRedirect(t *testing.T) {
	var redirected bool
	target := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		redirected = true
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("redirect target received Authorization = %q", got)
		}
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	client := clientFromConfig(Config{
		BackendURL: redirector.URL, ReportToken: "secret-token", RetryDelays: []time.Duration{},
	})
	if err := client.postJSON(context.Background(), "/api/ingest/runs", map[string]string{"run_id": "run-1"}); err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("redirect error = %v, want rejected 307", err)
	}
	if redirected {
		t.Fatal("API client followed redirect")
	}
}

func TestEventBatcherRespectsMaxBytes(t *testing.T) {
	events := []actaevents.Event{
		testEvent(1, "event"),
		testEvent(2, "event"),
		testEvent(3, "event"),
	}
	encoded, err := json.Marshal(events[0])
	if err != nil {
		t.Fatal(err)
	}

	batcher, err := newEventBatcher(eventsEnvelopeBytes + len(encoded))
	if err != nil {
		t.Fatalf("newEventBatcher() error = %v", err)
	}
	var batches [][]actaevents.Event
	for _, event := range events {
		batch, err := batcher.add(event)
		if err != nil {
			t.Fatalf("eventBatcher.add() error = %v", err)
		}
		if len(batch) > 0 {
			batches = append(batches, batch)
		}
	}
	if batch := batcher.flush(); len(batch) > 0 {
		batches = append(batches, batch)
	}
	if len(batches) != len(events) {
		t.Fatalf("batch count = %d, want %d", len(batches), len(events))
	}
	for i, batch := range batches {
		if len(batch) != 1 || batch[0].Sequence != i+1 {
			t.Fatalf("batch %d = %#v, want one event sequence %d", i, batch, i+1)
		}
	}
}

func TestEventBatcherRejectsSingleOversizedEvent(t *testing.T) {
	event := testEvent(1, "oversized")
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}

	batcher, err := newEventBatcher(eventsEnvelopeBytes + len(encoded) - 1)
	if err != nil {
		t.Fatalf("newEventBatcher() error = %v", err)
	}
	_, err = batcher.add(event)
	if err == nil || !strings.Contains(err.Error(), "exceeds max batch size") {
		t.Fatalf("eventBatcher.add() error = %v, want max batch size error", err)
	}
}

func writeBundle(t *testing.T) string {
	t.Helper()
	runDir := t.TempDir()
	writeFile(t, filepath.Join(runDir, "run.json"), `{"id":"run-1"}`+"\n")
	writeFile(t, filepath.Join(runDir, "digest.json"), `{"run_id":"run-1"}`+"\n")
	writeFile(t, filepath.Join(runDir, "acta-events.jsonl"), strings.Join([]string{
		`{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":1,"timestamp":"2026-07-06T12:00:00Z","source":"acta","type":"run.started","payload":{"agent":"codex","cwd":"/workspace","run_dir":"/workspace/.acta/runs/run-1"}}`,
		`{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":2,"timestamp":"2026-07-06T12:00:01Z","source":"acta","type":"run.completed","payload":{"status":"ok","ok":true,"timeout":false,"duration_ms":1000},"artifact_refs":[{"kind":"run_record","path":"run.json"},{"kind":"digest","path":"digest.json"},{"kind":"event_stream","path":"acta-events.jsonl"}]}`,
		"",
	}, "\n"))
	return runDir
}

func makeBundleDirectoryReadOnly(t *testing.T, runDir string) os.FileMode {
	t.Helper()
	info, err := os.Stat(runDir)
	if err != nil {
		t.Fatal(err)
	}
	originalMode := info.Mode().Perm()
	if err := os.Chmod(runDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(runDir, originalMode) })
	writable, err := projectionDirectoryWritable(runDir)
	if err != nil {
		t.Fatal(err)
	}
	if writable {
		t.Skip("test environment does not enforce read-only directory permissions")
	}
	return originalMode
}

func writeProjectionGeneration(t *testing.T, runDir, generation, digestPayload, eventsPayload string) {
	t.Helper()
	manifestPayload, err := json.Marshal(struct {
		SchemaVersion int                `json:"schema_version"`
		Producer      runrecord.Producer `json:"producer"`
		Generation    string             `json:"generation"`
		DigestSHA256  string             `json:"digest_sha256"`
		EventsSHA256  string             `json:"events_sha256"`
	}{
		SchemaVersion: actaevents.MinProjectionSchemaVersion,
		Producer:      runrecord.Producer{Name: "acta", Version: "test"},
		Generation:    generation,
		DigestSHA256:  fmt.Sprintf("%x", sha256.Sum256([]byte(digestPayload))),
		EventsSHA256:  fmt.Sprintf("%x", sha256.Sum256([]byte(eventsPayload))),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, artifact := range []struct {
		name    string
		payload []byte
	}{
		{name: "digest.json", payload: []byte(digestPayload)},
		{name: actaevents.Filename, payload: []byte(eventsPayload)},
		{name: "projection.json", payload: append(manifestPayload, '\n')},
	} {
		if err := securefile.WriteFile(filepath.Join(runDir, artifact.name), artifact.payload); err != nil {
			t.Fatal(err)
		}
	}
}

func addArtifactRef(t *testing.T, runDir, ref string) {
	t.Helper()
	eventsPath := filepath.Join(runDir, actaevents.Filename)
	events := readTestFile(t, eventsPath)
	events = strings.Replace(events,
		`{"kind":"event_stream","path":"acta-events.jsonl"}`,
		ref+`,{"kind":"event_stream","path":"acta-events.jsonl"}`,
		1,
	)
	writeFile(t, eventsPath, events)
}

func uploadBundleStderr(t *testing.T, content string) string {
	t.Helper()
	runDir := writeBundle(t)
	const stderrName = "agent.stderr.log"
	writeFile(t, filepath.Join(runDir, stderrName), content)
	addArtifactRef(t, runDir, `{"kind":"raw_stderr","path":"`+stderrName+`"}`)

	var uploaded string
	created := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/ingest/runs" {
			created = true
		}
		if request.URL.Path == "/api/ingest/runs/run-1/artifacts" && request.URL.Query().Get("filename") == stderrName {
			payload, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			uploaded = string(payload)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	record := testRecord(runDir)
	record.ReasoningRedactionState = "retained_local"
	if err := UploadRun(context.Background(), Config{
		BackendURL: server.URL, ReportToken: "token", HTTPClient: server.Client(), RetryDelays: []time.Duration{},
	}, record); err != nil {
		t.Fatalf("UploadRun() error = %v", err)
	}
	if !created {
		t.Fatal("upload did not create the remote run")
	}
	return uploaded
}

func testEvent(sequence int, text string) actaevents.Event {
	return actaevents.Event{
		SchemaVersion: actaevents.SchemaVersion,
		RunID:         "run-1",
		Sequence:      sequence,
		Timestamp:     time.Date(2026, 7, 6, 12, 0, sequence, 0, time.UTC),
		Source:        actaevents.Source,
		Type:          actaevents.TypeAgentMessage,
		Payload:       json.RawMessage(`{"text":"` + text + `"}`),
	}
}

func testRecord(runDir string) *runrecord.Record {
	exit := 0
	return &runrecord.Record{
		SchemaVersion:     runrecord.SchemaVersion,
		Producer:          runrecord.Producer{Name: "acta", Version: "test"},
		ID:                "run-1",
		Agent:             "codex",
		RunDir:            runDir,
		Model:             "gpt-test",
		Repository:        "example-org/example-repo",
		IssueNumber:       42,
		IssueTitle:        "Upload run bundles",
		IssueBody:         stringPtr("## Issue basis\n\nUpload this bundle.\n"),
		TaskTitle:         "Upload run bundles",
		StartedAt:         time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC),
		CompletedAt:       time.Date(2026, 7, 6, 12, 0, 1, 0, time.UTC),
		DurationMillis:    1000,
		ExitCode:          &exit,
		OK:                true,
		TerminationReason: "completed",
		PromptSource:      "test",
		PromptCaptured:    true,
	}
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func useSnapshotTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, dir)
	}
	if got := os.TempDir(); filepath.Clean(got) != filepath.Clean(dir) {
		t.Fatalf("os.TempDir() = %q, want isolated snapshot directory %q", got, dir)
	}
	return dir
}

func assertDirectoryEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("snapshot cleanup left temporary files behind: %v", entries)
	}
}

func writeSnapshotFile(t *testing.T, content string) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "snapshot-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if _, err := file.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	return file
}

func readOpenFile(t *testing.T, file *os.File) string {
	t.Helper()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

type cancelAfterWrite struct {
	cancel context.CancelFunc
	writes int
}

func (writer *cancelAfterWrite) Write(payload []byte) (int, error) {
	writer.writes++
	writer.cancel()
	return len(payload), nil
}

type cancelAfterChecksContext struct {
	context.Context
	checksRemaining int
}

func (ctx *cancelAfterChecksContext) Err() error {
	if ctx.checksRemaining == 0 {
		return context.Canceled
	}
	ctx.checksRemaining--
	return nil
}

func stringPtr(value string) *string {
	return &value
}
