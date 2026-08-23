package reporting

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nobbettt/acta/internal/actaevents"
	"github.com/nobbettt/acta/internal/runrecord"
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
				`{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":1,"timestamp":"2026-07-06T12:00:00Z","source":"acta","type":"run.started","payload":{"agent":"` + agent + `","reasoning_redaction_state":"retained_local"}}`,
				`{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":2,"timestamp":"2026-07-06T12:00:00.5Z","source":"acta","type":"agent.reasoning","payload":{"kind":"reasoning","provider_event":"private","text":"` + secret + `"}}`,
				`{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":3,"timestamp":"2026-07-06T12:00:01Z","source":"acta","type":"run.completed","payload":{"reasoning_redaction_state":"retained_local"},"artifact_refs":[{"kind":"run_record","path":"run.json"},{"kind":"raw_stdout","path":"` + rawName + `"},{"kind":"digest","path":"digest.json"},{"kind":"event_stream","path":"acta-events.jsonl"}]}`,
				"",
			}, "\n"))
			record := testRecord(runDir)
			record.Agent = agent
			record.ReasoningRedactionState = "retained_local"

			var remote bytes.Buffer
			redactionStates := map[string]string{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/api/ingest/runs/run-1/events" || request.URL.Path == "/api/ingest/runs/run-1/artifacts" {
					payload, err := io.ReadAll(request.Body)
					if err != nil {
						t.Error(err)
					}
					remote.Write(payload)
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
				"digest.json":       "not_required",
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
		})
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
		`{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":1,"timestamp":"2026-07-06T12:00:00Z","source":"acta","type":"run.started","payload":{"agent":"claude","reasoning_redaction_state":"retained_local"}}`,
		`{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":2,"timestamp":"2026-07-06T12:00:00.5Z","source":"acta","type":"agent.event.unsupported","payload":{"kind":"unsupported","provider_event":"assistant.redacted_thinking","details":{"type":"redacted_thinking","data":"` + secret + `"},"raw_event_lines":[1]},"artifact_refs":[{"kind":"raw_stdout","path":"` + rawName + `","lines":[1]}]}`,
		`{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":3,"timestamp":"2026-07-06T12:00:01Z","source":"acta","type":"run.completed","payload":{"status":"ok"},"artifact_refs":[{"kind":"run_record","path":"run.json"},{"kind":"raw_stdout","path":"` + rawName + `"},{"kind":"digest","path":"digest.json"},{"kind":"event_stream","path":"acta-events.jsonl"}]}`,
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
	if strings.Contains(remote.String(), secret) || strings.Contains(remote.String(), `"details"`) {
		t.Fatalf("remote upload retained unsupported reasoning details: %s", remote.String())
	}
	if !strings.Contains(remote.String(), `"provider_event":"assistant.redacted_thinking"`) ||
		!strings.Contains(remote.String(), `"raw_event_lines":[1]`) ||
		!strings.Contains(remote.String(), `"redacted":true`) {
		t.Fatalf("remote upload lost structural unsupported-event references: %s", remote.String())
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

func TestRedactActaReasoningEventLineRedactsUnknownTypeByDefault(t *testing.T) {
	const secret = "future-private-content-1209"
	original := []byte(`{"type":"agent.future.event","payload":{"kind":"future","provider_event":"future.block","details":{"text":"` + secret + `"},"raw_event_lines":[7]}}` + "\n")
	redacted, err := redactActaReasoningEventLine(original)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(redacted), secret) || strings.Contains(string(redacted), `"details"`) {
		t.Fatalf("unknown event retained free-text payload: %s", redacted)
	}
	if !strings.Contains(string(redacted), `"raw_event_lines":[7]`) || !strings.Contains(string(redacted), `"redacted":true`) {
		t.Fatalf("unknown event lost structural references: %s", redacted)
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
		`{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":1,"timestamp":"2026-07-06T12:00:00Z","source":"acta","type":"run.started","payload":{"agent":"codex"}}`,
		`{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":2,"timestamp":"2026-07-06T12:00:01Z","source":"acta","type":"run.completed","payload":{},"artifact_refs":[{"kind":"run_record","path":"../run.json"}]}`,
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
	started := `{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":1,"timestamp":"2026-07-06T12:00:00Z","source":"acta","type":"run.started","payload":{"agent":"codex"}}`
	completed := `{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":2,"timestamp":"2026-07-06T12:00:01Z","source":"acta","type":"run.completed","payload":{}}`
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

func TestScanEventsRejectsMixedSchemaStream(t *testing.T) {
	runDir := t.TempDir()
	writeFile(t, filepath.Join(runDir, actaevents.Filename), strings.Join([]string{
		`{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":1,"timestamp":"2026-07-06T12:00:00Z","source":"acta","type":"run.started","payload":{"agent":"codex"}}`,
		`{"schema_version":2,"producer":{"name":"acta","version":"v2"},"run_id":"run-1","sequence":2,"timestamp":"2026-07-06T12:00:01Z","source":"acta","type":"run.completed","payload":{}}`,
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
		`{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":1,"timestamp":"2026-07-06T12:00:00Z","source":"acta","type":"run.started","payload":{"agent":"codex"}}`,
		`{"schema_version":2,"producer":{"name":"acta","version":"test"},"run_id":"run-1","sequence":2,"timestamp":"2026-07-06T12:00:01Z","source":"acta","type":"run.completed","payload":{"status":"ok"},"artifact_refs":[{"kind":"run_record","path":"run.json"},{"kind":"digest","path":"digest.json"},{"kind":"event_stream","path":"acta-events.jsonl"}]}`,
		"",
	}, "\n"))
	return runDir
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

func stringPtr(value string) *string {
	return &value
}
