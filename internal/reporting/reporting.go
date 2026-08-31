package reporting

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/nobbettt/acta/internal/actaevents"
	"github.com/nobbettt/acta/internal/digest"
	"github.com/nobbettt/acta/internal/reasoning"
	"github.com/nobbettt/acta/internal/runrecord"
	"github.com/nobbettt/acta/internal/schemaversion"
	"github.com/nobbettt/acta/internal/securefile"
)

type Config struct {
	BackendURL        string
	ReportToken       string
	OrganizationID    string
	RepositoryID      string
	HTTPClient        *http.Client
	RetryDelays       []time.Duration
	AllowInsecureHTTP bool
	// MaxUploadBytes caps the total immutable upload snapshot. Zero explicitly
	// disables the cap; callers normally pass DefaultMaxUploadBytes.
	MaxUploadBytes int64
	// AllowUnredactedRemoteReasoning is an explicit privacy opt-in. The default
	// upload snapshot removes provider-private reasoning while leaving the local
	// run bundle untouched.
	AllowUnredactedRemoteReasoning bool
	// MaxRedactionLineBytes bounds one JSONL record while preparing redacted
	// upload snapshots. Zero selects DefaultMaxRedactionLineBytes.
	MaxRedactionLineBytes int
	// projectionSnapshotHook is a test seam invoked after each manifest read.
	projectionSnapshotHook func(attempt int)
}

const (
	maxEventsRequestBytes               = actaevents.MaxEventsRequestBytes
	eventsEnvelopeBytes                 = len(`{"events":[]}`)
	DefaultMaxUploadBytes         int64 = 1 << 30
	DefaultMaxRedactionLineBytes        = 8 << 20
	maxRedactionJSONDocumentBytes int64 = 64 << 20
	withheldArtifactReason              = "reasoning_redaction_unverified"
	maxProjectionManifestBytes    int64 = 64 << 10
	maxProjectionSnapshotAttempts       = 3
)

type createRunRequest struct {
	RunID          string             `json:"run_id"`
	OrganizationID string             `json:"organization_id,omitempty"`
	RepositoryID   string             `json:"repository_id,omitempty"`
	Status         string             `json:"status"`
	Agent          string             `json:"agent"`
	Model          string             `json:"model,omitempty"`
	Source         string             `json:"source"`
	StartedAt      time.Time          `json:"started_at"`
	Metadata       runMetadataPayload `json:"metadata"`
}

type completeRunRequest struct {
	Status      string             `json:"status"`
	CompletedAt time.Time          `json:"completed_at"`
	Metadata    completionMetadata `json:"metadata"`
}

type eventsRequest struct {
	Events []actaevents.Event `json:"events"`
}

type artifactUpload struct {
	Kind           string `json:"kind"`
	Filename       string `json:"filename"`
	ContentType    string `json:"content_type"`
	SizeBytes      int64  `json:"size_bytes"`
	SHA256         string `json:"sha256"`
	Compression    string `json:"compression,omitempty"`
	SchemaVersion  *int32 `json:"schema_version,omitempty"`
	RedactionState string `json:"redaction_state"`
	File           *os.File
	TempPath       string
	Withheld       bool `json:"-"`
}

type artifactSnapshot struct {
	File     *os.File
	TempPath string
}

// Manifested projection sources use the securefile opener whose Windows
// backend grants delete sharing. Keeping this seam here makes that snapshot
// contract independently testable on every host platform.
var openManifestedProjectionRegular = securefile.OpenRegular

type projectionManifest struct {
	SchemaVersion int                `json:"schema_version"`
	Producer      runrecord.Producer `json:"producer"`
	Generation    string             `json:"generation"`
	RunSHA256     string             `json:"run_sha256,omitempty"`
	DigestSHA256  string             `json:"digest_sha256"`
	EventsSHA256  string             `json:"events_sha256"`
}

type completionMetadata struct {
	OK                         bool   `json:"ok"`
	Timeout                    bool   `json:"timeout"`
	DurationMillis             int64  `json:"duration_ms"`
	ExitCode                   *int   `json:"exit_code,omitempty"`
	HeadCommitSHA              string `json:"head_commit_sha,omitempty"`
	TerminationReason          string `json:"termination_reason,omitempty"`
	Error                      string `json:"error,omitempty"`
	TraceID                    string `json:"trace_id,omitempty"`
	PromptSource               string `json:"prompt_source,omitempty"`
	PromptCaptured             bool   `json:"prompt_captured,omitempty"`
	OTLPStatus                 string `json:"otlp_status,omitempty"`
	OTLPError                  string `json:"otlp_error,omitempty"`
	RawOutputLimitBytes        int64  `json:"raw_output_limit_bytes,omitempty"`
	RawOutputLimitExceeded     bool   `json:"raw_output_limit_exceeded,omitempty"`
	WorkspaceDiffLimitBytes    int64  `json:"workspace_diff_limit_bytes,omitempty"`
	WorkspaceDiffLimitExceeded bool   `json:"workspace_diff_limit_exceeded,omitempty"`
	ReasoningRedactionState    string `json:"reasoning_redaction_state,omitempty"`
}

type runMetadataPayload struct {
	AgentVersion               string  `json:"agent_version,omitempty"`
	OTLPStatus                 string  `json:"otlp_status,omitempty"`
	OTLPError                  string  `json:"otlp_error,omitempty"`
	RawOutputLimitBytes        int64   `json:"raw_output_limit_bytes,omitempty"`
	RawOutputLimitExceeded     bool    `json:"raw_output_limit_exceeded,omitempty"`
	WorkspaceDiffLimitBytes    int64   `json:"workspace_diff_limit_bytes,omitempty"`
	WorkspaceDiffLimitExceeded bool    `json:"workspace_diff_limit_exceeded,omitempty"`
	ProcessContainment         string  `json:"process_containment,omitempty"`
	AgentConfigMode            string  `json:"agent_config_mode,omitempty"`
	RuntimeBundleSHA256        string  `json:"runtime_bundle_sha256,omitempty"`
	ReasoningRedactionState    string  `json:"reasoning_redaction_state,omitempty"`
	PromptSource               string  `json:"prompt_source"`
	PromptCaptured             bool    `json:"prompt_captured"`
	TerminationReason          string  `json:"termination_reason"`
	TraceID                    string  `json:"trace_id"`
	CWD                        string  `json:"cwd"`
	RunDir                     string  `json:"run_dir"`
	RecoveryDir                string  `json:"recovery_dir,omitempty"`
	Repository                 string  `json:"repository,omitempty"`
	IssueNumber                int     `json:"issue_number,omitempty"`
	IssueTitle                 string  `json:"issue_title,omitempty"`
	IssueBody                  *string `json:"issue_body,omitempty"`
	TaskTitle                  string  `json:"title,omitempty"`
	BaseCommitSHA              string  `json:"base_commit_sha,omitempty"`
	BaseBranch                 string  `json:"base_branch,omitempty"`
	BaseDirty                  *bool   `json:"base_dirty,omitempty"`
}

func UploadRun(ctx context.Context, cfg Config, record *runrecord.Record) error {
	if record == nil {
		return errors.New("record is nil")
	}
	backendURL, err := ValidateBackendURL(cfg.BackendURL, cfg.AllowInsecureHTTP)
	if err != nil {
		return err
	}
	cfg.BackendURL = backendURL
	if strings.TrimSpace(cfg.ReportToken) == "" {
		return errors.New("report token is required")
	}
	if strings.TrimSpace(record.RunDir) == "" {
		return errors.New("record run dir is empty")
	}
	organizationID := strings.TrimSpace(cfg.OrganizationID)
	repositoryID := strings.TrimSpace(cfg.RepositoryID)
	if (organizationID == "") != (repositoryID == "") {
		return errors.New("organization ID and repository ID must be provided together")
	}

	client := clientFromConfig(cfg)
	artifactLimit := cfg.MaxUploadBytes
	if artifactLimit < 0 {
		return errors.New("max upload bytes must not be negative")
	}
	maxRedactionLineBytes := cfg.MaxRedactionLineBytes
	if maxRedactionLineBytes < 0 {
		return errors.New("max redaction line bytes must not be negative")
	}
	if maxRedactionLineBytes == 0 {
		maxRedactionLineBytes = DefaultMaxRedactionLineBytes
	}
	// The upload boundary never trusts the mutable run record as evidence that
	// content is safe. Default uploads always perform their own idempotent pass.
	redactRemoteReasoning := !cfg.AllowUnredactedRemoteReasoning
	remoteRedactionState := "redacted"
	if !redactRemoteReasoning {
		remoteRedactionState = "unredacted"
	}
	eventFile, eventTempPath, artifacts, snapshotRecord, err := prepareUploadSnapshotContext(ctx, record, artifactLimit, redactRemoteReasoning, maxRedactionLineBytes, cfg.projectionSnapshotHook)
	if err != nil {
		return err
	}
	record = snapshotRecord
	defer func() {
		_ = eventFile.Close()
		_ = os.Remove(eventTempPath)
	}()
	defer closeArtifacts(artifacts)
	annotated, err := annotateWithheldArtifactRefsContext(ctx, eventFile, record.ID, artifacts)
	if err != nil {
		return err
	}
	if annotated {
		if err := refreshEventArtifactContext(ctx, artifacts, eventFile, artifactLimit); err != nil {
			return err
		}
	}

	status := "failed"
	if record.OK {
		status = "completed"
	}
	completePath := "/api/ingest/runs/" + url.PathEscape(record.ID) + "/complete"
	markUploadFailed := func(uploadErr error) error {
		// The upload context is often already canceled when a timeout causes the
		// partial failure. Give the best-effort terminal update its own short
		// deadline so the remote run is not stranded in "running".
		markCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		markErr := client.postJSON(markCtx, completePath, completeRunRequest{
			Status:      "failed",
			CompletedAt: record.CompletedAt,
			Metadata: completionMetadata{
				OK:                false,
				Timeout:           record.Timeout,
				DurationMillis:    record.DurationMillis,
				ExitCode:          record.ExitCode,
				HeadCommitSHA:     record.HeadCommitSHA,
				TerminationReason: record.TerminationReason,
				Error:             "acta upload failed: " + uploadErr.Error(),
				TraceID:           record.TraceID,
				PromptSource:      record.PromptSource,
				PromptCaptured:    record.PromptCaptured,
				OTLPStatus:        record.OTLPStatus, OTLPError: record.OTLPError,
				RawOutputLimitBytes: record.RawOutputLimitBytes, RawOutputLimitExceeded: record.RawOutputLimitExceeded,
				WorkspaceDiffLimitBytes: record.WorkspaceDiffLimitBytes, WorkspaceDiffLimitExceeded: record.WorkspaceDiffLimitExceeded,
				ReasoningRedactionState: remoteRedactionState,
			},
		})
		if markErr != nil {
			return errors.Join(uploadErr, fmt.Errorf("mark partial run failed: %w", markErr))
		}
		return uploadErr
	}

	if err := client.postJSON(ctx, "/api/ingest/runs", createRunRequest{
		RunID:          record.ID,
		OrganizationID: organizationID,
		RepositoryID:   repositoryID,
		Status:         "running",
		Agent:          record.Agent,
		Model:          record.Model,
		Source:         actaevents.Source,
		StartedAt:      record.StartedAt,
		Metadata:       buildRunMetadata(record, remoteRedactionState),
	}); err != nil {
		return fmt.Errorf("create run: %w", err)
	}
	if err := client.postEventsFromFile(ctx, record.ID, eventFile); err != nil {
		return fmt.Errorf("upload events: %w", markUploadFailed(err))
	}
	for _, artifact := range artifacts {
		if artifact.Withheld {
			continue
		}
		if err := client.postArtifact(ctx, record.ID, artifact); err != nil {
			return fmt.Errorf("upload artifact %s: %w", artifact.Filename, markUploadFailed(err))
		}
	}

	if err := client.postJSON(ctx, completePath, completeRunRequest{
		Status:      status,
		CompletedAt: record.CompletedAt,
		Metadata: completionMetadata{
			OK:                record.OK,
			Timeout:           record.Timeout,
			DurationMillis:    record.DurationMillis,
			ExitCode:          record.ExitCode,
			HeadCommitSHA:     record.HeadCommitSHA,
			TerminationReason: record.TerminationReason,
			Error:             record.Error,
			TraceID:           record.TraceID,
			PromptSource:      record.PromptSource,
			PromptCaptured:    record.PromptCaptured,
			OTLPStatus:        record.OTLPStatus, OTLPError: record.OTLPError,
			RawOutputLimitBytes: record.RawOutputLimitBytes, RawOutputLimitExceeded: record.RawOutputLimitExceeded,
			WorkspaceDiffLimitBytes: record.WorkspaceDiffLimitBytes, WorkspaceDiffLimitExceeded: record.WorkspaceDiffLimitExceeded,
			ReasoningRedactionState: remoteRedactionState,
		},
	}); err != nil {
		return fmt.Errorf("complete run: %w", err)
	}

	return nil
}

type client struct {
	baseURL     string
	token       string
	httpClient  *http.Client
	retryDelays []time.Duration
}

func clientFromConfig(cfg Config) client {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	// API endpoints are canonical and must not redirect. Besides making POST
	// retry semantics ambiguous, Go may forward Authorization to an HTTP
	// redirect on the same hostname, bypassing ValidateBackendURL's TLS check.
	hardenedClient := *httpClient
	hardenedClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	retryDelays := cfg.RetryDelays
	if retryDelays == nil {
		retryDelays = []time.Duration{250 * time.Millisecond, 750 * time.Millisecond, 1500 * time.Millisecond}
	}
	return client{
		baseURL:     strings.TrimRight(cfg.BackendURL, "/"),
		token:       strings.TrimSpace(cfg.ReportToken),
		httpClient:  &hardenedClient,
		retryDelays: retryDelays,
	}
}

// ValidateBackendURL normalizes an upload base URL and requires authenticated
// production traffic to use TLS unless the caller explicitly opts into HTTP.
func ValidateBackendURL(raw string, allowInsecureHTTP bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("backend URL is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil {
		return "", errors.New("backend URL must be an absolute HTTP(S) URL without user information")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		host := parsed.Hostname()
		ip := net.ParseIP(host)
		loopback := strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback()
		if !loopback && !allowInsecureHTTP {
			return "", errors.New("backend URL must use HTTPS outside loopback; pass --allow-insecure-http only for trusted development networks")
		}
	default:
		return "", errors.New("backend URL must use HTTP or HTTPS")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("backend URL must not contain a query or fragment")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func (c client) postJSON(ctx context.Context, path string, body any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	return c.retry(ctx, func() error {
		return c.postOnce(ctx, path, payload)
	})
}

func (c client) postEventsFromFile(ctx context.Context, runID string, file *os.File) error {
	path := "/api/ingest/runs/" + url.PathEscape(runID) + "/events"
	batcher, err := newEventBatcher(maxEventsRequestBytes)
	if err != nil {
		return err
	}
	postBatch := func(batch []actaevents.Event) error {
		if len(batch) == 0 {
			return nil
		}
		return c.postJSON(ctx, path, eventsRequest{Events: batch})
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind event snapshot: %w", err)
	}
	_, err = scanEventsFile(ctx, file, runID, func(event actaevents.Event) error {
		batch, err := batcher.add(event)
		if err != nil {
			return err
		}
		return postBatch(batch)
	})
	if err != nil {
		return err
	}
	return postBatch(batcher.flush())
}

type eventBatcher struct {
	maxBytes int
	bytes    int
	events   []actaevents.Event
}

func newEventBatcher(maxBytes int) (*eventBatcher, error) {
	if maxBytes <= eventsEnvelopeBytes {
		return nil, fmt.Errorf("event batch limit %d is too small", maxBytes)
	}
	return &eventBatcher{maxBytes: maxBytes, bytes: eventsEnvelopeBytes}, nil
}

// add returns a completed batch when event starts the next one. The event is
// retained by the batcher and will be returned by a later add or flush call.
func (b *eventBatcher) add(event actaevents.Event) ([]actaevents.Event, error) {
	encoded, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("size event sequence %d: %w", event.Sequence, err)
	}
	eventBytes := len(encoded)
	if eventsEnvelopeBytes+eventBytes > b.maxBytes {
		return nil, fmt.Errorf("event sequence %d exceeds max batch size", event.Sequence)
	}

	additionalBytes := eventBytes
	if len(b.events) > 0 {
		additionalBytes++ // comma between array elements
	}
	var completed []actaevents.Event
	if len(b.events) > 0 && b.bytes+additionalBytes > b.maxBytes {
		completed = b.flush()
		additionalBytes = eventBytes
	}
	b.events = append(b.events, event)
	b.bytes += additionalBytes
	return completed, nil
}

func (b *eventBatcher) flush() []actaevents.Event {
	batch := b.events
	b.events = nil
	b.bytes = eventsEnvelopeBytes
	return batch
}

func (c client) postArtifact(ctx context.Context, runID string, artifact artifactUpload) error {
	values := url.Values{}
	values.Set("kind", artifact.Kind)
	values.Set("filename", artifact.Filename)
	values.Set("content_type", artifact.ContentType)
	values.Set("size_bytes", fmt.Sprintf("%d", artifact.SizeBytes))
	values.Set("sha256", artifact.SHA256)
	if artifact.Compression != "" {
		values.Set("compression", artifact.Compression)
	}
	if artifact.SchemaVersion != nil {
		values.Set("schema_version", fmt.Sprintf("%d", *artifact.SchemaVersion))
	}
	values.Set("redaction_state", artifact.RedactionState)
	path := "/api/ingest/runs/" + url.PathEscape(runID) + "/artifacts?" + values.Encode()

	return c.retry(ctx, func() error {
		return c.postArtifactOnce(ctx, path, artifact)
	})
}

func (c client) retry(ctx context.Context, operation func() error) error {
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			delay := c.retryDelays[attempt-1]
			if delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
				}
			}
		}

		err := operation()
		if err == nil || !isTransient(err) || attempt == len(c.retryDelays) {
			return err
		}
	}
}

func (c client) postOnce(ctx context.Context, path string, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return transientError{err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	err = fmt.Errorf("backend returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return transientError{err: err}
	}
	return err
}

func (c client) postArtifactOnce(ctx context.Context, path string, artifact artifactUpload) error {
	reader := io.NewSectionReader(artifact.File, 0, artifact.SizeBytes)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.ContentLength = artifact.SizeBytes
	req.Header.Set("Content-Type", artifact.ContentType)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return transientError{err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	err = fmt.Errorf("backend returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return transientError{err: err}
	}
	return err
}

type transientError struct {
	err error
}

func (e transientError) Error() string {
	return e.err.Error()
}

func (e transientError) Unwrap() error {
	return e.err
}

func isTransient(err error) bool {
	var transient transientError
	return errors.As(err, &transient)
}

func terminalArtifactRefsFromFile(ctx context.Context, file *os.File, record *runrecord.Record) ([]actaevents.ArtifactRef, error) {
	var terminalSeen bool
	var terminalType string
	var terminalRefs []actaevents.ArtifactRef
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind event snapshot: %w", err)
	}
	if _, err := scanEventsFile(ctx, file, record.ID, func(event actaevents.Event) error {
		if event.SchemaVersion >= 2 && event.Producer != record.Producer {
			return fmt.Errorf("event producer does not match run record producer")
		}
		if event.SchemaVersion >= 2 && event.Type == actaevents.TypeRunStarted {
			var started struct {
				Agent               string `json:"agent"`
				AgentVersion        string `json:"agent_version"`
				AgentConfigMode     string `json:"agent_config_mode"`
				RuntimeBundleSHA256 string `json:"runtime_bundle_sha256"`
			}
			if err := json.Unmarshal(event.Payload, &started); err != nil {
				return fmt.Errorf("decode run.started payload: %w", err)
			}
			if started.Agent != record.Agent || started.AgentVersion != record.AgentVersion || started.AgentConfigMode != record.AgentConfigMode || started.RuntimeBundleSHA256 != record.RuntimeBundleSHA256 {
				return fmt.Errorf("run.started agent/runtime metadata does not match run record")
			}
		}
		if event.Type == actaevents.TypeRunCompleted || event.Type == actaevents.TypeRunFailed {
			terminalSeen = true
			terminalType = event.Type
			terminalRefs = dedupeArtifactRefs(event.ArtifactRefs)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if !terminalSeen {
		return nil, fmt.Errorf("%s has no terminal run event", actaevents.Filename)
	}
	expectedType := actaevents.TypeRunFailed
	if record.OK {
		expectedType = actaevents.TypeRunCompleted
	}
	if terminalType != expectedType {
		return nil, fmt.Errorf("terminal event type %q does not match recorded run outcome %q", terminalType, expectedType)
	}
	return terminalRefs, nil
}

func scanEvents(runDir string, runID string, visit func(actaevents.Event) error) (int, error) {
	path := filepath.Join(runDir, actaevents.Filename)
	file, err := securefile.OpenRegular(runDir, path)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", actaevents.Filename, err)
	}
	defer file.Close()
	return scanEventsFile(context.Background(), file, runID, visit)
}

func scanEventsFile(ctx context.Context, file *os.File, runID string, visit func(actaevents.Event) error) (int, error) {
	count := 0
	streamSchema := 0
	var streamProducer runrecord.Producer
	var streamRegeneratedBy runrecord.Producer
	streamWasRegenerated := false
	startedSeen := false
	terminalSeen := false
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), maxEventsRequestBytes)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) > 0 {
			if terminalSeen {
				return 0, fmt.Errorf("event appears after terminal run event")
			}
			count++
			var event actaevents.Event
			if err := decodeUploadEvent(line, &event); err != nil {
				return 0, fmt.Errorf("decode %s: %w", actaevents.Filename, err)
			}
			if err := actaevents.ValidateEvent(event, runID, count); err != nil {
				return 0, err
			}
			eventWasRegenerated := event.RegeneratedBy != nil
			if streamSchema == 0 {
				streamSchema, streamProducer = event.SchemaVersion, event.Producer
				streamWasRegenerated = eventWasRegenerated
				if streamWasRegenerated {
					streamRegeneratedBy = *event.RegeneratedBy
				}
			} else if event.SchemaVersion != streamSchema {
				return 0, fmt.Errorf("event sequence %d schema_version %d does not match stream schema_version %d", event.Sequence, event.SchemaVersion, streamSchema)
			} else if event.SchemaVersion >= 2 && event.Producer != streamProducer {
				return 0, fmt.Errorf("event sequence %d producer does not match stream producer", event.Sequence)
			} else if eventWasRegenerated != streamWasRegenerated || eventWasRegenerated && *event.RegeneratedBy != streamRegeneratedBy {
				return 0, fmt.Errorf("event sequence %d regenerated_by does not match stream regenerated_by", event.Sequence)
			}
			if event.Timestamp.IsZero() {
				return 0, fmt.Errorf("event sequence %d has no timestamp", event.Sequence)
			}
			if strings.TrimSpace(event.Type) == "" {
				return 0, fmt.Errorf("event sequence %d has no type", event.Sequence)
			}
			switch event.Type {
			case actaevents.TypeAgentPrompt:
				if count != 1 || startedSeen {
					return 0, fmt.Errorf("agent.prompt must appear at most once before run.started")
				}
			case actaevents.TypeRunStarted:
				if startedSeen {
					return 0, fmt.Errorf("event stream contains multiple run.started events")
				}
				startedSeen = true
			case actaevents.TypeRunCompleted, actaevents.TypeRunFailed:
				if !startedSeen {
					return 0, fmt.Errorf("terminal event appears before run.started")
				}
				terminalSeen = true
			default:
				if !startedSeen {
					return 0, fmt.Errorf("event type %q appears before run.started", event.Type)
				}
			}
			if visit != nil {
				if err := visit(event); err != nil {
					return 0, err
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("read %s (maximum line size %d bytes): %w", actaevents.Filename, maxEventsRequestBytes, err)
	}
	if count == 0 {
		return 0, fmt.Errorf("%s contains no events", actaevents.Filename)
	}
	if !startedSeen || !terminalSeen {
		return 0, fmt.Errorf("%s must contain one run.started event and one final terminal event", actaevents.Filename)
	}
	return count, nil
}

type uploadEventEnvelope struct {
	SchemaVersion json.RawMessage     `json:"schema_version"`
	Producer      runrecord.Producer  `json:"producer"`
	RegeneratedBy *runrecord.Producer `json:"regenerated_by"`
	RunID         json.RawMessage     `json:"run_id"`
	Sequence      json.RawMessage     `json:"sequence"`
	Timestamp     json.RawMessage     `json:"timestamp"`
	Source        json.RawMessage     `json:"source"`
	Type          json.RawMessage     `json:"type"`
	Payload       json.RawMessage     `json:"payload"`
	ArtifactRefs  []json.RawMessage   `json:"artifact_refs"`
}

type uploadArtifactRef struct {
	Kind           json.RawMessage `json:"kind"`
	Path           json.RawMessage `json:"path"`
	Lines          json.RawMessage `json:"lines"`
	Status         json.RawMessage `json:"status"`
	Reason         json.RawMessage `json:"reason"`
	RedactionState json.RawMessage `json:"redaction_state"`
}

func decodeUploadEvent(line []byte, event *actaevents.Event) error {
	var envelope uploadEventEnvelope
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return err
	}
	for index, rawRef := range envelope.ArtifactRefs {
		decoder = json.NewDecoder(bytes.NewReader(rawRef))
		decoder.DisallowUnknownFields()
		var ref uploadArtifactRef
		if err := decoder.Decode(&ref); err != nil {
			return fmt.Errorf("artifact_refs[%d]: %w", index, err)
		}
	}
	return json.Unmarshal(line, event)
}

func dedupeArtifactRefs(refs []actaevents.ArtifactRef) []actaevents.ArtifactRef {
	seen := map[string]bool{}
	out := make([]actaevents.ArtifactRef, 0, len(refs))
	for _, ref := range refs {
		key := ref.Kind + "\x00" + ref.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ref)
	}
	return out
}

func prepareUploadSnapshotContext(ctx context.Context, record *runrecord.Record, maxBytes int64, redactReasoning bool, maxRedactionLineBytes int, hook func(int)) (*os.File, string, []artifactUpload, *runrecord.Record, error) {
	for attempt := 1; attempt <= maxProjectionSnapshotAttempts; attempt++ {
		snapshots, _, retry, err := snapshotProjectionArtifactsContext(ctx, record.RunDir, maxBytes, attempt, hook)
		if err != nil {
			return nil, "", nil, nil, err
		}
		if retry {
			continue
		}
		snapshotRecord := record
		if snapshot, ok := snapshots["run.json"]; ok {
			payload, readErr := readBoundedFile(snapshot.File, runrecord.MaxRecordBytes)
			if readErr != nil {
				closeArtifactSnapshots(snapshots)
				return nil, "", nil, nil, fmt.Errorf("read manifested run record: %w", readErr)
			}
			var decoded runrecord.Record
			if err := json.Unmarshal(payload, &decoded); err != nil {
				closeArtifactSnapshots(snapshots)
				return nil, "", nil, nil, fmt.Errorf("parse manifested run record: %w", err)
			}
			if err := decoded.Validate(); err != nil {
				closeArtifactSnapshots(snapshots)
				return nil, "", nil, nil, fmt.Errorf("validate manifested run record: %w", err)
			}
			decoded.RunDir = record.RunDir
			snapshotRecord = &decoded
		}
		if redactReasoning && (snapshotRecord.ReasoningRedactionState == "failed" || snapshotRecord.ReasoningRedactionState == "partial") {
			closeArtifactSnapshots(snapshots)
			return nil, "", nil, nil, errors.New("remote upload refused because local reasoning redaction did not complete; pass --allow-unredacted-remote-reasoning to explicitly upload the unredacted bundle")
		}
		eventSnapshot := snapshots[actaevents.Filename]
		artifactRefs, err := terminalArtifactRefsFromFile(ctx, eventSnapshot.File, snapshotRecord)
		if err != nil {
			closeArtifactSnapshots(snapshots)
			return nil, "", nil, nil, err
		}
		if redactReasoning {
			if _, err := redactArtifactSnapshot(ctx, eventSnapshot.File, "event_stream", actaevents.Filename, maxRedactionLineBytes); err != nil {
				closeArtifactSnapshots(snapshots)
				return nil, "", nil, nil, fmt.Errorf("redact reasoning from event snapshot: %w", err)
			}
			if _, err := scanEventsFile(ctx, eventSnapshot.File, snapshotRecord.ID, nil); err != nil {
				closeArtifactSnapshots(snapshots)
				return nil, "", nil, nil, fmt.Errorf("validate redacted replay event snapshot: %w", err)
			}
		}
		artifacts, err := buildArtifactsContext(ctx, snapshotRecord.RunDir, artifactRefs, eventSnapshot.File, eventSnapshot.TempPath, snapshots, maxBytes, redactReasoning, maxRedactionLineBytes)
		if err != nil {
			closeArtifactSnapshots(snapshots)
			return nil, "", nil, nil, err
		}
		closeUnusedArtifactSnapshots(snapshots, eventSnapshot.File, artifacts)
		return eventSnapshot.File, eventSnapshot.TempPath, artifacts, snapshotRecord, nil
	}
	return nil, "", nil, nil, fmt.Errorf("torn bundle: projection generation changed while opening artifacts after %d attempts", maxProjectionSnapshotAttempts)
}

func snapshotProjectionArtifactsContext(ctx context.Context, runDir string, maxBytes int64, attempt int, hook func(int)) (map[string]artifactSnapshot, bool, bool, error) {
	resolvedRunDir, err := filepath.EvalSymlinks(runDir)
	if err != nil {
		return nil, false, false, fmt.Errorf("resolve run directory: %w", err)
	}
	manifestPath := filepath.Join(runDir, "projection.json")
	manifestFile, err := openManifestedProjectionRegular(resolvedRunDir, manifestPath)
	if errors.Is(err, os.ErrNotExist) {
		if hook != nil {
			hook(attempt)
		}
		snapshots, retry, snapshotErr := snapshotLegacyProjectionArtifactsContext(ctx, resolvedRunDir, runDir, manifestPath, maxBytes)
		return snapshots, false, retry, snapshotErr
	}
	if err != nil {
		return nil, false, false, fmt.Errorf("open projection manifest: %w", err)
	}
	defer manifestFile.Close()
	manifestInfo, err := manifestFile.Stat()
	if err != nil {
		return nil, false, false, fmt.Errorf("stat projection manifest: %w", err)
	}
	manifestPayload, err := readBoundedFile(manifestFile, maxProjectionManifestBytes)
	if err != nil {
		return nil, false, false, fmt.Errorf("read projection manifest: %w", err)
	}
	manifest, err := decodeProjectionManifest(manifestPayload)
	if err != nil {
		return nil, false, false, err
	}
	manifestHash := sha256.Sum256(manifestPayload)
	if hook != nil {
		hook(attempt)
	}

	expectedHashes := map[string]string{
		"digest.json":       manifest.DigestSHA256,
		actaevents.Filename: manifest.EventsSHA256,
	}
	if manifest.RunSHA256 != "" {
		expectedHashes["run.json"] = manifest.RunSHA256
	}
	sources := make(map[string]*os.File, len(expectedHashes))
	defer func() {
		for _, source := range sources {
			_ = source.Close()
		}
	}()
	for _, name := range []string{"run.json", "digest.json", actaevents.Filename} {
		if _, ok := expectedHashes[name]; !ok {
			continue
		}
		source, openErr := openManifestedProjectionRegular(resolvedRunDir, filepath.Join(runDir, name))
		if openErr != nil {
			if err := ctx.Err(); err != nil {
				return nil, false, false, err
			}
			return nil, true, true, nil
		}
		sources[name] = source
	}
	same, err := projectionManifestUnchanged(resolvedRunDir, manifestPath, manifestInfo, manifestHash)
	if err != nil {
		return nil, true, false, err
	}
	if !same {
		return nil, true, true, nil
	}

	snapshots, snapshotErr := snapshotProjectionSourcesContext(ctx, sources, maxBytes, expectedHashes)
	if snapshotErr != nil {
		if strings.Contains(snapshotErr.Error(), "does not match projection manifest") {
			return nil, true, true, nil
		}
		return nil, true, false, snapshotErr
	}
	return snapshots, true, false, nil
}

func snapshotLegacyProjectionArtifactsContext(ctx context.Context, resolvedRunDir, runDir, manifestPath string, maxBytes int64) (snapshots map[string]artifactSnapshot, retry bool, returnErr error) {
	lock, err := actaevents.AcquireProjectionLockContext(ctx, runDir)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, false, fmt.Errorf("projection lock held; upload cancelled/timed out: %w", err)
		}
		lockFree, probeErr := legacyProjectionLockFreeAllowed(runDir, err)
		if probeErr != nil {
			return nil, false, probeErr
		}
		if !lockFree {
			return nil, false, fmt.Errorf("lock legacy projection snapshot: %w", err)
		}
		slog.DebugContext(ctx, "uploading legacy projection without lock because bundle is not writable", "run_dir", runDir, "error", err)
	}
	recovered := false
	if lock != nil {
		defer func() {
			returnErr = errors.Join(returnErr, lock.Close())
		}()
		var recoverErr error
		recovered, recoverErr = actaevents.RecoverProjectionCommit(runDir)
		if recoverErr != nil {
			return nil, false, fmt.Errorf("torn bundle: recover interrupted projection commit: %w", recoverErr)
		}
	} else {
		pending, pendingErr := actaevents.ProjectionCommitRecoveryPending(runDir)
		if pendingErr != nil {
			return nil, false, fmt.Errorf("inspect legacy projection commit debris: %w", pendingErr)
		}
		if pending {
			return nil, false, errors.New("torn bundle: interrupted projection commit requires recovery, but the legacy bundle cannot be locked")
		}
	}
	if _, err := os.Stat(manifestPath); err == nil {
		return nil, true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("re-stat projection manifest: %w", err)
	}
	sources := make(map[string]*os.File, 3)
	defer func() {
		for _, source := range sources {
			_ = source.Close()
		}
	}()
	names := []string{actaevents.Filename, "digest.json"}
	if recovered {
		names = append(names, "run.json")
	}
	for _, name := range names {
		source, openErr := securefile.OpenRegular(resolvedRunDir, filepath.Join(runDir, name))
		if openErr != nil {
			if name == "digest.json" && errors.Is(openErr, os.ErrNotExist) {
				continue
			}
			if _, statErr := os.Stat(manifestPath); statErr == nil {
				return nil, true, nil
			}
			return nil, false, openErr
		}
		sources[name] = source
	}

	snapshots, err = snapshotProjectionSourcesContext(ctx, sources, maxBytes, nil)
	if err != nil {
		return nil, false, err
	}
	if _, err := os.Stat(manifestPath); err == nil {
		closeArtifactSnapshots(snapshots)
		return nil, true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		closeArtifactSnapshots(snapshots)
		return nil, false, fmt.Errorf("re-stat projection manifest: %w", err)
	}
	return snapshots, false, nil
}

func snapshotProjectionSourcesContext(ctx context.Context, sources map[string]*os.File, maxBytes int64, expectedHashes map[string]string) (map[string]artifactSnapshot, error) {
	var remaining *int64
	if maxBytes > 0 {
		remaining = &maxBytes
	}
	snapshots := make(map[string]artifactSnapshot, len(sources))
	for _, name := range []string{actaevents.Filename, "run.json", "digest.json"} {
		if sources[name] == nil {
			continue
		}
		file, tempPath, err := snapshotOpenFileBudgetContext(ctx, sources[name], remaining, expectedHashes[name])
		if err != nil {
			closeArtifactSnapshots(snapshots)
			return nil, err
		}
		snapshots[name] = artifactSnapshot{File: file, TempPath: tempPath}
	}
	return snapshots, nil
}

func legacyProjectionLockFreeAllowed(runDir string, lockErr error) (bool, error) {
	return legacyProjectionLockFreeAllowedWithProbe(runDir, lockErr, projectionDirectoryWritable)
}

func legacyProjectionLockFreeAllowedWithProbe(runDir string, lockErr error, writableProbe func(string) (bool, error)) (bool, error) {
	if errors.Is(lockErr, syscall.EROFS) {
		return true, nil
	}
	if !errors.Is(lockErr, syscall.EACCES) {
		return false, nil
	}
	writable, err := writableProbe(runDir)
	if err != nil {
		return false, fmt.Errorf("probe bundle directory writability after projection lock permission error: %w", err)
	}
	return !writable, nil
}

func projectionManifestUnchanged(root, path string, firstInfo os.FileInfo, firstHash [sha256.Size]byte) (bool, error) {
	current, err := openManifestedProjectionRegular(root, path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reopen projection manifest: %w", err)
	}
	defer current.Close()
	payload, err := readBoundedFile(current, maxProjectionManifestBytes)
	if err != nil {
		return false, fmt.Errorf("re-read projection manifest: %w", err)
	}
	currentInfo, err := current.Stat()
	if err != nil {
		return false, fmt.Errorf("re-stat opened projection manifest: %w", err)
	}
	pathInfo, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("re-stat projection manifest path: %w", err)
	}
	return os.SameFile(firstInfo, currentInfo) && os.SameFile(currentInfo, pathInfo) && firstHash == sha256.Sum256(payload), nil
}

func decodeProjectionManifest(payload []byte) (projectionManifest, error) {
	var manifest projectionManifest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, fmt.Errorf("decode projection manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return manifest, errors.New("decode projection manifest: trailing JSON value")
	}
	if manifest.SchemaVersion < actaevents.MinProjectionSchemaVersion || manifest.SchemaVersion > actaevents.ProjectionSchemaVersion {
		return manifest, fmt.Errorf("projection manifest has unsupported schema_version %d", manifest.SchemaVersion)
	}
	if strings.TrimSpace(manifest.Producer.Name) == "" || strings.TrimSpace(manifest.Producer.Version) == "" {
		return manifest, errors.New("projection manifest producer name and version are required")
	}
	if manifest.Generation == "" || strings.Trim(manifest.Generation, "0123456789") != "" {
		return manifest, errors.New("projection manifest generation must contain only digits")
	}
	if manifest.SchemaVersion == actaevents.ProjectionSchemaVersion && manifest.RunSHA256 == "" {
		return manifest, errors.New("projection manifest run_sha256 is required")
	}
	if manifest.SchemaVersion < actaevents.ProjectionSchemaVersion && manifest.RunSHA256 != "" {
		return manifest, errors.New("projection manifest run_sha256 requires schema_version 3")
	}
	hashes := map[string]string{"digest_sha256": manifest.DigestSHA256, "events_sha256": manifest.EventsSHA256}
	if manifest.RunSHA256 != "" {
		hashes["run_sha256"] = manifest.RunSHA256
	}
	for name, value := range hashes {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != sha256.Size || value != strings.ToLower(value) {
			return manifest, fmt.Errorf("projection manifest %s must be a lowercase SHA-256 digest", name)
		}
	}
	return manifest, nil
}

func readBoundedFile(file *os.File, maxBytes int64) ([]byte, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > maxBytes {
		return nil, fmt.Errorf("file exceeds %d-byte limit", maxBytes)
	}
	return payload, nil
}

func closeArtifactSnapshots(snapshots map[string]artifactSnapshot) {
	for _, snapshot := range snapshots {
		if snapshot.File != nil {
			_ = snapshot.File.Close()
		}
		if snapshot.TempPath != "" {
			_ = os.Remove(snapshot.TempPath)
		}
	}
}

func closeUnusedArtifactSnapshots(snapshots map[string]artifactSnapshot, eventFile *os.File, artifacts []artifactUpload) {
	used := map[*os.File]bool{eventFile: true}
	for _, artifact := range artifacts {
		used[artifact.File] = true
	}
	for _, snapshot := range snapshots {
		if !used[snapshot.File] {
			_ = snapshot.File.Close()
			_ = os.Remove(snapshot.TempPath)
		}
	}
}

func buildArtifactsContext(ctx context.Context, runDir string, refs []actaevents.ArtifactRef, eventFile *os.File, eventTempPath string, snapshots map[string]artifactSnapshot, maxBytes int64, redactReasoning bool, maxRedactionLineBytes int) ([]artifactUpload, error) {
	resolvedRunDir, err := filepath.EvalSymlinks(runDir)
	if err != nil {
		return nil, fmt.Errorf("resolve run directory: %w", err)
	}
	artifacts := make([]artifactUpload, 0, len(refs))
	var eventSnapshotBytes int64
	if maxBytes > 0 {
		if eventFile != nil {
			info, statErr := eventFile.Stat()
			if statErr != nil {
				return nil, fmt.Errorf("stat event snapshot: %w", statErr)
			}
			eventSnapshotBytes = info.Size()
		}
		plannedBytes := eventSnapshotBytes
		if plannedBytes > maxBytes {
			return nil, fmt.Errorf("artifact snapshot is %d bytes; maximum is %d", plannedBytes, maxBytes)
		}
		for _, ref := range refs {
			if isCanonicalEventArtifact(ref.Path) && eventFile != nil {
				continue
			} else if snapshot, ok := snapshots[ref.Path]; ok {
				info, statErr := snapshot.File.Stat()
				if statErr != nil {
					return nil, fmt.Errorf("stat artifact snapshot %s: %w", ref.Path, statErr)
				}
				plannedBytes += info.Size()
			} else {
				plannedPath, pathErr := artifactPath(runDir, ref.Path)
				if pathErr != nil {
					return nil, pathErr
				}
				info, statErr := os.Lstat(plannedPath)
				if statErr != nil {
					return nil, fmt.Errorf("stat artifact %s: %w", ref.Path, statErr)
				}
				plannedBytes += info.Size()
			}
			if plannedBytes > maxBytes {
				return nil, fmt.Errorf("artifact snapshot is %d bytes; maximum is %d", plannedBytes, maxBytes)
			}
		}
	}
	totalBytes := eventSnapshotBytes
	for _, ref := range refs {
		path, err := artifactPath(runDir, ref.Path)
		if err != nil {
			closeArtifacts(artifacts)
			return nil, err
		}
		var file *os.File
		var tempPath string
		redactionRequired := true
		redactionVerified := true
		if isCanonicalEventArtifact(ref.Path) && eventFile != nil {
			file, tempPath = eventFile, eventTempPath
			redactionRequired = true
		} else if snapshot, ok := snapshots[ref.Path]; ok {
			file, tempPath = snapshot.File, snapshot.TempPath
		} else {
			remaining := int64(0)
			if maxBytes > 0 {
				remaining = maxBytes - totalBytes
			}
			file, tempPath, err = snapshotRegularFile(ctx, resolvedRunDir, path, remaining)
			if err != nil {
				closeArtifacts(artifacts)
				return nil, fmt.Errorf("snapshot artifact %s: %w", ref.Path, err)
			}
		}
		if redactReasoning {
			redactionVerified, err = redactArtifactSnapshot(ctx, file, ref.Kind, ref.Path, maxRedactionLineBytes)
			if err != nil {
				if tempPath != eventTempPath {
					_ = file.Close()
					_ = os.Remove(tempPath)
				}
				closeArtifacts(artifacts)
				return nil, fmt.Errorf("redact reasoning from artifact %s: %w", ref.Path, err)
			}
		}
		if !redactReasoning {
			inspection, inspectErr := inspectArtifactSnapshot(ctx, file, ref.Kind, ref.Path, maxRedactionLineBytes)
			if inspectErr != nil {
				if tempPath != eventTempPath {
					_ = file.Close()
					_ = os.Remove(tempPath)
				}
				closeArtifacts(artifacts)
				return nil, fmt.Errorf("inspect reasoning in artifact %s: %w", ref.Path, inspectErr)
			}
			redactionRequired = inspection.ContainsReasoning || !inspection.Verified
			redactionVerified = inspection.Verified
		}
		sha256Hex, sizeBytes, err := hashFileContext(ctx, file)
		if err != nil {
			_ = file.Close()
			closeArtifacts(artifacts)
			return nil, fmt.Errorf("hash artifact %s: %w", ref.Path, err)
		}
		if !isCanonicalEventArtifact(ref.Path) || eventFile == nil {
			totalBytes += sizeBytes
		}
		if maxBytes > 0 && totalBytes > maxBytes {
			if tempPath != eventTempPath {
				_ = file.Close()
				_ = os.Remove(tempPath)
			}
			closeArtifacts(artifacts)
			return nil, fmt.Errorf("artifact snapshot is %d bytes; maximum is %d", totalBytes, maxBytes)
		}
		artifactRedactionState := "not_required"
		withheld := false
		switch {
		case !redactReasoning && redactionRequired:
			artifactRedactionState = "unredacted"
		case redactReasoning && !redactionVerified:
			artifactRedactionState = "unverified"
			withheld = true
		case redactReasoning && redactionRequired:
			artifactRedactionState = "redacted"
		}
		artifact := artifactUpload{
			Kind:           ref.Kind,
			Filename:       ref.Path,
			ContentType:    contentType(ref.Path),
			SizeBytes:      sizeBytes,
			SHA256:         sha256Hex,
			Compression:    compression(ref.Path),
			RedactionState: artifactRedactionState,
			File:           file,
			TempPath:       tempPath,
			Withheld:       withheld,
		}
		if isCanonicalEventArtifact(ref.Path) {
			schemaVersion, schemaErr := eventArtifactSchemaVersionContext(ctx, file)
			if schemaErr != nil {
				if tempPath != eventTempPath {
					_ = file.Close()
					_ = os.Remove(tempPath)
				}
				closeArtifacts(artifacts)
				return nil, fmt.Errorf("read schema version from artifact %s: %w", ref.Path, schemaErr)
			}
			artifact.SchemaVersion = &schemaVersion
		}
		artifacts = append(artifacts, artifact)
	}
	return artifacts, nil
}

func annotateWithheldArtifactRefsContext(ctx context.Context, eventFile *os.File, runID string, artifacts []artifactUpload) (bool, error) {
	withheld := make(map[string]artifactUpload)
	for _, artifact := range artifacts {
		if artifact.Withheld {
			withheld[artifact.Kind+"\x00"+artifact.Filename] = artifact
		}
	}
	if len(withheld) == 0 {
		return false, nil
	}
	if _, err := eventFile.Seek(0, io.SeekStart); err != nil {
		return false, fmt.Errorf("rewind event snapshot for withheld artifact annotations: %w", err)
	}

	annotated, err := os.CreateTemp("", "acta-upload-events-withheld-*")
	if err != nil {
		return false, fmt.Errorf("create annotated event snapshot: %w", err)
	}
	annotatedPath := annotated.Name()
	defer func() {
		_ = annotated.Close()
		_ = os.Remove(annotatedPath)
	}()

	scanner := bufio.NewScanner(eventFile)
	scanner.Buffer(make([]byte, 64<<10), maxEventsRequestBytes)
	eventCount := 0
	totalBytes := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		eventCount++
		var event actaevents.Event
		if err := json.Unmarshal(line, &event); err != nil {
			return false, fmt.Errorf("decode %s for withheld artifact annotations: %w", actaevents.Filename, err)
		}
		if err := rejectUnsupportedFutureDocumentVersion(schemaversion.Event, &event); err != nil {
			return false, err
		}
		for i := range event.ArtifactRefs {
			ref := &event.ArtifactRefs[i]
			artifact, ok := withheld[ref.Kind+"\x00"+ref.Path]
			if !ok {
				continue
			}
			ref.Status = actaevents.ArtifactStatusWithheld
			ref.Reason = withheldArtifactReason
			ref.RedactionState = artifact.RedactionState
		}
		if _, err := stampRewrittenDocumentSchemaVersion(schemaversion.Event, &event, true); err != nil {
			return false, fmt.Errorf("upgrade event sequence %d after withheld artifact annotations: %w", event.Sequence, err)
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			return false, fmt.Errorf("encode event sequence %d with withheld artifact annotations: %w", event.Sequence, err)
		}
		if len(encoded)+1 > actaevents.MaxEventBytes {
			return false, fmt.Errorf("event sequence %d is %d bytes after withheld artifact annotations; maximum is %d", event.Sequence, len(encoded)+1, actaevents.MaxEventBytes)
		}
		totalBytes += len(encoded) + 1
		if totalBytes > actaevents.MaxStreamBytes {
			return false, fmt.Errorf("event stream exceeds maximum size %d after withheld artifact annotations", actaevents.MaxStreamBytes)
		}
		encoded = append(encoded, '\n')
		if n, writeErr := annotated.Write(encoded); writeErr != nil {
			return false, fmt.Errorf("write annotated event snapshot: %w", writeErr)
		} else if n != len(encoded) {
			return false, io.ErrShortWrite
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("read event snapshot for withheld artifact annotations: %w", err)
	}
	if eventCount == 0 {
		return false, fmt.Errorf("%s contains no events", actaevents.Filename)
	}
	if _, err := annotated.Seek(0, io.SeekStart); err != nil {
		return false, fmt.Errorf("rewind annotated event snapshot: %w", err)
	}
	if err := replaceSnapshotReaderContext(ctx, eventFile, annotated); err != nil {
		return false, fmt.Errorf("publish annotated event snapshot: %w", err)
	}
	if _, err := scanEventsFile(ctx, eventFile, runID, nil); err != nil {
		return false, fmt.Errorf("validate annotated replay event snapshot: %w", err)
	}
	return true, nil
}

func refreshEventArtifactContext(ctx context.Context, artifacts []artifactUpload, eventFile *os.File, maxBytes int64) error {
	info, err := eventFile.Stat()
	if err != nil {
		return fmt.Errorf("stat annotated event snapshot: %w", err)
	}
	totalBytes := info.Size()
	var eventRefreshed bool
	var eventSHA256 string
	var eventSizeBytes int64
	var eventSchemaVersion int32
	for i := range artifacts {
		artifact := &artifacts[i]
		if isCanonicalEventArtifact(artifact.Filename) {
			if !eventRefreshed {
				eventSHA256, eventSizeBytes, err = hashFileContext(ctx, eventFile)
				if err != nil {
					return fmt.Errorf("hash annotated event snapshot: %w", err)
				}
				eventSchemaVersion, err = eventArtifactSchemaVersionContext(ctx, eventFile)
				if err != nil {
					return fmt.Errorf("read schema version from annotated event snapshot: %w", err)
				}
				eventRefreshed = true
			}
			artifact.SHA256 = eventSHA256
			artifact.SizeBytes = eventSizeBytes
			artifact.SchemaVersion = &eventSchemaVersion
			continue
		}
		totalBytes += artifact.SizeBytes
	}
	if maxBytes > 0 && totalBytes > maxBytes {
		return fmt.Errorf("artifact snapshot is %d bytes after withheld artifact annotations; maximum is %d", totalBytes, maxBytes)
	}
	return nil
}

type artifactInspection struct {
	ContainsReasoning bool
	Verified          bool
}

type artifactJSONFormat uint8

const (
	artifactOpaque artifactJSONFormat = iota
	artifactJSONDocument
	artifactJSONLines
	artifactActaEventStream
)

func isCanonicalEventArtifact(path string) bool {
	return filepath.ToSlash(filepath.Clean(filepath.FromSlash(path))) == actaevents.Filename
}

func eventArtifactSchemaVersionContext(ctx context.Context, file *os.File) (int32, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	defer func() { _, _ = file.Seek(0, io.SeekStart) }()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), maxEventsRequestBytes)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var envelope struct {
			SchemaVersion int32 `json:"schema_version"`
		}
		if err := json.Unmarshal(line, &envelope); err != nil {
			return 0, err
		}
		if envelope.SchemaVersion == 0 {
			return 0, errors.New("event artifact has no schema_version")
		}
		return envelope.SchemaVersion, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("event artifact contains no events")
}

// redactArtifactSnapshot uses the declared path/kind only to select a structured
// schema. Everything else is opaque text: independently parseable JSON lines
// receive the provider privacy pass, while any JSON-shaped ambiguity is marked
// unverified so the caller can keep that artifact local-only.
func redactArtifactSnapshot(ctx context.Context, file *os.File, kind, path string, maxLineBytes int) (bool, error) {
	format := classifyArtifactJSON(kind, path)
	switch format {
	case artifactOpaque:
		return rewriteOpaqueTextSnapshot(ctx, file, maxLineBytes)
	case artifactJSONDocument:
		if isRunRecordArtifact(path) {
			return true, redactRunRecordSnapshot(ctx, file)
		}
		if isDigestArtifact(path) {
			return true, redactDigestSnapshot(ctx, file)
		}
		return true, redactJSONDocumentSnapshot(ctx, file)
	case artifactJSONLines:
		err := rewriteJSONLSnapshot(ctx, file, maxLineBytes, redactProviderReasoningLine)
		if errors.Is(err, errProviderRedactionUnverified) {
			return false, nil
		}
		return true, err
	case artifactActaEventStream:
		return true, redactActaEventSnapshot(ctx, file, maxLineBytes)
	default:
		return false, fmt.Errorf("unsupported artifact JSON format")
	}
}

func isRunRecordArtifact(path string) bool {
	return filepath.ToSlash(filepath.Clean(filepath.FromSlash(path))) == "run.json"
}

func isDigestArtifact(path string) bool {
	return filepath.ToSlash(filepath.Clean(filepath.FromSlash(path))) == "digest.json"
}

func classifyArtifactJSON(kind, path string) artifactJSONFormat {
	cleanPath := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if cleanPath == actaevents.Filename {
		return artifactActaEventStream
	}
	extension := strings.ToLower(filepath.Ext(cleanPath))
	switch extension {
	case ".jsonl":
		return artifactJSONLines
	case ".json":
		return artifactJSONDocument
	}

	// Kind is only a parser hint for declared structured artifacts. Opaque text
	// is never promoted by sniffing: its full contents are classified line by
	// line so a later multiline fragment cannot bypass the privacy boundary.
	switch kind {
	case "run_record", "digest":
		return artifactJSONDocument
	case "raw_stdout", "event_stream", "event_times":
		return artifactJSONLines
	}
	return artifactOpaque
}

func looksLikeJSON(first byte) bool {
	// Only containers can carry nested reasoning. Treating arbitrary log lines
	// beginning with a timestamp, '-', or a JSON scalar as JSON would reject
	// otherwise opaque stderr/workspace evidence without improving privacy.
	return first == '{' || first == '['
}

func rewriteOpaqueTextSnapshot(ctx context.Context, file *os.File, maxLineBytes int) (bool, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	if maxLineBytes <= 0 {
		return false, fmt.Errorf("maximum redaction line size must be positive")
	}
	temp, err := os.CreateTemp("", "acta-redacted-snapshot-*")
	if err != nil {
		return false, err
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}()
	reader := bufio.NewReaderSize(file, 64<<10)
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		line, readErr := readBoundedJSONLLine(reader, maxLineBytes)
		if errors.Is(readErr, errRedactionLineTooLong) {
			// An overlong opaque line cannot be classified within the configured
			// privacy bound. Keep the artifact local rather than failing the run.
			return false, nil
		}
		_, trimmed, _ := jsonLineParts(line)
		if opaqueLineHasJSONAmbiguity(trimmed) {
			return false, nil
		}
		output := line
		if len(trimmed) > 0 && looksLikeJSON(trimmed[0]) {
			var verified bool
			output, verified, err = redactProviderReasoningLineVerified(line)
			if err != nil {
				return false, err
			}
			if !verified {
				return false, nil
			}
		}
		if len(output) > 0 {
			if _, err := temp.Write(output); err != nil {
				return false, err
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				return false, readErr
			}
			break
		}
	}
	if err := temp.Sync(); err != nil {
		return false, err
	}
	if _, err := temp.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	if err := replaceSnapshotFromReader(ctx, file, temp); err != nil {
		return false, err
	}
	return true, nil
}

func opaqueLineHasJSONAmbiguity(trimmed []byte) bool {
	if len(trimmed) == 0 {
		return false
	}
	if looksLikeJSON(trimmed[0]) {
		return !json.Valid(trimmed)
	}
	if trimmed[0] == '}' || trimmed[0] == ']' {
		return true
	}
	if trimmed[0] == '"' {
		// Standalone strings, complete object members, and truncated members are
		// all valid continuations of a JSON container split across log lines.
		return true
	}
	return opaqueLineContainsJSONFragment(trimmed)
}

func opaqueLineContainsJSONFragment(line []byte) bool {
	for index := 0; index < len(line); index++ {
		char := line[index]
		switch char {
		case '{', '[', '}', ']':
			if jsonFragmentBoundaryBefore(line, index) {
				return true
			}
		case '"':
			end := jsonStringEnd(line, index)
			if end < 0 {
				return jsonFragmentBoundaryBefore(line, index) || lineHasReasoningDiscriminator(line)
			}
			after := bytes.TrimSpace(line[end+1:])
			if len(after) > 0 && after[0] == ':' {
				return true
			}
			if jsonFragmentBoundaryBefore(line, index) &&
				(len(after) == 0 || after[0] == ',' || after[0] == '}' || after[0] == ']') {
				return true
			}
			index = end
		}
	}
	return lineHasReasoningDiscriminator(line) && bytes.ContainsAny(line, "{}[]\",':")
}

func jsonFragmentBoundaryBefore(line []byte, index int) bool {
	for index > 0 {
		index--
		if line[index] == ' ' || line[index] == '\t' {
			continue
		}
		switch line[index] {
		case ':', ',', '{', '[':
			return true
		default:
			return false
		}
	}
	return true
}

func jsonStringEnd(line []byte, start int) int {
	escaped := false
	for index := start + 1; index < len(line); index++ {
		switch {
		case escaped:
			escaped = false
		case line[index] == '\\':
			escaped = true
		case line[index] == '"':
			return index
		}
	}
	return -1
}

func lineHasReasoningDiscriminator(line []byte) bool {
	lower := bytes.ToLower(line)
	for _, discriminator := range []string{"reasoning", "thinking", "redacted_thinking"} {
		for start := 0; start < len(lower); {
			index := bytes.Index(lower[start:], []byte(discriminator))
			if index < 0 {
				break
			}
			index += start
			end := index + len(discriminator)
			if (index == 0 || !isIdentifierByte(lower[index-1])) &&
				(end == len(lower) || !isIdentifierByte(lower[end])) {
				return true
			}
			start = end
		}
	}
	return false
}

func isIdentifierByte(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '_'
}

func inspectArtifactSnapshot(ctx context.Context, file *os.File, kind, path string, maxLineBytes int) (artifactInspection, error) {
	format := classifyArtifactJSON(kind, path)
	switch format {
	case artifactOpaque:
		return inspectOpaqueTextSnapshot(ctx, file, maxLineBytes)
	case artifactJSONDocument:
		return inspectJSONDocumentSnapshot(ctx, file, path, maxRedactionJSONDocumentBytes)
	case artifactJSONLines:
		return inspectJSONLinesSnapshot(ctx, file, maxLineBytes, inspectProviderValue)
	case artifactActaEventStream:
		return inspectJSONLinesSnapshot(ctx, file, maxLineBytes, inspectActaEventValue)
	default:
		return artifactInspection{}, fmt.Errorf("unsupported artifact JSON format")
	}
}

func inspectOpaqueTextSnapshot(ctx context.Context, file *os.File, maxLineBytes int) (artifactInspection, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return artifactInspection{}, err
	}
	defer func() { _, _ = file.Seek(0, io.SeekStart) }()
	if maxLineBytes <= 0 {
		return artifactInspection{}, fmt.Errorf("maximum redaction line size must be positive")
	}
	reader := bufio.NewReaderSize(file, 64<<10)
	inspection := artifactInspection{Verified: true}
	for {
		if err := ctx.Err(); err != nil {
			return artifactInspection{}, err
		}
		line, readErr := readBoundedJSONLLine(reader, maxLineBytes)
		if errors.Is(readErr, errRedactionLineTooLong) {
			inspection.Verified = false
			return inspection, nil
		}
		trimmed := bytes.TrimSpace(line)
		if opaqueLineHasJSONAmbiguity(trimmed) {
			inspection.Verified = false
			return inspection, nil
		}
		if len(trimmed) > 0 && looksLikeJSON(trimmed[0]) {
			var value any
			if err := decodeJSONUseNumber(trimmed, &value); err != nil {
				inspection.Verified = false
				return inspection, nil
			}
			containsReasoning, verified := reasoning.RedactValue(value, reasoning.ProviderTraversal())
			inspection.ContainsReasoning = containsReasoning || inspection.ContainsReasoning
			inspection.Verified = verified && inspection.Verified
		}
		if readErr != nil {
			if readErr != io.EOF {
				return artifactInspection{}, readErr
			}
			return inspection, nil
		}
	}
}

type inspectJSONValue func(any) (containsReasoning bool, verified bool)

func inspectJSONLinesSnapshot(ctx context.Context, file *os.File, maxLineBytes int, inspect inspectJSONValue) (artifactInspection, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return artifactInspection{}, err
	}
	defer func() { _, _ = file.Seek(0, io.SeekStart) }()
	if maxLineBytes <= 0 {
		return artifactInspection{}, fmt.Errorf("maximum redaction line size must be positive")
	}
	reader := bufio.NewReaderSize(file, 64<<10)
	inspection := artifactInspection{Verified: true}
	for {
		if err := ctx.Err(); err != nil {
			return artifactInspection{}, err
		}
		line, readErr := readBoundedJSONLLine(reader, maxLineBytes)
		if errors.Is(readErr, errRedactionLineTooLong) {
			inspection.Verified = false
			return inspection, nil
		}
		payload := bytes.TrimSpace(line)
		if len(payload) > 0 {
			var value any
			if err := decodeJSONUseNumber(payload, &value); err != nil {
				inspection.Verified = false
				return inspection, nil
			}
			containsReasoning, verified := inspect(value)
			inspection.ContainsReasoning = containsReasoning || inspection.ContainsReasoning
			inspection.Verified = verified && inspection.Verified
		}
		if readErr != nil {
			if readErr != io.EOF {
				return artifactInspection{}, readErr
			}
			return inspection, nil
		}
	}
}

func inspectProviderValue(value any) (bool, bool) {
	return reasoning.RedactValue(value, reasoning.ProviderTraversal())
}

func inspectActaEventValue(value any) (bool, bool) {
	event, ok := value.(map[string]any)
	if !ok {
		return false, false
	}
	typ, _ := event["type"].(string)
	payload, hasPayload := event["payload"]
	if typ == actaevents.TypeAgentReasoning {
		if !hasPayload {
			return false, true
		}
		_, changed := redactToStructuralReferences(payload)
		return changed, true
	}
	if typ == actaevents.TypeAgentEventUnsupported {
		_, changed, verified := redactUnsupportedPayload(payload)
		return changed, verified
	}
	if !reasoningFreeActaEventType(typ) {
		return false, false
	}
	if !hasPayload {
		return false, true
	}
	return reasoning.RedactValue(payload, reasoning.NormalizedTraversal(typ))
}

func inspectJSONDocumentSnapshot(ctx context.Context, file *os.File, path string, maxBytes int64) (artifactInspection, error) {
	payload, exceeded, err := readFileContextLimit(ctx, file, maxBytes)
	if err != nil {
		return artifactInspection{}, err
	}
	if exceeded {
		return artifactInspection{Verified: false}, nil
	}
	var value any
	if err := decodeJSONUseNumberContext(ctx, payload, &value); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return artifactInspection{}, err
		}
		return artifactInspection{Verified: false}, nil
	}
	if err := ctx.Err(); err != nil {
		return artifactInspection{}, err
	}
	switch {
	case isRunRecordArtifact(path):
		if err := rejectUnsupportedFutureDocumentVersion(schemaversion.RunRecord, value); err != nil {
			return artifactInspection{}, err
		}
	case isDigestArtifact(path):
		if err := rejectUnsupportedFutureDocumentVersion(schemaversion.Digest, value); err != nil {
			return artifactInspection{}, err
		}
	}
	traversal := reasoning.ProviderTraversal()
	if isRunRecordArtifact(path) {
		traversal = reasoning.NormalizedTraversal("run_record")
	} else if isDigestArtifact(path) {
		traversal = reasoning.NormalizedTraversal("digest")
	}
	containsReasoning, verified := reasoning.RedactValue(value, traversal)
	return artifactInspection{ContainsReasoning: containsReasoning, Verified: verified}, nil
}

func rewriteJSONLSnapshot(ctx context.Context, file *os.File, maxLineBytes int, transform func([]byte) ([]byte, error)) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if maxLineBytes <= 0 {
		return fmt.Errorf("maximum redaction line size must be positive")
	}
	temp, err := os.CreateTemp("", "acta-redacted-snapshot-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}()
	reader := bufio.NewReaderSize(file, 64<<10)
	lineNumber := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		lineNumber++
		line, readErr := readBoundedJSONLLine(reader, maxLineBytes)
		if errors.Is(readErr, errRedactionLineTooLong) {
			return fmt.Errorf("JSONL line %d exceeds maximum redaction line size of %d bytes", lineNumber, maxLineBytes)
		}
		if len(line) > 0 {
			redacted, err := transform(line)
			if err != nil {
				return err
			}
			if _, err := temp.Write(redacted); err != nil {
				return err
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				return readErr
			}
			break
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := temp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := copyContext(ctx, file, temp); err != nil {
		return err
	}
	_, err = file.Seek(0, io.SeekStart)
	return err
}

func jsonLineParts(line []byte) (prefix, payload, suffix []byte) {
	payload = bytes.TrimSpace(line)
	if len(payload) == 0 {
		return line, nil, nil
	}
	leftTrimmed := bytes.TrimLeftFunc(line, unicode.IsSpace)
	prefixLength := len(line) - len(leftTrimmed)
	suffixOffset := prefixLength + len(payload)
	return line[:prefixLength], payload, line[suffixOffset:]
}

func wrapJSONLine(prefix, payload, suffix []byte) []byte {
	line := make([]byte, 0, len(prefix)+len(payload)+len(suffix))
	line = append(line, prefix...)
	line = append(line, payload...)
	return append(line, suffix...)
}

// redactActaEventSnapshot upgrades the entire stream when any event body is
// rewritten. Event streams require a single schema version, so upgrading only
// the event that acquired v3 redaction fields would produce an invalid mixed
// v2/v3 stream.
func redactActaEventSnapshot(ctx context.Context, file *os.File, maxLineBytes int) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if maxLineBytes <= 0 {
		return fmt.Errorf("maximum redaction line size must be positive")
	}
	reader := bufio.NewReaderSize(file, 64<<10)
	lineNumber := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		lineNumber++
		line, readErr := readBoundedJSONLLine(reader, maxLineBytes)
		if errors.Is(readErr, errRedactionLineTooLong) {
			return fmt.Errorf("JSONL line %d exceeds maximum redaction line size of %d bytes", lineNumber, maxLineBytes)
		}
		redacted, err := redactActaReasoningEventLine(line)
		if err != nil {
			return err
		}
		if !bytes.Equal(redacted, line) {
			break
		}
		if readErr != nil {
			if readErr != io.EOF {
				return readErr
			}
			_, err := file.Seek(0, io.SeekStart)
			return err
		}
	}
	return rewriteJSONLSnapshot(ctx, file, maxLineBytes, func(line []byte) ([]byte, error) {
		redacted, err := redactActaReasoningEventLine(line)
		if err != nil {
			return nil, err
		}
		return stampActaEventLineSchemaVersion(redacted)
	})
}

func stampActaEventLineSchemaVersion(line []byte) ([]byte, error) {
	prefix, payload, suffix := jsonLineParts(line)
	if len(payload) == 0 {
		return line, nil
	}
	var event map[string]any
	if err := decodeJSONUseNumber(payload, &event); err != nil {
		return nil, fmt.Errorf("parse Acta event for schema upgrade: %w", err)
	}
	if _, err := stampRewrittenDocumentSchemaVersion(schemaversion.Event, event, true); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	return wrapJSONLine(prefix, encoded, suffix), nil
}

func copyContext(ctx context.Context, dst io.Writer, src io.Reader) error {
	buffer := make([]byte, 128<<10)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := src.Read(buffer)
		if n > 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
			written, writeErr := dst.Write(buffer[:n])
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func replaceSnapshotFromReader(ctx context.Context, file *os.File, source io.Reader) error {
	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := copyContext(ctx, file, source); err != nil {
		return err
	}
	_, err := file.Seek(0, io.SeekStart)
	return err
}

var errRedactionLineTooLong = errors.New("redaction line too long")

var errProviderRedactionUnverified = errors.New("provider event reasoning redaction could not be verified")

func readBoundedJSONLLine(reader *bufio.Reader, maxLineBytes int) ([]byte, error) {
	line := make([]byte, 0, min(maxLineBytes, 64<<10))
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) > maxLineBytes-len(line) {
			return nil, errRedactionLineTooLong
		}
		line = append(line, fragment...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return line, err
	}
}

func redactProviderReasoningLine(line []byte) ([]byte, error) {
	redacted, verified, err := redactProviderReasoningLineVerified(line)
	if err != nil {
		return nil, err
	}
	if !verified {
		return nil, errProviderRedactionUnverified
	}
	return redacted, nil
}

func redactProviderReasoningLineVerified(line []byte) ([]byte, bool, error) {
	prefix, payload, suffix := jsonLineParts(line)
	if len(payload) == 0 {
		return line, true, nil
	}
	var value any
	if err := reasoning.UnmarshalProviderLine(payload, &value); err != nil {
		if errors.Is(err, reasoning.ErrInvalidProviderEnvelope) {
			return line, false, nil
		}
		return nil, false, fmt.Errorf("parse provider event for remote reasoning redaction: %w", err)
	}
	traversal := reasoning.ProviderTraversal()
	changed := setReasoningRedactionState(value, traversal)
	reasoningChanged, verified := reasoning.RedactValue(value, traversal)
	if !verified {
		return line, false, nil
	}
	changed = reasoningChanged || changed
	if !changed {
		return line, true, nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, false, err
	}
	return wrapJSONLine(prefix, encoded, suffix), true, nil
}

func redactActaReasoningEventLine(line []byte) ([]byte, error) {
	prefix, payload, suffix := jsonLineParts(line)
	if len(payload) == 0 {
		return line, nil
	}
	var event map[string]any
	if err := decodeJSONUseNumber(payload, &event); err != nil {
		return nil, fmt.Errorf("parse Acta event for remote reasoning redaction: %w", err)
	}
	if err := rejectUnsupportedFutureDocumentVersion(schemaversion.Event, event); err != nil {
		return nil, err
	}
	typ, _ := event["type"].(string)
	traversal := reasoning.NormalizedTraversal(typ)
	changed := setReasoningRedactionState(event, reasoning.NormalizedTraversal(""))
	if payload, ok := event["payload"]; ok {
		switch {
		case typ == actaevents.TypeAgentReasoning:
			structural, structuralChanged := redactToStructuralReferences(payload)
			event["payload"] = structural
			changed = structuralChanged || changed
		case typ == actaevents.TypeAgentEventUnsupported:
			redacted, detailsChanged, verified := redactUnsupportedPayload(payload)
			if !verified {
				redacted, detailsChanged = redactToStructuralReferences(payload)
			}
			event["payload"] = redacted
			changed = detailsChanged || changed
		case !reasoningFreeActaEventType(typ):
			structural, structuralChanged := redactToStructuralReferences(payload)
			event["payload"] = structural
			changed = structuralChanged || changed
		default:
			// Known reasoning-free payloads retain their documented content, but
			// still receive a defensive recursive pass for nested provider blocks.
			reasoningChanged, verified := reasoning.RedactValue(payload, traversal)
			if !verified {
				return nil, errors.New("acta event reasoning redaction could not be verified")
			}
			changed = reasoningChanged || changed
		}
	}
	if !changed {
		return line, nil
	}
	if _, err := stampRewrittenDocumentSchemaVersion(schemaversion.Event, event, true); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	return wrapJSONLine(prefix, encoded, suffix), nil
}

// redactUnsupportedPayload understands the stable normalized wrapper used in
// digests and Acta events, but treats Details as retained raw provider data.
// Exact nested provider blocks and standalone blocks in Details arrays are
// masked recursively. Other inspectable diagnostics remain byte-for-byte data;
// unfamiliar shapes fail verification so their artifact can be withheld.
func redactUnsupportedPayload(value any) (any, bool, bool) {
	return reasoning.RedactUnsupportedPayload(value)
}

// reasoningFreeActaEventType is deliberately explicit. A newly introduced
// event type is redacted until this upload privacy boundary has audited it.
func reasoningFreeActaEventType(typ string) bool {
	switch typ {
	case actaevents.TypeRunStarted, actaevents.TypeRunCompleted, actaevents.TypeRunFailed,
		actaevents.TypeAgentPrompt, actaevents.TypeAgentInput, actaevents.TypeAgentMessage,
		actaevents.TypeAgentTodo, actaevents.TypeAgentTodoUpdated,
		actaevents.TypeAgentTaskStarted, actaevents.TypeAgentTaskProgress,
		actaevents.TypeAgentTaskCompleted, actaevents.TypeAgentTaskIncomplete,
		actaevents.TypeAgentPermissionDenied, actaevents.TypeAgentRuntimeConfigured,
		actaevents.TypeAgentStructuredOutput, actaevents.TypeAgentRateLimitObserved,
		actaevents.TypeAgentError, actaevents.TypeAgentLifecycle,
		actaevents.TypeToolCallCompleted, actaevents.TypeToolCallIncomplete,
		actaevents.TypeToolResultOrphaned, actaevents.TypeShellCommandComplete,
		actaevents.TypeShellCommandIncomplete, actaevents.TypeWebSearchCompleted,
		actaevents.TypeWebSearchIncomplete, actaevents.TypeFileRead,
		actaevents.TypeFileWritten, actaevents.TypeFileWriteIncomplete,
		actaevents.TypeDiffGenerated, actaevents.TypeTokensReported:
		return true
	default:
		return false
	}
}

func redactToStructuralReferences(value any) (any, bool) {
	payload, ok := value.(map[string]any)
	if !ok {
		return reasoningRedactionMask(value)
	}
	changed := false
	for key, item := range payload {
		if structuralPayloadValue(key, item) {
			continue
		}
		masked, itemChanged := reasoningRedactionMask(item)
		if itemChanged {
			payload[key] = masked
			changed = true
		}
	}
	if redacted, _ := payload["redacted"].(bool); !redacted {
		payload["redacted"] = true
		changed = true
	}
	return payload, changed
}

func structuralPayloadValue(key string, value any) bool {
	switch key {
	case "type", "kind", "provider_event", "id", "parent_id", "thread_id", "session_id", "task_id",
		"phase", "status", "visibility", "started_at", "observed_at", "completed_at", "tool", "server":
		_, ok := value.(string)
		return ok
	case "exit_code", "input_chars", "result_chars", "output_chars", "text_chars":
		return structuralInteger(value)
	case "is_error", "input_truncated", "result_truncated", "output_truncated", "text_truncated", "redacted":
		_, ok := value.(bool)
		return ok
	case "raw_event_lines":
		lines, ok := value.([]any)
		if !ok {
			return false
		}
		for _, line := range lines {
			if !structuralInteger(line) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func structuralInteger(value any) bool {
	switch typed := value.(type) {
	case json.Number:
		_, err := typed.Int64()
		return err == nil
	case float64:
		return !math.IsInf(typed, 0) && !math.IsNaN(typed) && math.Trunc(typed) == typed
	case float32:
		return !float32IsInfOrNaN(typed) && float32(math.Trunc(float64(typed))) == typed
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	default:
		return false
	}
}

func float32IsInfOrNaN(value float32) bool {
	return math.IsInf(float64(value), 0) || math.IsNaN(float64(value))
}

const reasoningRedactionMarker = reasoning.RedactedMarker

func reasoningRedactionMask(value any) (any, bool) {
	return reasoning.MaskValue(value)
}

func redactReasoningValueContext(ctx context.Context, value any, traversal reasoning.TraversalContext) (bool, error) {
	changed, verified, err := reasoning.RedactValueContext(ctx, value, traversal)
	if err == nil && !verified {
		err = errors.New("reasoning redaction could not verify provider payload")
	}
	return changed, err
}

func setReasoningRedactionState(value any, traversal reasoning.TraversalContext) bool {
	changed := false
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			changed = setReasoningRedactionState(item, traversal) || changed
		}
	case map[string]any:
		for key, item := range typed {
			childTraversal, exempt := traversal.Enter(typed, key)
			if exempt {
				continue
			}
			if key == "reasoning_redaction_state" {
				if item != "redacted" {
					typed[key] = "redacted"
					changed = true
				}
				continue
			}
			changed = setReasoningRedactionState(item, childTraversal) || changed
		}
	}
	return changed
}

func setReasoningRedactionStateContext(ctx context.Context, value any, traversal reasoning.TraversalContext) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	changed := false
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			itemChanged, err := setReasoningRedactionStateContext(ctx, item, traversal)
			if err != nil {
				return false, err
			}
			changed = itemChanged || changed
		}
	case map[string]any:
		for key, item := range typed {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			childTraversal, exempt := traversal.Enter(typed, key)
			if exempt {
				continue
			}
			if key == "reasoning_redaction_state" {
				if item != "redacted" {
					typed[key] = "redacted"
					changed = true
				}
				continue
			}
			itemChanged, err := setReasoningRedactionStateContext(ctx, item, childTraversal)
			if err != nil {
				return false, err
			}
			changed = itemChanged || changed
		}
	}
	return changed, nil
}

// stampRewrittenDocumentSchemaVersion is the single version and provenance
// boundary for Acta documents rewritten during remote redaction. Schema v2
// does not define the redaction and withheld-reference fields introduced by
// these rewrites, so an altered emitted copy must declare v3. Digests identify
// the rewriting binary as their producer; events preserve their immutable
// producer and identify the rewriting binary separately. Unchanged legacy
// documents stay byte identical.
func stampRewrittenDocumentSchemaVersion(documentType schemaversion.DocumentType, document any, rewritten bool) (bool, error) {
	if err := rejectUnsupportedFutureDocumentVersion(documentType, document); err != nil {
		return false, err
	}
	v3Fields, err := schemaversion.PresentV3OnlyFields(documentType, document)
	if err != nil {
		return false, fmt.Errorf("inspect rewritten Acta document fields: %w", err)
	}
	requiresFieldUpgrade := len(v3Fields) > 0 && rewrittenDocumentSchemaVersion(document) < runrecord.SchemaVersion
	if !rewritten && !requiresFieldUpgrade {
		return false, nil
	}
	switch typed := document.(type) {
	case map[string]any:
		typed["schema_version"] = runrecord.SchemaVersion
		switch documentType {
		case schemaversion.Digest:
			typed["producer"] = runrecord.CurrentProducer()
		case schemaversion.Event:
			typed["regenerated_by"] = runrecord.CurrentProducer()
		}
	case *actaevents.Event:
		typed.SchemaVersion = actaevents.SchemaVersion
		regenerator := runrecord.CurrentProducer()
		typed.RegeneratedBy = &regenerator
	default:
		return false, fmt.Errorf("rewritten Acta document has unsupported root type %T", document)
	}
	return true, nil
}

func rejectUnsupportedFutureDocumentVersion(documentType schemaversion.DocumentType, document any) error {
	var maximum int
	switch documentType {
	case schemaversion.RunRecord:
		maximum = runrecord.SchemaVersion
	case schemaversion.Digest:
		maximum = digest.SchemaVersion
	case schemaversion.Event:
		maximum = actaevents.SchemaVersion
	default:
		return fmt.Errorf("unsupported Acta document type %q", documentType)
	}

	var version any
	switch typed := document.(type) {
	case map[string]any:
		var present bool
		version, present = typed["schema_version"]
		if !present {
			return nil
		}
	case *actaevents.Event:
		version = typed.SchemaVersion
	default:
		return nil
	}

	future := false
	switch typed := version.(type) {
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return fmt.Errorf("invalid schema_version %q for %s: %w", typed, documentType, err)
		}
		future = parsed > int64(maximum)
	case float64:
		if math.IsInf(typed, 0) || math.IsNaN(typed) || math.Trunc(typed) != typed {
			return fmt.Errorf("invalid schema_version %v for %s", typed, documentType)
		}
		future = typed > float64(maximum)
	case int:
		future = typed > maximum
	case int8:
		future = int64(typed) > int64(maximum)
	case int16:
		future = int64(typed) > int64(maximum)
	case int32:
		future = int64(typed) > int64(maximum)
	case int64:
		future = typed > int64(maximum)
	case uint:
		future = uint64(typed) > uint64(maximum)
	case uint8:
		future = uint64(typed) > uint64(maximum)
	case uint16:
		future = uint64(typed) > uint64(maximum)
	case uint32:
		future = uint64(typed) > uint64(maximum)
	case uint64:
		future = typed > uint64(maximum)
	default:
		return fmt.Errorf("invalid schema_version type %T for %s", version, documentType)
	}
	if future {
		return fmt.Errorf("unsupported schema_version %v for %s (maximum supported is %d)", version, documentType, maximum)
	}
	return nil
}

func rewrittenDocumentSchemaVersion(document any) int {
	switch typed := document.(type) {
	case map[string]any:
		switch version := typed["schema_version"].(type) {
		case json.Number:
			value, _ := version.Int64()
			return int(value)
		case float64:
			return int(version)
		case int:
			return version
		}
	case *actaevents.Event:
		return typed.SchemaVersion
	}
	return 0
}

func redactRunRecordSnapshot(ctx context.Context, file *os.File) error {
	return rewriteJSONDocumentSnapshot(ctx, file, runrecord.MaxRecordBytes, func(ctx context.Context, value any) (bool, error) {
		if err := rejectUnsupportedFutureDocumentVersion(schemaversion.RunRecord, value); err != nil {
			return false, err
		}
		record, ok := value.(map[string]any)
		if !ok {
			changed, err := redactReasoningValueContext(ctx, value, reasoning.NormalizedTraversal("run_record"))
			if err != nil {
				return false, err
			}
			return stampRewrittenDocumentSchemaVersion(schemaversion.RunRecord, value, changed)
		}
		contentChanged, err := redactReasoningValueContext(ctx, record, reasoning.NormalizedTraversal("run_record"))
		if err != nil {
			return false, err
		}
		schemaVersion := int64(0)
		if encoded, ok := record["schema_version"].(json.Number); ok {
			schemaVersion, _ = encoded.Int64()
		}
		changed, err := stampRewrittenDocumentSchemaVersion(schemaversion.RunRecord, record, contentChanged)
		if err != nil {
			return false, err
		}
		if schemaVersion < runrecord.SchemaVersion && !changed {
			// Legacy schemas do not define reasoning_redaction_state. Keep a
			// content-safe record byte-for-byte intact and carry the result only
			// in the artifact upload metadata.
			return false, nil
		}
		if record["reasoning_redaction_state"] != "redacted" {
			record["reasoning_redaction_state"] = "redacted"
			changed = true
		}
		return stampRewrittenDocumentSchemaVersion(schemaversion.RunRecord, record, changed)
	})
}

// redactDigestSnapshot handles both current digests and pre-privacy-boundary
// schema-v2 digests which persisted reasoning text in timeline entries. The
// recursive fallback covers legacy/unknown locations, while reasoning-shaped
// objects preserve their keys and mask every value outside the structural
// allowlist used for Acta events.
func redactDigestSnapshot(ctx context.Context, file *os.File) error {
	return rewriteJSONDocumentSnapshot(ctx, file, maxRedactionJSONDocumentBytes, func(ctx context.Context, value any) (bool, error) {
		if err := rejectUnsupportedFutureDocumentVersion(schemaversion.Digest, value); err != nil {
			return false, err
		}
		traversal := reasoning.NormalizedTraversal("digest")
		changed, err := setReasoningRedactionStateContext(ctx, value, traversal)
		if err != nil {
			return false, err
		}
		reasoningChanged, err := redactReasoningValueContext(ctx, value, traversal)
		if err != nil {
			return false, err
		}
		return stampRewrittenDocumentSchemaVersion(schemaversion.Digest, value, reasoningChanged || changed)
	})
}

func redactJSONDocumentSnapshot(ctx context.Context, file *os.File) error {
	return rewriteJSONDocumentSnapshot(ctx, file, maxRedactionJSONDocumentBytes, func(ctx context.Context, value any) (bool, error) {
		traversal := reasoning.ProviderTraversal()
		changed, err := setReasoningRedactionStateContext(ctx, value, traversal)
		if err != nil {
			return false, err
		}
		reasoningChanged, err := redactReasoningValueContext(ctx, value, traversal)
		return reasoningChanged || changed, err
	})
}

func rewriteJSONDocumentSnapshot(ctx context.Context, file *os.File, maxBytes int64, transform func(context.Context, any) (bool, error)) error {
	payload, exceeded, err := readFileContextLimit(ctx, file, maxBytes)
	if err != nil {
		return err
	}
	if exceeded {
		return fmt.Errorf("JSON artifact exceeds %d-byte redaction limit", maxBytes)
	}
	var value any
	if err := decodeJSONUseNumberContext(ctx, payload, &value); err != nil {
		return err
	}
	changed, err := transform(ctx, value)
	if err != nil {
		return err
	}
	if !changed {
		_, err := file.Seek(0, io.SeekStart)
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	redacted, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(payload) > 0 && payload[len(payload)-1] == '\n' {
		redacted = append(redacted, '\n')
	}
	return replaceSnapshotContentsContext(ctx, file, redacted)
}

func readFileContextLimit(ctx context.Context, file *os.File, maxBytes int64) ([]byte, bool, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, false, err
	}
	defer func() { _, _ = file.Seek(0, io.SeekStart) }()
	var payload bytes.Buffer
	if err := copyContext(ctx, &payload, io.LimitReader(file, maxBytes+1)); err != nil {
		return nil, false, err
	}
	if int64(payload.Len()) > maxBytes {
		return nil, true, nil
	}
	return payload.Bytes(), false, nil
}

func decodeJSONUseNumber(payload []byte, value any) error {
	return reasoning.UnmarshalProviderLine(payload, value)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(payload []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(payload)
}

func decodeJSONUseNumberContext(ctx context.Context, payload []byte, value any) error {
	if err := reasoning.ValidateUniqueObjectKeysContext(ctx, payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(contextReader{ctx: ctx, reader: bytes.NewReader(payload)})
	decoder.UseNumber()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return ctx.Err()
}

func replaceSnapshotContentsContext(ctx context.Context, file *os.File, payload []byte) error {
	return replaceSnapshotReaderContext(ctx, file, bytes.NewReader(payload))
}

func replaceSnapshotReaderContext(ctx context.Context, file *os.File, reader io.Reader) error {
	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := copyContext(ctx, file, reader); err != nil {
		return err
	}
	_, err := file.Seek(0, io.SeekStart)
	return err
}

func hashFileContext(ctx context.Context, file *os.File) (string, int64, error) {
	hasher := sha256.New()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	buffer := make([]byte, 128<<10)
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			return "", 0, err
		}
		n, readErr := file.Read(buffer)
		if n > 0 {
			_, _ = hasher.Write(buffer[:n])
			size += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", 0, readErr
		}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

func snapshotEventStreamLimit(ctx context.Context, runDir string, maxBytes int64) (*os.File, string, error) {
	resolvedRunDir, err := filepath.EvalSymlinks(runDir)
	if err != nil {
		return nil, "", fmt.Errorf("resolve run directory: %w", err)
	}
	path := filepath.Join(runDir, actaevents.Filename)
	if maxBytes > 0 {
		if info, statErr := os.Lstat(path); statErr == nil && info.Size() > maxBytes {
			return nil, "", fmt.Errorf("event stream is %d bytes; artifact snapshot maximum is %d", info.Size(), maxBytes)
		}
	}
	file, tempPath, err := snapshotRegularFile(ctx, resolvedRunDir, path, maxBytes)
	if err != nil {
		return nil, "", err
	}
	return file, tempPath, nil
}

// snapshotRegularFile copies one pinned source into a private temporary file,
// then verifies the source still hashes to the copied bytes. Upload therefore
// reads an immutable, coherent snapshot and fails if a bundle changes during
// preparation.
func snapshotRegularFile(ctx context.Context, root, path string, maxBytes int64) (*os.File, string, error) {
	source, err := securefile.OpenRegular(root, path)
	if err != nil {
		return nil, "", err
	}
	defer source.Close()
	return snapshotOpenFileContext(ctx, source, maxBytes, "")
}

// snapshotOpenFileContext copies an already-pinned source into a private
// temporary file. An expected hash supplied by projection.json authoritatively
// binds the copied bytes to that projection generation.
func snapshotOpenFileContext(ctx context.Context, source *os.File, maxBytes int64, expectedHash string) (*os.File, string, error) {
	var remaining *int64
	if maxBytes > 0 {
		remaining = &maxBytes
	}
	return snapshotOpenFileBudgetContext(ctx, source, remaining, expectedHash)
}

func snapshotOpenFileBudgetContext(ctx context.Context, source *os.File, remaining *int64, expectedHash string) (*os.File, string, error) {
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return nil, "", err
	}
	temp, err := os.CreateTemp("", "acta-upload-snapshot-*")
	if err != nil {
		return nil, "", err
	}
	tempPath := temp.Name()
	cleanup := func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}
	hasher := sha256.New()
	buffer := make([]byte, 128<<10)
	var copied int64
	for {
		if err := ctx.Err(); err != nil {
			cleanup()
			return nil, "", err
		}
		n, readErr := source.Read(buffer)
		if n > 0 {
			if remaining != nil && copied+int64(n) > *remaining {
				cleanup()
				return nil, "", fmt.Errorf("file exceeded remaining upload snapshot maximum of %d bytes", *remaining)
			}
			if _, err := temp.Write(buffer[:n]); err != nil {
				cleanup()
				return nil, "", err
			}
			_, _ = hasher.Write(buffer[:n])
			copied += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			cleanup()
			return nil, "", readErr
		}
	}
	copyHash := hex.EncodeToString(hasher.Sum(nil))
	if expectedHash != "" && copyHash != expectedHash {
		cleanup()
		return nil, "", fmt.Errorf("opened artifact SHA-256 %s does not match projection manifest %s", copyHash, expectedHash)
	}
	sourceHash, _, err := hashFileContext(ctx, source)
	if err != nil {
		cleanup()
		return nil, "", err
	}
	if sourceHash != copyHash {
		cleanup()
		return nil, "", fmt.Errorf("source changed while upload snapshot was prepared")
	}
	if _, err := temp.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, "", err
	}
	if remaining != nil {
		*remaining -= copied
	}
	return temp, tempPath, nil
}

func closeArtifacts(artifacts []artifactUpload) {
	seenFiles := map[*os.File]bool{}
	seenPaths := map[string]bool{}
	for _, artifact := range artifacts {
		if artifact.File != nil && !seenFiles[artifact.File] {
			_ = artifact.File.Close()
			seenFiles[artifact.File] = true
		}
		if artifact.TempPath != "" && !seenPaths[artifact.TempPath] {
			_ = os.Remove(artifact.TempPath)
			seenPaths[artifact.TempPath] = true
		}
	}
}

func artifactPath(runDir string, rel string) (string, error) {
	if rel == "" {
		return "", errors.New("artifact path is empty")
	}
	if filepath.IsAbs(rel) || strings.Contains(rel, `\`) {
		return "", fmt.Errorf("unsafe artifact path %q", rel)
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if filepath.ToSlash(clean) != rel {
		return "", fmt.Errorf("unsafe artifact path %q", rel)
	}
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe artifact path %q", rel)
	}
	return filepath.Join(runDir, clean), nil
}

func contentType(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "application/json"
	case ".jsonl":
		return "application/x-ndjson"
	case ".diff", ".patch":
		return "text/x-diff"
	case ".log", ".txt":
		return "text/plain; charset=utf-8"
	}
	if typ := mime.TypeByExtension(filepath.Ext(path)); typ != "" {
		return typ
	}
	return "application/octet-stream"
}

func compression(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".gz":
		return "gzip"
	case ".zst":
		return "zstd"
	default:
		return ""
	}
}

func buildRunMetadata(record *runrecord.Record, reasoningRedactionState string) runMetadataPayload {
	metadata := runMetadataPayload{
		AgentVersion:               record.AgentVersion,
		OTLPStatus:                 record.OTLPStatus,
		OTLPError:                  record.OTLPError,
		RawOutputLimitBytes:        record.RawOutputLimitBytes,
		RawOutputLimitExceeded:     record.RawOutputLimitExceeded,
		WorkspaceDiffLimitBytes:    record.WorkspaceDiffLimitBytes,
		WorkspaceDiffLimitExceeded: record.WorkspaceDiffLimitExceeded,
		ProcessContainment:         record.ProcessContainment,
		AgentConfigMode:            record.AgentConfigMode,
		RuntimeBundleSHA256:        record.RuntimeBundleSHA256,
		ReasoningRedactionState:    reasoningRedactionState,
		PromptSource:               record.PromptSource,
		PromptCaptured:             record.PromptCaptured,
		TerminationReason:          record.TerminationReason,
		TraceID:                    record.TraceID,
		CWD:                        record.CWD,
		RunDir:                     record.RunDir,
		RecoveryDir:                record.RecoveryDir,
		Repository:                 record.Repository,
		IssueTitle:                 record.IssueTitle,
		IssueBody:                  record.IssueBody,
		TaskTitle:                  record.TaskTitle,
		BaseCommitSHA:              record.BaseCommitSHA,
		BaseBranch:                 record.BaseBranch,
		BaseDirty:                  record.BaseDirty,
	}
	if record.IssueNumber > 0 {
		metadata.IssueNumber = record.IssueNumber
	}
	return metadata
}
