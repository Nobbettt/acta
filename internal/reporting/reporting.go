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
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nobbettt/acta/internal/actaevents"
	"github.com/nobbettt/acta/internal/runrecord"
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
}

const (
	maxEventsRequestBytes       = actaevents.MaxEventsRequestBytes
	eventsEnvelopeBytes         = len(`{"events":[]}`)
	DefaultMaxUploadBytes int64 = 1 << 30
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
	Kind          string `json:"kind"`
	Filename      string `json:"filename"`
	ContentType   string `json:"content_type"`
	SizeBytes     int64  `json:"size_bytes"`
	SHA256        string `json:"sha256"`
	Compression   string `json:"compression,omitempty"`
	SchemaVersion *int32 `json:"schema_version,omitempty"`
	File          *os.File
	TempPath      string
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
	eventFile, eventTempPath, err := snapshotEventStreamLimit(ctx, record.RunDir, artifactLimit)
	if err != nil {
		return err
	}
	defer func() {
		_ = eventFile.Close()
		_ = os.Remove(eventTempPath)
	}()
	artifactRefs, err := terminalArtifactRefsFromFile(ctx, eventFile, record)
	if err != nil {
		return err
	}
	artifacts, err := buildArtifactsContext(ctx, record.RunDir, artifactRefs, eventFile, eventTempPath, artifactLimit)
	if err != nil {
		return err
	}
	defer closeArtifacts(artifacts)

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
				ReasoningRedactionState: record.ReasoningRedactionState,
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
		Metadata:       buildRunMetadata(record),
	}); err != nil {
		return fmt.Errorf("create run: %w", err)
	}
	if err := client.postEventsFromFile(ctx, record.ID, eventFile); err != nil {
		return fmt.Errorf("upload events: %w", markUploadFailed(err))
	}
	for _, artifact := range artifacts {
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
			ReasoningRedactionState: record.ReasoningRedactionState,
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
			if err := json.Unmarshal(line, &event); err != nil {
				return 0, fmt.Errorf("decode %s: %w", actaevents.Filename, err)
			}
			if err := actaevents.ValidateEvent(event, runID, count); err != nil {
				return 0, err
			}
			if streamSchema == 0 {
				streamSchema, streamProducer = event.SchemaVersion, event.Producer
			} else if event.SchemaVersion != streamSchema {
				return 0, fmt.Errorf("event sequence %d schema_version %d does not match stream schema_version %d", event.Sequence, event.SchemaVersion, streamSchema)
			} else if event.SchemaVersion >= 2 && event.Producer != streamProducer {
				return 0, fmt.Errorf("event sequence %d producer does not match stream producer", event.Sequence)
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

func buildArtifactsContext(ctx context.Context, runDir string, refs []actaevents.ArtifactRef, eventFile *os.File, eventTempPath string, maxBytes int64) ([]artifactUpload, error) {
	resolvedRunDir, err := filepath.EvalSymlinks(runDir)
	if err != nil {
		return nil, fmt.Errorf("resolve run directory: %w", err)
	}
	artifacts := make([]artifactUpload, 0, len(refs))
	if maxBytes > 0 {
		var plannedBytes int64
		for _, ref := range refs {
			if ref.Kind == "event_stream" && eventFile != nil {
				info, statErr := eventFile.Stat()
				if statErr != nil {
					return nil, fmt.Errorf("stat event snapshot: %w", statErr)
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
	var totalBytes int64
	for _, ref := range refs {
		path, err := artifactPath(runDir, ref.Path)
		if err != nil {
			closeArtifacts(artifacts)
			return nil, err
		}
		var file *os.File
		var tempPath string
		if ref.Kind == "event_stream" && eventFile != nil {
			file, tempPath = eventFile, eventTempPath
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
		sha256Hex, sizeBytes, err := hashFileContext(ctx, file)
		if err != nil {
			_ = file.Close()
			closeArtifacts(artifacts)
			return nil, fmt.Errorf("hash artifact %s: %w", ref.Path, err)
		}
		totalBytes += sizeBytes
		if maxBytes > 0 && totalBytes > maxBytes {
			if tempPath != eventTempPath {
				_ = file.Close()
				_ = os.Remove(tempPath)
			}
			closeArtifacts(artifacts)
			return nil, fmt.Errorf("artifact snapshot is %d bytes; maximum is %d", totalBytes, maxBytes)
		}
		schemaVersion := int32(actaevents.SchemaVersion)
		artifact := artifactUpload{
			Kind:        ref.Kind,
			Filename:    ref.Path,
			ContentType: contentType(ref.Path),
			SizeBytes:   sizeBytes,
			SHA256:      sha256Hex,
			Compression: compression(ref.Path),
			File:        file,
			TempPath:    tempPath,
		}
		if ref.Kind == "event_stream" {
			artifact.SchemaVersion = &schemaVersion
		}
		artifacts = append(artifacts, artifact)
	}
	return artifacts, nil
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
	return snapshotRegularFile(ctx, resolvedRunDir, path, maxBytes)
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
			if maxBytes > 0 && copied+int64(n) > maxBytes {
				cleanup()
				return nil, "", fmt.Errorf("file exceeded remaining upload snapshot budget of %d bytes", maxBytes)
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

func buildRunMetadata(record *runrecord.Record) runMetadataPayload {
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
		ReasoningRedactionState:    record.ReasoningRedactionState,
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
