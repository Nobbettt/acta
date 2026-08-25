// Package actaevents renders Acta's normalized digest into a stable
// product-facing JSONL event stream. The stream is intended for replay and
// backend ingestion; raw vendor JSONL remains the evidence source.
package actaevents

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nobbettt/acta/internal/digest"
	"github.com/nobbettt/acta/internal/runrecord"
	"github.com/nobbettt/acta/internal/schemaversion"
	"github.com/nobbettt/acta/internal/securefile"
)

const (
	SchemaVersion    = 3
	MinSchemaVersion = 2
	// ProjectionSchemaVersion versions projection.json independently from the
	// digest and event contracts it binds by hash.
	ProjectionSchemaVersion = 2
	Source                  = "acta"
	Filename                = "acta-events.jsonl"
	// MaxEventsRequestBytes is the complete upload-request budget. MaxEventBytes
	// reserves the JSON array envelope so every writer-valid individual event is
	// also uploadable as a one-event batch.
	MaxEventsRequestBytes = 8 << 20
	MaxEventBytes         = MaxEventsRequestBytes - len(`{"events":[]}`)
	MaxStreamBytes        = 256 << 20
)

const (
	TypeRunStarted             = "run.started"
	TypeRunCompleted           = "run.completed"
	TypeRunFailed              = "run.failed"
	TypeAgentPrompt            = "agent.prompt"
	TypeAgentInput             = "agent.input"
	TypeAgentMessage           = "agent.message"
	TypeAgentReasoning         = "agent.reasoning"
	TypeAgentTodo              = "agent.todo"
	TypeAgentTodoUpdated       = "agent.todo.updated"
	TypeAgentTaskStarted       = "agent.task.started"
	TypeAgentTaskProgress      = "agent.task.progress"
	TypeAgentTaskCompleted     = "agent.task.completed"
	TypeAgentTaskIncomplete    = "agent.task.incomplete"
	TypeAgentPermissionDenied  = "agent.permission.denied"
	TypeAgentRuntimeConfigured = "agent.runtime.configured"
	TypeAgentStructuredOutput  = "agent.output.structured"
	TypeAgentRateLimitObserved = "agent.rate_limit.observed"
	TypeAgentError             = "agent.error"
	TypeAgentEventUnsupported  = "agent.event.unsupported"
	TypeAgentLifecycle         = "agent.lifecycle"
	TypeToolCallCompleted      = "tool.call.completed"
	TypeToolCallIncomplete     = "tool.call.incomplete"
	TypeToolResultOrphaned     = "tool.result.orphaned"
	TypeShellCommandComplete   = "shell.command.completed"
	TypeShellCommandIncomplete = "shell.command.incomplete"
	TypeWebSearchCompleted     = "web.search.completed"
	TypeWebSearchIncomplete    = "web.search.incomplete"
	TypeFileRead               = "file.read"
	TypeFileWritten            = "file.written"
	TypeFileWriteIncomplete    = "file.write.incomplete"
	TypeDiffGenerated          = "diff.generated"
	TypeTokensReported         = "tokens.reported"
)

const (
	ArtifactStatusWithheld           = "withheld"
	ArtifactRedactionStateUnverified = "unverified"
)

type ArtifactRef struct {
	Kind           string `json:"kind"`
	Path           string `json:"path"`
	Lines          []int  `json:"lines,omitempty"`
	Status         string `json:"status,omitempty"`
	Reason         string `json:"reason,omitempty"`
	RedactionState string `json:"redaction_state,omitempty"`
}

type Event struct {
	SchemaVersion int                 `json:"schema_version"`
	Producer      runrecord.Producer  `json:"producer,omitempty"`
	RegeneratedBy *runrecord.Producer `json:"regenerated_by,omitempty"`
	RunID         string              `json:"run_id"`
	Sequence      int                 `json:"sequence"`
	Timestamp     time.Time           `json:"timestamp"`
	Source        string              `json:"source"`
	Type          string              `json:"type"`
	Payload       json.RawMessage     `json:"payload"`
	ArtifactRefs  []ArtifactRef       `json:"artifact_refs,omitempty"`

	presentV3Fields []string
}

// UnmarshalJSON retains explicit v3-only field presence independently of Go
// zero values so replay validation enforces the labeled schema version.
func (e *Event) UnmarshalJSON(data []byte) error {
	type plainEvent Event
	var decoded plainEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	fields, err := schemaversion.PresentV3OnlyFieldsJSON(schemaversion.Event, data)
	if err != nil {
		return err
	}
	*e = Event(decoded)
	e.presentV3Fields = fields
	return nil
}

// ValidateEnvelope checks the stable identity and ordering fields shared by
// replay and upload consumers.
func ValidateEnvelope(event Event, runID string, expectedSequence int) error {
	if event.RunID != runID {
		return fmt.Errorf("event run_id %q does not match record run_id %q", event.RunID, runID)
	}
	if event.SchemaVersion < MinSchemaVersion || event.SchemaVersion > SchemaVersion {
		return fmt.Errorf("event sequence %d has unsupported schema_version %d (supported %d..%d)", event.Sequence, event.SchemaVersion, MinSchemaVersion, SchemaVersion)
	}
	if !runrecord.SupportsV3Fields(event.SchemaVersion) {
		field, found, err := schemaversion.FirstPresentV3OnlyField(schemaversion.Event, event, event.presentV3Fields)
		if err != nil {
			return fmt.Errorf("inspect event sequence %d versioned fields: %w", event.Sequence, err)
		}
		if found {
			return fmt.Errorf("event sequence %d schema_version %d does not support %s", event.Sequence, event.SchemaVersion, field)
		}
	}
	if event.SchemaVersion >= 2 && (strings.TrimSpace(event.Producer.Name) == "" || strings.TrimSpace(event.Producer.Version) == "") {
		return fmt.Errorf("event sequence %d schema_version %d requires producer name and version", event.Sequence, event.SchemaVersion)
	}
	if event.RegeneratedBy != nil {
		if strings.TrimSpace(event.RegeneratedBy.Name) == "" || strings.TrimSpace(event.RegeneratedBy.Version) == "" {
			return fmt.Errorf("event sequence %d regenerated_by requires producer name and version", event.Sequence)
		}
		if event.RegeneratedBy.Name != "acta" {
			return fmt.Errorf("event sequence %d regenerated_by producer name must be acta", event.Sequence)
		}
	}
	if event.Source != Source {
		return fmt.Errorf("event sequence %d has invalid source %q", event.Sequence, event.Source)
	}
	if event.Sequence != expectedSequence {
		return fmt.Errorf("event sequence %d is out of order; expected %d", event.Sequence, expectedSequence)
	}
	return nil
}

// IsKnownType reports whether typ belongs to the published Acta event
// vocabulary. Provider event names are payload metadata, never envelope types.
func IsKnownType(typ string) bool {
	switch typ {
	case TypeRunStarted, TypeRunCompleted, TypeRunFailed, TypeAgentPrompt,
		TypeAgentInput, TypeAgentMessage, TypeAgentReasoning, TypeAgentTodo,
		TypeAgentTodoUpdated, TypeAgentTaskStarted, TypeAgentTaskProgress,
		TypeAgentTaskCompleted, TypeAgentTaskIncomplete, TypeAgentPermissionDenied,
		TypeAgentRuntimeConfigured, TypeAgentStructuredOutput, TypeAgentRateLimitObserved,
		TypeAgentError, TypeAgentEventUnsupported, TypeAgentLifecycle,
		TypeToolCallCompleted, TypeToolCallIncomplete, TypeToolResultOrphaned,
		TypeShellCommandComplete, TypeShellCommandIncomplete, TypeWebSearchCompleted,
		TypeWebSearchIncomplete, TypeFileRead, TypeFileWritten, TypeFileWriteIncomplete,
		TypeDiffGenerated, TypeTokensReported:
		return true
	default:
		return false
	}
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func ValidateEvent(event Event, runID string, expectedSequence int) error {
	if err := ValidateEnvelope(event, runID, expectedSequence); err != nil {
		return err
	}
	if event.SchemaVersion >= 2 && !IsKnownType(event.Type) {
		return fmt.Errorf("event sequence %d has unknown schema-v%d type %q", event.Sequence, event.SchemaVersion, event.Type)
	}
	if len(event.Payload) == 0 || !json.Valid(event.Payload) {
		return fmt.Errorf("event sequence %d has invalid payload", event.Sequence)
	}
	if event.Type == TypeRunStarted {
		var payload struct {
			OTLPStatus string `json:"otlp_status"`
		}
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return fmt.Errorf("event sequence %d has invalid run.started payload: %w", event.Sequence, err)
		}
		validOTLPStatus := payload.OTLPStatus == "" || oneOf(payload.OTLPStatus, "not_configured", "exported", "failed")
		if runrecord.SupportsV3Fields(event.SchemaVersion) {
			validOTLPStatus = validOTLPStatus || payload.OTLPStatus == "not_sampled"
		}
		if !validOTLPStatus {
			return fmt.Errorf("event sequence %d schema_version %d has invalid run.started otlp_status %q", event.Sequence, event.SchemaVersion, payload.OTLPStatus)
		}
	}
	for _, ref := range event.ArtifactRefs {
		if strings.TrimSpace(ref.Kind) == "" || strings.TrimSpace(ref.Path) == "" {
			return fmt.Errorf("event sequence %d has an invalid artifact reference", event.Sequence)
		}
		switch ref.Status {
		case "":
			if ref.Reason != "" || ref.RedactionState != "" {
				return fmt.Errorf("event sequence %d artifact %q has status metadata without a status", event.Sequence, ref.Path)
			}
		case ArtifactStatusWithheld:
			if strings.TrimSpace(ref.Reason) == "" || ref.RedactionState != ArtifactRedactionStateUnverified {
				return fmt.Errorf("event sequence %d withheld artifact %q requires a reason and redaction_state unverified", event.Sequence, ref.Path)
			}
		default:
			return fmt.Errorf("event sequence %d artifact %q has invalid status %q", event.Sequence, ref.Path, ref.Status)
		}
	}
	return nil
}

type builder struct {
	runID         string
	producer      runrecord.Producer
	regeneratedBy *runrecord.Producer
	bundleDir     string
	schemaVersion int
	next          int
	events        []Event
	bytes         int
}

func Build(record *runrecord.Record, d *digest.Digest) ([]Event, error) {
	return BuildWithPrompt(record, d, "")
}

// BuildWithPrompt adds the exact submitted prompt when prompt retention was
// explicitly enabled for the run. The prompt remains outside run.json so
// ordinary run metadata and process diagnostics do not duplicate its content.
func BuildWithPrompt(record *runrecord.Record, d *digest.Digest, prompt string) ([]Event, error) {
	bundleDir := ""
	if record != nil {
		bundleDir = record.RunDir
	}
	return BuildForBundle(bundleDir, record, d, prompt)
}

// BuildForBundle reads artifact presence from bundleDir while keeping the
// logical final paths from record.RunDir in normalized references.
func BuildForBundle(bundleDir string, record *runrecord.Record, d *digest.Digest, prompt string) ([]Event, error) {
	return buildForBundle(bundleDir, record, d, prompt, nil)
}

func buildForBundle(bundleDir string, record *runrecord.Record, d *digest.Digest, prompt string, regeneratedBy *runrecord.Producer) ([]Event, error) {
	if record == nil {
		return nil, fmt.Errorf("run record is nil")
	}
	if d == nil {
		return nil, fmt.Errorf("digest is nil")
	}
	if record.SchemaVersion >= 2 {
		if err := record.Validate(); err != nil {
			return nil, fmt.Errorf("validate run record: %w", err)
		}
	}
	if record.ID == "" || d.RunID != "" && d.RunID != record.ID {
		return nil, fmt.Errorf("digest run_id %q does not match record run_id %q", d.RunID, record.ID)
	}
	if d.SchemaVersion != 0 {
		if err := d.Validate(); err != nil {
			return nil, fmt.Errorf("validate digest: %w", err)
		}
	}
	resolved := digest.ResolveOutcome(record, d)
	if resolved.OK != record.OK {
		return nil, fmt.Errorf("record outcome is inconsistent with provider termination %q; reconcile the run record before building events", d.Termination.Outcome)
	}
	if d.Status != "" && d.Status != resolved.Status {
		return nil, fmt.Errorf("digest status %q does not match resolved status %q", d.Status, resolved.Status)
	}
	if d.Termination.RunnerReason != "" && d.Termination.RunnerReason != record.TerminationReason {
		return nil, fmt.Errorf("digest runner termination %q does not match record termination %q", d.Termination.RunnerReason, record.TerminationReason)
	}

	producer := record.Producer
	if strings.TrimSpace(producer.Name) == "" {
		producer = runrecord.CurrentProducer()
	}
	b := &builder{runID: record.ID, producer: producer, regeneratedBy: regeneratedBy, bundleDir: bundleDir, schemaVersion: SchemaVersion, next: 1}
	if prompt != "" {
		if _, err := b.append(TypeAgentPrompt, record.StartedAt, agentPromptPayload{
			Text:   prompt,
			Source: record.PromptSource,
		}); err != nil {
			return nil, err
		}
	}
	if _, err := b.append(TypeRunStarted, record.StartedAt, runStartedPayload{
		Agent:                   record.Agent,
		AgentVersion:            record.AgentVersion,
		Model:                   record.Model,
		CWD:                     record.CWD,
		BaseCommitSHA:           record.BaseCommitSHA,
		BaseBranch:              record.BaseBranch,
		BaseDirty:               record.BaseDirty,
		Repository:              record.Repository,
		IssueNumber:             record.IssueNumber,
		IssueTitle:              record.IssueTitle,
		IssueBody:               record.IssueBody,
		TaskTitle:               record.TaskTitle,
		RunDir:                  record.RunDir,
		RecoveryDir:             record.RecoveryDir,
		Command:                 record.Command,
		PromptSource:            record.PromptSource,
		PromptCaptured:          record.PromptCaptured,
		OTLPStatus:              record.OTLPStatus,
		OTLPError:               record.OTLPError,
		RawOutputLimitBytes:     record.RawOutputLimitBytes,
		WorkspaceDiffLimitBytes: record.WorkspaceDiffLimitBytes,
		ProcessContainment:      record.ProcessContainment,
		AgentConfigMode:         record.AgentConfigMode,
		RuntimeBundleSHA256:     record.RuntimeBundleSHA256,
		ReasoningRedactionState: record.ReasoningRedactionState,
	}); err != nil {
		return nil, err
	}

	for _, item := range d.Timeline {
		if err := b.appendTimelineEvent(record, item); err != nil {
			return nil, err
		}
	}

	completedAt := record.CompletedAt
	if d.HasWorkspaceDiff {
		if _, err := b.append(TypeDiffGenerated, completedAt, diffPayload{
			Path: "workspace.diff",
		}, ArtifactRef{Kind: "workspace_diff", Path: "workspace.diff"}); err != nil {
			return nil, err
		}
	}
	if hasTokens(d.Metrics.Tokens) || d.Metrics.CostUSD != 0 {
		if _, err := b.append(TypeTokensReported, completedAt, tokensPayload{
			Tokens:  d.Metrics.Tokens,
			CostUSD: d.Metrics.CostUSD,
		}); err != nil {
			return nil, err
		}
	}

	endType := TypeRunCompleted
	if !record.OK {
		endType = TypeRunFailed
	}
	if _, err := b.append(endType, completedAt, runCompletedPayload{
		Status:                     terminalStatus(record, d),
		OK:                         record.OK,
		Timeout:                    record.Timeout,
		ExitCode:                   record.ExitCode,
		HeadCommitSHA:              record.HeadCommitSHA,
		DurationMillis:             record.DurationMillis,
		Error:                      record.Error,
		Termination:                d.Termination,
		UnsupportedEvents:          d.Metrics.UnsupportedEvents,
		IncompleteToolCalls:        d.Metrics.IncompleteToolCalls,
		OrphanedToolResults:        d.Metrics.OrphanedToolResults,
		StructuredOutput:           d.StructuredOutput,
		ModelUsage:                 d.ModelUsage,
		RawOutputLimitBytes:        record.RawOutputLimitBytes,
		RawOutputLimitExceeded:     record.RawOutputLimitExceeded,
		WorkspaceDiffLimitBytes:    record.WorkspaceDiffLimitBytes,
		WorkspaceDiffLimitExceeded: record.WorkspaceDiffLimitExceeded,
	}, completionArtifacts(bundleDir, record, d)...); err != nil {
		return nil, err
	}
	return b.events, nil
}

func terminalStatus(record *runrecord.Record, d *digest.Digest) string {
	switch {
	case record.Timeout:
		return "timeout"
	case !record.OK:
		return "error"
	case d.Status != "":
		return d.Status
	default:
		return "ok"
	}
}

func Write(runDir string, events []Event) error {
	payload, err := encodeEvents(events)
	if err != nil {
		return err
	}
	path := filepath.Join(runDir, Filename)
	if err := securefile.WriteFile(path, payload); err != nil {
		return fmt.Errorf("write acta events: %w", err)
	}
	return nil
}

func encodeEvents(events []Event) ([]byte, error) {
	var output bytes.Buffer
	totalBytes := 0
	for i := range events {
		encoded, err := json.Marshal(events[i])
		if err != nil {
			return nil, fmt.Errorf("encode acta events: %w", err)
		}
		if len(encoded)+1 > MaxEventBytes {
			return nil, fmt.Errorf("event sequence %d is %d bytes; maximum is %d", events[i].Sequence, len(encoded)+1, MaxEventBytes)
		}
		totalBytes += len(encoded) + 1
		if totalBytes > MaxStreamBytes {
			return nil, fmt.Errorf("event stream exceeds maximum size %d bytes", MaxStreamBytes)
		}
		_, _ = output.Write(encoded)
		_ = output.WriteByte('\n')
	}
	return output.Bytes(), nil
}

func WriteForRecord(runDir string, record *runrecord.Record, d *digest.Digest) error {
	return WriteForRecordWithPrompt(runDir, record, d, "")
}

func WriteForRecordWithPrompt(runDir string, record *runrecord.Record, d *digest.Digest, prompt string) error {
	events, err := BuildForBundle(runDir, record, d, prompt)
	if err != nil {
		return err
	}
	return Write(runDir, events)
}

func WriteForRunDir(runDir string, d *digest.Digest) error {
	events, err := buildEventsForRunDir(runDir, d)
	if err != nil {
		return err
	}
	return Write(runDir, events)
}

func buildEventsForRunDir(runDir string, d *digest.Digest) ([]Event, error) {
	payload, err := securefile.ReadRegularFile(runDir, filepath.Join(runDir, "run.json"), runrecord.MaxRecordBytes)
	if err != nil {
		return nil, fmt.Errorf("read run record: %w", err)
	}
	var record runrecord.Record
	if err := json.Unmarshal(payload, &record); err != nil {
		return nil, fmt.Errorf("parse run record: %w", err)
	}
	// The event producer remains the immutable execution producer recorded in
	// run.json. Re-digestion is attributed separately to the binary performing
	// the new projection. Pre-schema records have no original identity to keep.
	if strings.TrimSpace(record.Producer.Name) == "" {
		record.Producer = runrecord.CurrentProducer()
	}
	regeneratedBy := d.Producer
	if strings.TrimSpace(regeneratedBy.Name) == "" {
		regeneratedBy = runrecord.CurrentProducer()
	}
	if record.RawStdoutArtifact == "" {
		record.RawStdoutArtifact = artifactPath(record.RunDir, record.RawStdoutPath)
	}
	if record.RawStderrArtifact == "" {
		record.RawStderrArtifact = artifactPath(record.RunDir, record.RawStderrPath)
		if record.RawStderrArtifact == "." || record.RawStderrArtifact == "" {
			record.RawStderrArtifact = "stderr.log"
		}
	}
	// Re-digestion may deliberately produce a degraded projection while leaving
	// the immutable execution record unchanged. Reconcile an in-memory copy for
	// the new event generation; standalone upload will continue to reject a
	// degraded terminal stream that disagrees with the original run outcome.
	digest.ReconcileRecord(&record, d)
	prompt := ""
	if record.PromptCaptured {
		prompt, err = capturedPromptFromEventStream(runDir, record.ID)
		if err != nil {
			return nil, err
		}
		if prompt == "" {
			return nil, fmt.Errorf("captured prompt is missing from existing event stream")
		}
	}
	return buildForBundle(runDir, &record, d, prompt, &regeneratedBy)
}

// WriteProjectionForRunDir prebuilds and validates digest.json and the event
// stream, stages both on the bundle filesystem, and publishes them as one
// rollback-protected generation. projection.json is committed last and is the
// completion marker for consumers that require pair consistency.
func WriteProjectionForRunDir(runDir string, d *digest.Digest) error {
	events, err := buildEventsForRunDir(runDir, d)
	if err != nil {
		return err
	}
	digestPayload, err := digest.MarshalEvaluation(d)
	if err != nil {
		return fmt.Errorf("marshal digest: %w", err)
	}
	digestPayload = append(digestPayload, '\n')
	if len(digestPayload) > digest.MaxDigestBytes {
		return fmt.Errorf("digest is %d bytes; maximum is %d", len(digestPayload), digest.MaxDigestBytes)
	}
	eventPayload, err := encodeEvents(events)
	if err != nil {
		return err
	}
	generation := fmt.Sprintf("%d", time.Now().UnixNano())
	manifestPayload, err := json.MarshalIndent(struct {
		SchemaVersion int                `json:"schema_version"`
		Producer      runrecord.Producer `json:"producer"`
		Generation    string             `json:"generation"`
		DigestSHA256  string             `json:"digest_sha256"`
		EventsSHA256  string             `json:"events_sha256"`
	}{SchemaVersion: ProjectionSchemaVersion, Producer: d.Producer, Generation: generation,
		DigestSHA256: fmt.Sprintf("%x", sha256.Sum256(digestPayload)), EventsSHA256: fmt.Sprintf("%x", sha256.Sum256(eventPayload))}, "", "  ")
	if err != nil {
		return err
	}
	manifestPayload = append(manifestPayload, '\n')
	finals := []string{"digest.json", Filename, "projection.json"}
	payloads := [][]byte{digestPayload, eventPayload, manifestPayload}
	staged := make([]string, len(finals))
	backups := make([]string, len(finals))
	for index := range finals {
		staged[index] = filepath.Join(runDir, "."+finals[index]+".staged-"+generation)
		backups[index] = filepath.Join(runDir, "."+finals[index]+".backup-"+generation)
		if err := securefile.WriteFile(staged[index], payloads[index]); err != nil {
			for _, path := range staged {
				_ = os.Remove(path)
			}
			return fmt.Errorf("stage projection: %w", err)
		}
	}
	rollback := func(published int) error {
		var rollbackErr error
		for index := 0; index < published; index++ {
			_ = os.Remove(filepath.Join(runDir, finals[index]))
		}
		for index := range finals {
			if _, err := os.Stat(backups[index]); err == nil {
				rollbackErr = errors.Join(rollbackErr, os.Rename(backups[index], filepath.Join(runDir, finals[index])))
			}
			_ = os.Remove(staged[index])
		}
		return rollbackErr
	}
	for index, name := range finals {
		finalPath := filepath.Join(runDir, name)
		if _, err := os.Stat(finalPath); err == nil {
			if err := os.Rename(finalPath, backups[index]); err != nil {
				return errors.Join(fmt.Errorf("backup projection %s: %w", name, err), rollback(0))
			}
		}
	}
	for index, name := range finals {
		if err := os.Rename(staged[index], filepath.Join(runDir, name)); err != nil {
			return errors.Join(fmt.Errorf("publish projection %s: %w", name, err), rollback(index))
		}
	}
	if err := securefile.SyncDirectory(runDir); err != nil {
		rollbackErr := rollback(len(finals))
		_ = securefile.SyncDirectory(runDir)
		return errors.Join(fmt.Errorf("sync published projection directory: %w", err), rollbackErr)
	}
	for _, backup := range backups {
		_ = os.Remove(backup)
	}
	// The projection generation is already durable. Backup cleanup is
	// best-effort and does not invalidate the committed manifest.
	_ = securefile.SyncDirectory(runDir)
	return nil
}

func capturedPromptFromEventStream(runDir, runID string) (string, error) {
	path := filepath.Join(runDir, Filename)
	f, err := securefile.OpenRegular(runDir, path)
	if err != nil {
		return "", fmt.Errorf("open existing acta events: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), MaxEventBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return "", fmt.Errorf("parse existing acta event: %w", err)
		}
		if err := ValidateEnvelope(event, runID, 1); err != nil {
			return "", fmt.Errorf("validate existing prompt event: %w", err)
		}
		if event.Type != TypeAgentPrompt {
			return "", nil
		}
		var payload agentPromptPayload
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return "", fmt.Errorf("parse existing agent prompt: %w", err)
		}
		return payload.Text, nil
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read existing acta events: %w", err)
	}
	return "", nil
}

func (b *builder) appendTimelineEvent(record *runrecord.Record, item digest.Event) error {
	typ := timelineType(item)
	eventTime := timelineTimes(record, item)
	text := item.Text
	if item.Kind == digest.KindReasoning {
		text = item.LocalReasoningText()
	}
	seq, err := b.append(typ, eventTime, timelinePayload{
		Kind: item.Kind, ProviderEvent: item.ProviderEvent,
		ID: item.ID, ParentID: item.ParentID, ThreadID: item.ThreadID,
		SessionID: item.SessionID, TaskID: item.TaskID,
		Phase: item.Phase, Status: item.Status, Visibility: item.Visibility,
		StartedAt: item.ObservedAt, CompletedAt: item.CompletedAt,
		Tool: item.Tool, Server: item.Server,
		Input: item.Input, InputChars: item.InputChars, InputTruncated: item.InputTruncated,
		Result: item.Result, ResultChars: item.ResultChars, ResultTruncated: item.ResultTruncated,
		Command: item.Command, ExitCode: item.ExitCode, IsError: item.IsError,
		ErrorMessage: item.ErrorMessage,
		Output:       item.Output, OutputChars: item.OutputChars, OutputTruncated: item.OutputTruncated,
		Text: text, TextChars: item.TextChars, TextTruncated: item.TextTruncated,
		Query: item.Query, Action: item.Action,
		Files: item.Files, Changes: item.Changes, Spans: item.Spans,
		Patches: item.FilePatches,
		Details: item.Details, RawEventLines: item.RawEventLines, Redacted: item.Redacted,
	}, rawTimelineArtifactRefs(b.bundleDir, record, item)...)
	if err != nil {
		return err
	}
	if item.Kind != digest.KindFileEdit {
		return b.appendFileReadEvents(seq, eventTime, item)
	}
	return nil
}

// timelineTimes picks the wall-clock timestamp for a timeline event: the
// completion time for events that represent a finished action, otherwise the
// observed start, falling back to the run start when the item carries no time.
func timelineTimes(record *runrecord.Record, item digest.Event) time.Time {
	if item.CompletedAt != nil && !item.CompletedAt.IsZero() {
		return *item.CompletedAt
	}
	if item.ObservedAt != nil {
		return *item.ObservedAt
	}
	return record.StartedAt
}

func (b *builder) appendFileReadEvents(sourceSeq int, eventTime time.Time, item digest.Event) error {
	paths := map[string][]digest.Span{}
	for _, path := range item.Files {
		if path != "" {
			if _, ok := paths[path]; !ok {
				paths[path] = nil
			}
		}
	}
	for path, spans := range item.Spans {
		if path != "" {
			paths[path] = append(paths[path], spans...)
		}
	}
	if len(paths) == 0 {
		return nil
	}

	ordered := make([]string, 0, len(paths))
	for path := range paths {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)

	for _, path := range ordered {
		if _, err := b.append(TypeFileRead, eventTime, fileReadPayload{
			Path:                path,
			Spans:               paths[path],
			Ranges:              item.ReadRanges[path],
			SourceEventSequence: sourceSeq,
			Tool:                item.Tool,
			Command:             item.Command,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (b *builder) append(typ string, timestamp time.Time, payload any, refs ...ArtifactRef) (int, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("marshal %s payload: %w", typ, err)
	}
	seq := b.next
	b.next++
	b.events = append(b.events, Event{
		SchemaVersion: b.schemaVersion,
		Producer:      b.producer,
		RegeneratedBy: b.regeneratedBy,
		RunID:         b.runID,
		Sequence:      seq,
		Timestamp:     normalizeTime(timestamp),
		Source:        Source,
		Type:          typ,
		Payload:       raw,
		ArtifactRefs:  refs,
	})
	encoded, err := json.Marshal(b.events[len(b.events)-1])
	if err != nil {
		return 0, fmt.Errorf("marshal %s event: %w", typ, err)
	}
	if len(encoded)+1 > MaxEventBytes {
		b.events = b.events[:len(b.events)-1]
		return 0, fmt.Errorf("%s event exceeds maximum encoded size %d bytes", typ, MaxEventBytes)
	}
	b.bytes += len(encoded) + 1
	if b.bytes > MaxStreamBytes {
		b.events = b.events[:len(b.events)-1]
		return 0, fmt.Errorf("normalized event projection exceeds maximum size %d bytes", MaxStreamBytes)
	}
	return seq, nil
}

func timelineType(item digest.Event) string {
	switch item.Kind {
	case digest.KindCommand:
		if item.Status == "incomplete" {
			return TypeShellCommandIncomplete
		}
		return TypeShellCommandComplete
	case digest.KindToolCall:
		if item.Status == "incomplete" {
			return TypeToolCallIncomplete
		}
		return TypeToolCallCompleted
	case digest.KindToolResult:
		return TypeToolResultOrphaned
	case digest.KindMessage:
		return TypeAgentMessage
	case digest.KindUserInput:
		return TypeAgentInput
	case digest.KindReasoning:
		return TypeAgentReasoning
	case digest.KindFileEdit:
		if item.Status == "incomplete" {
			return TypeFileWriteIncomplete
		}
		return TypeFileWritten
	case digest.KindTodo:
		if item.Phase == "updated" {
			return TypeAgentTodoUpdated
		}
		return TypeAgentTodo
	case digest.KindWebSearch:
		if item.Status == "incomplete" {
			return TypeWebSearchIncomplete
		}
		return TypeWebSearchCompleted
	case digest.KindTask:
		switch item.Phase {
		case "started":
			return TypeAgentTaskStarted
		case "progress":
			return TypeAgentTaskProgress
		case "incomplete":
			return TypeAgentTaskIncomplete
		case "completed", "notification":
			return TypeAgentTaskCompleted
		default:
			return TypeAgentEventUnsupported
		}
	case digest.KindPermission:
		return TypeAgentPermissionDenied
	case digest.KindRuntime:
		return TypeAgentRuntimeConfigured
	case digest.KindRateLimit:
		return TypeAgentRateLimitObserved
	case digest.KindStructuredOutput:
		return TypeAgentStructuredOutput
	case digest.KindError:
		return TypeAgentError
	case digest.KindLifecycle:
		return TypeAgentLifecycle
	case digest.KindUnsupported:
		return TypeAgentEventUnsupported
	default:
		return TypeAgentEventUnsupported
	}
}

func rawTimelineArtifactRefs(bundleDir string, record *runrecord.Record, item digest.Event) []ArtifactRef {
	if strings.TrimSpace(record.RawStdoutPath) == "" && strings.TrimSpace(record.RawStdoutArtifact) == "" {
		return nil
	}
	rel := record.RawStdoutArtifact
	if rel == "" {
		rel = artifactPath(record.RunDir, record.RawStdoutPath)
	}
	if _, err := os.Stat(filepath.Join(bundleDir, filepath.FromSlash(rel))); err != nil {
		return nil
	}
	return []ArtifactRef{{
		Kind:  "raw_stdout",
		Path:  rel,
		Lines: item.RawEventLines,
	}}
}

func normalizeTime(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return t.UTC()
}

func hasTokens(tokens digest.TokenUsage) bool {
	return tokens.Input != 0 ||
		tokens.Output != 0 ||
		tokens.CacheRead != 0 ||
		tokens.CacheCreation != 0 ||
		tokens.Reasoning != 0 ||
		tokens.Total != 0
}

func completionArtifacts(bundleDir string, record *runrecord.Record, d *digest.Digest) []ArtifactRef {
	var refs []ArtifactRef
	// Only reference artifacts that are actually on disk, so a partial or failed
	// run never ships a terminal event pointing a consumer at a file that was
	// never written (e.g. digest.json when digest.Write failed mid-run).
	add := func(kind string, path string) {
		if strings.TrimSpace(path) == "" {
			return
		}
		rel := artifactPath(record.RunDir, path)
		if _, err := os.Stat(filepath.Join(bundleDir, filepath.FromSlash(rel))); err != nil {
			return
		}
		refs = append(refs, ArtifactRef{Kind: kind, Path: rel})
	}
	add("run_record", filepath.Join(record.RunDir, "run.json"))
	add("raw_stdout", record.RawStdoutPath)
	add("raw_stderr", record.RawStderrPath)
	add("event_times", filepath.Join(record.RunDir, "event-times.jsonl"))
	add("digest", filepath.Join(record.RunDir, "digest.json"))
	// event_stream is this file, written immediately after Build returns, so it
	// is guaranteed to exist once Write completes and cannot be stat-gated here.
	refs = append(refs, ArtifactRef{Kind: "event_stream", Path: Filename})
	if d.HasWorkspaceDiff {
		add("workspace_diff", filepath.Join(record.RunDir, "workspace.diff"))
	}
	return refs
}

func artifactPath(runDir string, path string) string {
	if runDir != "" {
		if rel, err := filepath.Rel(runDir, path); err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(filepath.Base(path))
}

type runStartedPayload struct {
	Agent         string `json:"agent"`
	AgentVersion  string `json:"agent_version,omitempty"`
	Model         string `json:"model,omitempty"`
	CWD           string `json:"cwd"`
	BaseCommitSHA string `json:"base_commit_sha,omitempty"`
	BaseBranch    string `json:"base_branch,omitempty"`
	// Pointer so "verified clean" (false) still serializes; absent means the
	// workspace was not a git repo or capture failed.
	BaseDirty               *bool    `json:"base_dirty,omitempty"`
	Repository              string   `json:"repository,omitempty"`
	IssueNumber             int      `json:"issue_number,omitempty"`
	IssueTitle              string   `json:"issue_title,omitempty"`
	IssueBody               *string  `json:"issue_body,omitempty"`
	TaskTitle               string   `json:"task_title,omitempty"`
	RunDir                  string   `json:"run_dir"`
	RecoveryDir             string   `json:"recovery_dir,omitempty"`
	Command                 []string `json:"command,omitempty"`
	PromptSource            string   `json:"prompt_source,omitempty"`
	PromptCaptured          bool     `json:"prompt_captured,omitempty"`
	OTLPStatus              string   `json:"otlp_status,omitempty"`
	OTLPError               string   `json:"otlp_error,omitempty"`
	RawOutputLimitBytes     int64    `json:"raw_output_limit_bytes,omitempty"`
	WorkspaceDiffLimitBytes int64    `json:"workspace_diff_limit_bytes,omitempty"`
	ProcessContainment      string   `json:"process_containment,omitempty"`
	AgentConfigMode         string   `json:"agent_config_mode,omitempty"`
	RuntimeBundleSHA256     string   `json:"runtime_bundle_sha256,omitempty"`
	ReasoningRedactionState string   `json:"reasoning_redaction_state,omitempty"`
}

type agentPromptPayload struct {
	Text   string `json:"text"`
	Source string `json:"source,omitempty"`
}

type timelinePayload struct {
	Kind            string                   `json:"kind"`
	ProviderEvent   string                   `json:"provider_event,omitempty"`
	ID              string                   `json:"id,omitempty"`
	ParentID        string                   `json:"parent_id,omitempty"`
	ThreadID        string                   `json:"thread_id,omitempty"`
	SessionID       string                   `json:"session_id,omitempty"`
	TaskID          string                   `json:"task_id,omitempty"`
	Phase           string                   `json:"phase,omitempty"`
	Status          string                   `json:"status,omitempty"`
	Visibility      string                   `json:"visibility,omitempty"`
	StartedAt       *time.Time               `json:"started_at,omitempty"`
	CompletedAt     *time.Time               `json:"completed_at,omitempty"`
	Tool            string                   `json:"tool,omitempty"`
	Server          string                   `json:"server,omitempty"`
	Input           json.RawMessage          `json:"input,omitempty"`
	InputChars      int                      `json:"input_chars,omitempty"`
	InputTruncated  bool                     `json:"input_truncated,omitempty"`
	Result          json.RawMessage          `json:"result,omitempty"`
	ResultChars     int                      `json:"result_chars,omitempty"`
	ResultTruncated bool                     `json:"result_truncated,omitempty"`
	Command         string                   `json:"command,omitempty"`
	ExitCode        *int                     `json:"exit_code,omitempty"`
	IsError         bool                     `json:"is_error,omitempty"`
	ErrorMessage    string                   `json:"error_message,omitempty"`
	Output          string                   `json:"output,omitempty"`
	OutputChars     int                      `json:"output_chars,omitempty"`
	OutputTruncated bool                     `json:"output_truncated,omitempty"`
	Text            string                   `json:"text,omitempty"`
	TextChars       int                      `json:"text_chars,omitempty"`
	TextTruncated   bool                     `json:"text_truncated,omitempty"`
	Query           string                   `json:"query,omitempty"`
	Action          json.RawMessage          `json:"action,omitempty"`
	Files           []string                 `json:"files,omitempty"`
	Changes         []digest.FileMutation    `json:"changes,omitempty"`
	Spans           map[string][]digest.Span `json:"spans,omitempty"`
	Patches         []digest.FilePatch       `json:"patches,omitempty"`
	Details         json.RawMessage          `json:"details,omitempty"`
	RawEventLines   []int                    `json:"raw_event_lines,omitempty"`
	Redacted        bool                     `json:"redacted,omitempty"`
}

type fileReadPayload struct {
	Path                string             `json:"path"`
	Spans               []digest.Span      `json:"spans,omitempty"`
	Ranges              []digest.ReadRange `json:"ranges,omitempty"`
	SourceEventSequence int                `json:"source_event_sequence"`
	Tool                string             `json:"tool,omitempty"`
	Command             string             `json:"command,omitempty"`
}

type diffPayload struct {
	Path string `json:"path"`
}

type tokensPayload struct {
	Tokens  digest.TokenUsage `json:"tokens"`
	CostUSD float64           `json:"cost_usd,omitempty"`
}

type runCompletedPayload struct {
	Status                     string             `json:"status"`
	OK                         bool               `json:"ok"`
	Timeout                    bool               `json:"timeout"`
	ExitCode                   *int               `json:"exit_code,omitempty"`
	HeadCommitSHA              string             `json:"head_commit_sha,omitempty"`
	DurationMillis             int64              `json:"duration_ms"`
	Error                      string             `json:"error,omitempty"`
	Termination                digest.Termination `json:"termination,omitempty"`
	UnsupportedEvents          map[string]int     `json:"unsupported_events,omitempty"`
	IncompleteToolCalls        int                `json:"incomplete_tool_calls,omitempty"`
	OrphanedToolResults        int                `json:"orphaned_tool_results,omitempty"`
	StructuredOutput           json.RawMessage    `json:"structured_output,omitempty"`
	ModelUsage                 json.RawMessage    `json:"model_usage,omitempty"`
	RawOutputLimitBytes        int64              `json:"raw_output_limit_bytes,omitempty"`
	RawOutputLimitExceeded     bool               `json:"raw_output_limit_exceeded,omitempty"`
	WorkspaceDiffLimitBytes    int64              `json:"workspace_diff_limit_bytes,omitempty"`
	WorkspaceDiffLimitExceeded bool               `json:"workspace_diff_limit_exceeded,omitempty"`
}
