// Package digest normalizes raw agent output (codex exec --json events,
// claude --print stream-json) into a versioned, reporting-oriented digest:
// a timeline of what the agent did, metrics, and the files it looked at.
package digest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nobbettt/acta/internal/reasoning"
	"github.com/nobbettt/acta/internal/runrecord"
	"github.com/nobbettt/acta/internal/schemaversion"
	"github.com/nobbettt/acta/internal/securefile"
)

const (
	SchemaVersion    = 3
	MinSchemaVersion = 2

	OutcomeCompleted   = "completed"
	OutcomeFailed      = "failed"
	OutcomeError       = "error"
	OutcomeTimeout     = "timeout"
	OutcomeCancelled   = "cancelled"
	OutcomeInterrupted = "interrupted"
	OutcomeDegraded    = "degraded"

	StatusOK       = "ok"
	StatusError    = "error"
	StatusTimeout  = "timeout"
	StatusDegraded = "degraded"
)

// MaxEventOutputChars caps per-event output stored in the digest; the raw
// JSONL in the bundle keeps full fidelity.
const MaxEventOutputChars = 8_000

// MaxEventInputChars caps per-event tool input stored in the digest. A single
// large edit (Write/MultiEdit carrying a whole file) would otherwise bloat the
// digest with content the raw JSONL already holds verbatim.
const MaxEventInputChars = 8_000

// MaxEventTextBytes bounds every free-form normalized string. Raw provider
// streams remain the full-fidelity evidence source.
const MaxEventTextBytes = reasoning.MaxTextBytes

// Projection limits prevent an arbitrarily long provider stream from being
// retained in memory twice (as Digest and then as encoded Acta events).
const (
	MaxTimelineEvents  = 100_000
	MaxProjectionBytes = 64 << 20
	MaxDigestBytes     = 64 << 20
)

// Event kinds.
const (
	KindToolCall         = "tool_call"
	KindToolResult       = "tool_result"
	KindCommand          = "command"
	KindMessage          = "message"
	KindUserInput        = "user_input"
	KindReasoning        = "reasoning"
	KindFileEdit         = "file_edit"
	KindTodo             = "todo"
	KindWebSearch        = "web_search"
	KindTask             = "task"
	KindPermission       = "permission"
	KindRuntime          = "runtime"
	KindLifecycle        = "lifecycle"
	KindRateLimit        = "rate_limit"
	KindStructuredOutput = "structured_output"
	KindError            = "error"
	KindUnsupported      = "unsupported"

	VisibilityPrimary    = "primary"
	VisibilityDiagnostic = "diagnostic"
)

type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// ReadRange retains the exact provider output attributed to one file span.
// Content is only populated when the parser can link the output to one file
// without guessing across combined command results.
type ReadRange struct {
	Start   int    `json:"start"`
	End     int    `json:"end"`
	Content string `json:"content"`
}

// FilePatch is the exact per-write unified diff captured while the agent was
// running. It is distinct from the cumulative workspace.diff artifact.
type FilePatch struct {
	Path  string `json:"path"`
	Patch string `json:"patch"`
}

type Event struct {
	Kind            string                 `json:"kind"`
	ProviderEvent   string                 `json:"provider_event,omitempty"`
	ID              string                 `json:"id,omitempty"`
	ParentID        string                 `json:"parent_id,omitempty"`
	ThreadID        string                 `json:"thread_id,omitempty"`
	SessionID       string                 `json:"session_id,omitempty"`
	TaskID          string                 `json:"task_id,omitempty"`
	Phase           string                 `json:"phase,omitempty"`
	Status          string                 `json:"status,omitempty"`
	Visibility      string                 `json:"visibility,omitempty"`
	ObservedAt      *time.Time             `json:"observed_at,omitempty"`
	CompletedAt     *time.Time             `json:"completed_at,omitempty"`
	Tool            string                 `json:"tool,omitempty"`
	Server          string                 `json:"server,omitempty"`
	Input           json.RawMessage        `json:"input,omitempty"`
	InputChars      int                    `json:"input_chars,omitempty"`
	InputTruncated  bool                   `json:"input_truncated,omitempty"`
	Result          json.RawMessage        `json:"result,omitempty"`
	ResultChars     int                    `json:"result_chars,omitempty"`
	ResultTruncated bool                   `json:"result_truncated,omitempty"`
	Command         string                 `json:"command,omitempty"`
	ExitCode        *int                   `json:"exit_code,omitempty"`
	IsError         bool                   `json:"is_error,omitempty"`
	ErrorMessage    string                 `json:"error_message,omitempty"`
	Output          string                 `json:"output,omitempty"`
	OutputChars     int                    `json:"output_chars,omitempty"`
	OutputTruncated bool                   `json:"output_truncated,omitempty"`
	Text            string                 `json:"text,omitempty"`
	TextChars       int                    `json:"text_chars,omitempty"`
	TextTruncated   bool                   `json:"text_truncated,omitempty"`
	Query           string                 `json:"query,omitempty"`
	Action          json.RawMessage        `json:"action,omitempty"`
	Files           []string               `json:"files,omitempty"`
	Changes         []FileMutation         `json:"changes,omitempty"`
	Spans           map[string][]Span      `json:"spans,omitempty"`
	ReadRanges      map[string][]ReadRange `json:"read_ranges,omitempty"`
	FilePatches     []FilePatch            `json:"file_patches,omitempty"`
	FilePatchStatus string                 `json:"file_patch_status,omitempty"`
	FilePatchErrors []string               `json:"file_patch_errors,omitempty"`
	Details         json.RawMessage        `json:"details,omitempty"`
	RawEventLines   []int                  `json:"raw_event_lines,omitempty"`
	Redacted        bool                   `json:"redacted,omitempty"`

	srcLine       int // raw JSONL line that produced this event, for the sidecar join
	inputFilePath string
	inputPath     string
	completedLine int
	fileSnapshots []fileWriteSnapshot
	// localReasoningText is deliberately excluded from digest serialization.
	// It exists only long enough to build the local normalized event stream.
	localReasoningText string
}

// LocalReasoningText returns provider-private reasoning for the local event
// projection. Callers must never use it for telemetry, digests, summaries, or
// evaluation inputs.
func (e Event) LocalReasoningText() string {
	return e.localReasoningText
}

// RedactReasoning removes provider-private reasoning from the in-memory local
// projection before a redacted bundle is persisted. Structural events and raw
// line references remain intact. It reports whether every payload was safely
// inspected; unverifiable payloads are still conservatively masked.
func RedactReasoning(d *Digest) bool {
	if d == nil {
		return true
	}
	verified := true
	for i := range d.Timeline {
		event := &d.Timeline[i]
		if isReasoningEvent(*event) {
			redactEventPayload(event)
			continue
		}
		if isKnownEventKind(event.Kind) {
			details, changed, detailsVerified := redactEventDetails(event.Kind, event.ProviderEvent, event.Details)
			verified = detailsVerified && verified
			if changed {
				event.Details = details
				event.Redacted = true
			}
			continue
		}
		redactEventPayload(event)
		event.Details = json.RawMessage(`"` + reasoning.RedactedMarker + `"`)
	}
	return verified
}

func redactEventPayload(event *Event) {
	event.Redacted = true
	event.Text = ""
	event.localReasoningText = ""
	event.Input = nil
	event.Result = nil
	event.Command = ""
	event.ErrorMessage = ""
	event.Output = ""
	event.Query = ""
	event.Action = nil
	event.Details = nil
}

func isReasoningEvent(event Event) bool {
	if event.Kind == KindReasoning {
		return true
	}
	var details struct {
		Type string `json:"type"`
	}
	if len(event.Details) > 0 {
		if err := reasoning.ValidateUniqueObjectKeys(event.Details); err != nil {
			return false
		}
		_ = json.Unmarshal(event.Details, &details)
	}
	return reasoning.IsNormalizedEvent(event.Kind, event.ProviderEvent, details.Type)
}

func isKnownEventKind(kind string) bool {
	switch kind {
	case KindToolCall, KindToolResult, KindCommand, KindMessage, KindUserInput,
		KindReasoning, KindFileEdit, KindTodo, KindWebSearch, KindTask,
		KindPermission, KindRuntime, KindLifecycle, KindRateLimit,
		KindStructuredOutput, KindError, KindUnsupported:
		return true
	default:
		return false
	}
}

// redactEventDetails retains inspectable normalized details while applying the
// shared exact and generic reasoning passes to raw-backed payloads regardless
// of whether their event kind is known. Unverifiable details are replaced with
// an explicit marker and reported to the caller.
func redactEventDetails(kind, providerEvent string, raw json.RawMessage) (json.RawMessage, bool, bool) {
	if len(raw) == 0 {
		return raw, false, true
	}
	if err := reasoning.ValidateUniqueObjectKeys(raw); err != nil {
		return json.RawMessage(`"` + reasoning.RedactedMarker + `"`), true, false
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return json.RawMessage(`"` + reasoning.RedactedMarker + `"`), true, false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return json.RawMessage(`"` + reasoning.RedactedMarker + `"`), true, false
	}
	payload := map[string]any{
		"kind":           kind,
		"provider_event": providerEvent,
		"details":        value,
	}
	var changed, verified bool
	if kind == KindUnsupported {
		_, changed, verified = reasoning.RedactUnsupportedPayload(payload)
	} else {
		changed, verified = reasoning.RedactValue(payload, reasoning.NormalizedTraversal(""))
	}
	if !verified {
		return json.RawMessage(`"` + reasoning.RedactedMarker + `"`), true, false
	}
	if !changed {
		return raw, false, true
	}
	redacted, err := json.Marshal(payload["details"])
	if err != nil {
		return json.RawMessage(`"` + reasoning.RedactedMarker + `"`), true, false
	}
	return redacted, true, true
}

type FileMutation struct {
	Path string `json:"path"`
	Kind string `json:"kind,omitempty"`
}

type TokenUsage struct {
	Input         int64 `json:"input"`
	Output        int64 `json:"output"`
	CacheRead     int64 `json:"cache_read,omitempty"`
	CacheCreation int64 `json:"cache_creation,omitempty"`
	Reasoning     int64 `json:"reasoning,omitempty"`
	Total         int64 `json:"total"`
}

type Metrics struct {
	DurationMillis int64          `json:"duration_ms"`
	Turns          int            `json:"turns,omitempty"`
	ToolCalls      map[string]int `json:"tool_calls,omitempty"`
	Commands       int            `json:"commands"`
	Edits          int            `json:"edits"`
	Tokens         TokenUsage     `json:"tokens"`
	CostUSD        float64        `json:"cost_usd,omitempty"`
	// ParseErrors counts non-blank raw stream lines that failed to decode, so a
	// truncated or corrupt stream yields a digest that admits it is incomplete
	// rather than looking complete while silently missing events.
	ParseErrors         int            `json:"parse_errors,omitempty"`
	UnsupportedEvents   map[string]int `json:"unsupported_events,omitempty"`
	IncompleteToolCalls int            `json:"incomplete_tool_calls,omitempty"`
	OrphanedToolResults int            `json:"orphaned_tool_results,omitempty"`
	DroppedEvents       int            `json:"dropped_events,omitempty"`
	ProjectionTruncated bool           `json:"projection_truncated,omitempty"`
}

type Termination struct {
	Outcome         string `json:"outcome,omitempty"`
	ProviderReason  string `json:"provider_reason,omitempty"`
	ProviderSubtype string `json:"provider_subtype,omitempty"`
	RunnerReason    string `json:"runner_reason,omitempty"`
	ErrorCode       string `json:"error_code,omitempty"`
	ErrorMessage    string `json:"error_message,omitempty"`
}

type RuntimeInfo struct {
	Version        string          `json:"version,omitempty"`
	PermissionMode string          `json:"permission_mode,omitempty"`
	Tools          []string        `json:"tools,omitempty"`
	Agents         []string        `json:"agents,omitempty"`
	Skills         []string        `json:"skills,omitempty"`
	Commands       []string        `json:"commands,omitempty"`
	MCPServers     json.RawMessage `json:"mcp_servers,omitempty"`
	Plugins        json.RawMessage `json:"plugins,omitempty"`
}

// renderChecklist formats "[x]/[ ] item" lines for a todo list, shared by both
// agents' todo rendering so the marker format lives in one place.
func renderChecklist[T any](items []T, text func(T) string, done func(T) bool) string {
	var b strings.Builder
	for _, it := range items {
		mark := " "
		if done(it) {
			mark = "x"
		}
		fmt.Fprintf(&b, "[%s] %s\n", mark, text(it))
	}
	return strings.TrimRight(b.String(), "\n")
}

// countParseError records a raw stream line that failed to decode. Blank lines
// (trailing newlines etc.) are not corruption and are ignored.
func (d *Digest) countParseError(line []byte) {
	if len(bytes.TrimSpace(line)) > 0 {
		d.Metrics.ParseErrors++
	}
}

// countTool records one call of the named tool, creating the map on first use
// so parsers need no eager init / nil-out dance for omitempty.
func (m *Metrics) countTool(name string) {
	if m.ToolCalls == nil {
		m.ToolCalls = map[string]int{}
	}
	m.ToolCalls[name]++
}

type FileTouch struct {
	Path      string `json:"path"`
	Read      bool   `json:"read"`
	Edited    bool   `json:"edited"`
	ReadSpans []Span `json:"read_spans,omitempty"`
}

type Digest struct {
	SchemaVersion              int                `json:"schema_version"`
	Producer                   runrecord.Producer `json:"producer,omitempty"`
	RunID                      string             `json:"run_id"`
	Agent                      string             `json:"agent"`
	AgentVersion               string             `json:"agent_version,omitempty"`
	Model                      string             `json:"model,omitempty"`
	ThreadID                   string             `json:"thread_id,omitempty"`
	SessionID                  string             `json:"session_id,omitempty"`
	Status                     string             `json:"status"` // ok | error | timeout
	Timeline                   []Event            `json:"timeline"`
	Metrics                    Metrics            `json:"metrics"`
	Files                      []FileTouch        `json:"files"`
	FinalMessage               string             `json:"final_message,omitempty"`
	StructuredOutput           json.RawMessage    `json:"structured_output,omitempty"`
	ModelUsage                 json.RawMessage    `json:"model_usage,omitempty"`
	Runtime                    RuntimeInfo        `json:"runtime,omitempty"`
	Termination                Termination        `json:"termination,omitempty"`
	Error                      string             `json:"error,omitempty"`
	HasWorkspaceDiff           bool               `json:"has_workspace_diff"`
	OTLPStatus                 string             `json:"otlp_status,omitempty"`
	OTLPError                  string             `json:"otlp_error,omitempty"`
	RawOutputLimitBytes        int64              `json:"raw_output_limit_bytes,omitempty"`
	RawOutputLimitExceeded     bool               `json:"raw_output_limit_exceeded,omitempty"`
	WorkspaceDiffLimitBytes    int64              `json:"workspace_diff_limit_bytes,omitempty"`
	WorkspaceDiffLimitExceeded bool               `json:"workspace_diff_limit_exceeded,omitempty"`
	ProcessContainment         string             `json:"process_containment,omitempty"`
	AgentConfigMode            string             `json:"agent_config_mode,omitempty"`
	RuntimeBundleSHA256        string             `json:"runtime_bundle_sha256,omitempty"`
	RecoveryDir                string             `json:"recovery_dir,omitempty"`
	PatchPreservation          PatchPreservation  `json:"patch_preservation,omitempty"`

	projectionBytes      int
	projectionLimitBytes int
	presentV3Fields      []string
}

// UnmarshalJSON retains explicit v3-only field presence even when omitempty
// would hide a decoded false or zero value during validation.
func (d *Digest) UnmarshalJSON(data []byte) error {
	type plainDigest Digest
	var decoded plainDigest
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	fields, err := schemaversion.PresentV3OnlyFieldsJSON(schemaversion.Digest, data)
	if err != nil {
		return err
	}
	*d = Digest(decoded)
	d.presentV3Fields = fields
	return nil
}

// Validate checks the versioned fields that readers must interpret before
// using a persisted digest. Schema v3 adds not_sampled without changing the
// closed v2 OTLP status vocabulary.
func (d *Digest) Validate() error {
	if d == nil {
		return fmt.Errorf("digest is nil")
	}
	if d.SchemaVersion < MinSchemaVersion || d.SchemaVersion > SchemaVersion {
		return fmt.Errorf("unsupported digest schema_version %d (supported %d..%d)", d.SchemaVersion, MinSchemaVersion, SchemaVersion)
	}
	if !runrecord.SupportsV3Fields(d.SchemaVersion) {
		field, found, err := schemaversion.FirstPresentV3OnlyField(schemaversion.Digest, d, d.presentV3Fields)
		if err != nil {
			return fmt.Errorf("inspect digest versioned fields: %w", err)
		}
		if found {
			return fmt.Errorf("digest schema_version %d does not support %s", d.SchemaVersion, field)
		}
	}
	validOTLPStatus := d.OTLPStatus == "" || oneOf(d.OTLPStatus, "not_configured", "exported", "failed")
	if runrecord.SupportsV3Fields(d.SchemaVersion) {
		validOTLPStatus = validOTLPStatus || oneOf(d.OTLPStatus, "not_sampled", "pending")
	}
	if !validOTLPStatus {
		return fmt.Errorf("digest schema_version %d has invalid otlp_status %q", d.SchemaVersion, d.OTLPStatus)
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func (d *Digest) projectionLimit() int {
	if d != nil && d.projectionLimitBytes > 0 {
		return d.projectionLimitBytes
	}
	return MaxProjectionBytes
}

func (d *Digest) appendEvent(event Event) bool {
	normalizeEvent(&event)
	eventBytes, err := eventProjectionBytes(event)
	if err != nil || len(d.Timeline) >= MaxTimelineEvents || d.projectionBytes+eventBytes > d.projectionLimit() {
		d.Metrics.DroppedEvents++
		d.Metrics.ProjectionTruncated = true
		return false
	}
	d.projectionBytes += eventBytes
	d.Timeline = append(d.Timeline, event)
	return true
}

// eventProjectionBytes accounts for the encoded event plus local-only
// reasoning exactly as if that text occupied the normalized event's text
// field. Reasoning is excluded from digest JSON, but it is retained in memory
// and copied into the local Acta event stream, so it shares the same projection
// budget as every other retained string.
func eventProjectionBytes(event Event) (int, error) {
	encoded, err := json.Marshal(event)
	if err != nil {
		return 0, err
	}
	size := len(encoded)
	if event.localReasoningText != "" {
		reasoning, err := json.Marshal(event.localReasoningText)
		if err != nil {
			return 0, err
		}
		size += len(`,"text":`) + len(reasoning)
	}
	return size, nil
}

func normalizeEvent(event *Event) {
	capString := func(value *string) { *value = Truncate(*value, MaxEventTextBytes) }
	for _, value := range []*string{
		&event.ProviderEvent, &event.ID, &event.ParentID, &event.ThreadID, &event.SessionID,
		&event.TaskID, &event.Phase, &event.Status, &event.Visibility, &event.Tool,
		&event.Server, &event.Command, &event.ErrorMessage, &event.Output, &event.Query,
	} {
		capString(value)
	}
	if event.Redacted && event.Kind == KindReasoning {
		// A re-digested redacted block may carry the original metadata stamped
		// by the raw-stream redactor. Never replace it with marker metadata.
		event.Text = ""
		event.localReasoningText = ""
	} else {
		event.Text, event.TextChars, event.TextTruncated = capText(event.Text)
		if event.localReasoningText != "" {
			event.localReasoningText, event.TextChars, event.TextTruncated = capText(event.localReasoningText)
		}
	}
	event.Input = capInput(event.Input)
	event.Result = capInput(event.Result)
	event.Action = capInput(event.Action)
	event.Details = capInput(event.Details)
	if len(event.Files) > 1024 {
		event.Files = event.Files[:1024]
	}
	for index := range event.Files {
		event.Files[index] = Truncate(event.Files[index], 4096)
	}
	if len(event.Changes) > 1024 {
		event.Changes = event.Changes[:1024]
	}
	for index := range event.Changes {
		event.Changes[index].Path = Truncate(event.Changes[index].Path, 4096)
		event.Changes[index].Kind = Truncate(event.Changes[index].Kind, 256)
	}
	for path, ranges := range event.ReadRanges {
		if len(ranges) > 1024 {
			ranges = ranges[:1024]
		}
		for index := range ranges {
			ranges[index].Content = Truncate(ranges[index].Content, MaxEventTextBytes)
		}
		if path != Truncate(path, 4096) {
			delete(event.ReadRanges, path)
			continue
		}
		event.ReadRanges[path] = ranges
	}
	if len(event.RawEventLines) > 2048 {
		event.RawEventLines = event.RawEventLines[:2048]
	}
}

type PatchPreservation struct {
	Status    string `json:"status,omitempty"` // not_available | preserved | partial | invalid
	Preserved int    `json:"preserved,omitempty"`
	Missing   int    `json:"missing,omitempty"`
	Error     string `json:"error,omitempty"`
}

// OutcomeResolution is the single terminal decision shared by the runner,
// digest and normalized event projection.
type OutcomeResolution struct {
	OK                bool
	Status            string
	TerminationReason string
	Error             string
}

// ResolveOutcome reconciles process/runner state with the provider's terminal
// state. A provider failure, interruption or degraded projection can never be
// promoted to success merely because the subprocess exited zero.
func ResolveOutcome(record *runrecord.Record, d *Digest) OutcomeResolution {
	if record == nil {
		return OutcomeResolution{Status: StatusError, TerminationReason: OutcomeFailed, Error: "run record is nil"}
	}
	result := OutcomeResolution{OK: record.OK, Status: statusFromRecord(*record), TerminationReason: record.TerminationReason, Error: record.Error}
	if record.Timeout {
		result.OK, result.Status, result.TerminationReason = false, StatusTimeout, OutcomeTimeout
		return result
	}
	if record.TerminationReason == OutcomeCancelled {
		result.OK, result.Status = false, StatusError
		return result
	}
	if !record.OK && (result.TerminationReason == "" || result.TerminationReason == OutcomeCompleted) {
		result.TerminationReason = OutcomeFailed
	}
	if record.RawOutputLimitExceeded {
		result.OK, result.Status, result.TerminationReason = false, StatusError, OutcomeError
		if result.Error == "" {
			result.Error = "raw output capture limit exceeded"
		}
	}
	if record.WorkspaceDiffLimitExceeded {
		result.OK, result.Status, result.TerminationReason = false, StatusError, OutcomeError
		if result.Error == "" {
			result.Error = "workspace diff capture limit exceeded"
		}
	}
	if d == nil {
		return result
	}
	switch d.Termination.Outcome {
	case OutcomeFailed, OutcomeError:
		result.OK, result.Status = false, StatusError
		if record.OK {
			result.TerminationReason = d.Termination.Outcome
		}
	case OutcomeInterrupted, OutcomeDegraded:
		result.OK = false
		if record.OK || result.TerminationReason == d.Termination.Outcome {
			result.Status = StatusDegraded
			if record.OK {
				result.TerminationReason = d.Termination.Outcome
			}
		}
	case OutcomeTimeout:
		result.OK = false
		if record.OK {
			result.Status, result.TerminationReason = StatusTimeout, OutcomeTimeout
		}
	case OutcomeCancelled:
		result.OK = false
		if record.OK {
			result.Status, result.TerminationReason = StatusError, OutcomeCancelled
		}
	}
	if !result.OK && result.Error == "" {
		result.Error = firstNonEmpty(d.Termination.ErrorMessage, d.Termination.ProviderReason, "agent run failed")
	}
	return result
}

// ReconcileRecord applies ResolveOutcome and settled record metadata before
// digest.json, run.json, and terminal Acta events are written.
func ReconcileRecord(record *runrecord.Record, d *Digest) {
	if record == nil {
		return
	}
	resolved := ResolveOutcome(record, d)
	record.OK = resolved.OK
	record.TerminationReason = resolved.TerminationReason
	record.Error = resolved.Error
	if d != nil {
		d.SchemaVersion = SchemaVersion
		d.OTLPStatus = record.OTLPStatus
		d.OTLPError = record.OTLPError
		d.Status = resolved.Status
		d.Error = resolved.Error
		d.Termination.RunnerReason = resolved.TerminationReason
		if !resolved.OK && (d.Termination.Outcome == "" || d.Termination.Outcome == OutcomeCompleted) {
			d.Termination.Outcome = resolved.TerminationReason
		}
	}
}

// FromRunDir digests an existing run bundle. workspaceDir overrides the
// workspace root recorded in run.json (pass "" to use the recorded one).
func FromRunDir(runDir string, workspaceDir string) (*Digest, error) {
	return FromRunDirContext(context.Background(), runDir, workspaceDir)
}

func FromRunDirContext(ctx context.Context, runDir string, workspaceDir string) (*Digest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	recordPath := filepath.Join(runDir, "run.json")
	payload, err := securefile.ReadRegularFile(runDir, recordPath, runrecord.MaxRecordBytes)
	if err != nil {
		return nil, fmt.Errorf("read run record: %w", err)
	}
	var record runrecord.Record
	if err := json.Unmarshal(payload, &record); err != nil {
		return nil, fmt.Errorf("parse run record: %w", err)
	}
	if err := record.Validate(); err != nil {
		return nil, fmt.Errorf("validate run record: %w", err)
	}

	if workspaceDir == "" {
		workspaceDir = record.CWD
	}
	ws := newWorkspace(workspaceDir)

	var parse func(io.Reader, *workspace) (*Digest, error)
	switch record.Agent {
	case "codex":
		parse = parseCodex
	case "claude":
		parse = parseClaude
	default:
		return nil, fmt.Errorf("unknown agent %q in run record", record.Agent)
	}

	// Take the raw stream filename from the record instead of re-deriving it
	// from the agent name — one source of truth, no second mapping to drift.
	rawName := strings.TrimSpace(record.RawStdoutArtifact)
	if rawName == "" {
		rawName = portableBase(record.RawStdoutPath)
	}
	if rawName == "" || rawName == "." || rawName == string(filepath.Separator) {
		return nil, fmt.Errorf("run record has no raw stdout path")
	}
	rawName = filepath.FromSlash(rawName)
	raw, err := securefile.OpenRegular(runDir, filepath.Join(runDir, rawName))
	if err != nil {
		return nil, fmt.Errorf("open raw output: %w", err)
	}
	defer raw.Close()

	d, parseErr := parse(contextReader{ctx: ctx, reader: raw}, ws)
	if d == nil {
		return nil, parseErr // fatal: unreadable stream or unknown structure
	}
	applyRecord(d, &record, runDir)
	// Re-digestion is a new Acta-owned projection even when the execution
	// record already uses a supported published schema. Attribute the derived artifacts to the
	// binary performing this projection, never to the historical producer.
	d.Producer = runrecord.CurrentProducer()
	markUnavailableFilePatches(d)
	preserveErr := restoreCapturedFilePatches(ctx, runDir, d)

	// parse_errors (malformed lines) and a sidecar-read failure both leave a
	// usable-but-incomplete digest. Surface either — so `acta digest` exits
	// non-zero and matches the live run's "write the digest, fail loud"
	// behavior — without discarding the events that did parse.
	if err := errors.Join(parseErr, preserveErr, applyEventTimesContext(ctx, runDir, d.Timeline)); err != nil {
		d.Status = StatusDegraded
		d.Termination.Outcome = OutcomeDegraded
		d.Termination.ProviderReason = "projection_incomplete"
		d.Termination.ErrorMessage = Truncate(err.Error(), MaxEventTextBytes)
		d.Error = d.Termination.ErrorMessage
		return d, err
	}
	return d, nil
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

// applyRecord stamps run-record metadata and the assembled file summary onto a
// freshly parsed digest. Shared by FromRunDir (re-digest) and the live
// StreamDigester so the two paths produce identical output.
func applyRecord(d *Digest, record *runrecord.Record, runDir string) {
	d.SchemaVersion = SchemaVersion
	d.Producer = record.Producer
	if strings.TrimSpace(d.Producer.Name) == "" {
		d.Producer = runrecord.CurrentProducer()
	}
	d.RunID = record.ID
	d.Agent = record.Agent
	d.AgentVersion = record.AgentVersion
	d.OTLPStatus = record.OTLPStatus
	d.OTLPError = record.OTLPError
	d.RawOutputLimitBytes = record.RawOutputLimitBytes
	d.RawOutputLimitExceeded = record.RawOutputLimitExceeded
	d.WorkspaceDiffLimitBytes = record.WorkspaceDiffLimitBytes
	d.WorkspaceDiffLimitExceeded = record.WorkspaceDiffLimitExceeded
	d.ProcessContainment = record.ProcessContainment
	d.AgentConfigMode = record.AgentConfigMode
	d.RuntimeBundleSHA256 = record.RuntimeBundleSHA256
	d.RecoveryDir = record.RecoveryDir
	if d.Model == "" {
		d.Model = record.Model
	}
	d.Error = record.Error
	d.Termination.RunnerReason = record.TerminationReason
	switch {
	case record.Timeout:
		d.Termination.Outcome = OutcomeTimeout
	case record.TerminationReason == "cancelled":
		d.Termination.Outcome = OutcomeCancelled
	case !record.OK && (d.Termination.Outcome == "" || d.Termination.Outcome == OutcomeCompleted):
		d.Termination.Outcome = OutcomeFailed
	case d.Termination.Outcome == "":
		d.Termination.Outcome = OutcomeCompleted
	}
	resolved := ResolveOutcome(record, d)
	d.Status = resolved.Status
	if d.Error == "" {
		d.Error = resolved.Error
	}
	d.Metrics.DurationMillis = record.DurationMillis
	d.Files = assembleFiles(d.Timeline)
	if diff, err := os.Stat(filepath.Join(runDir, "workspace.diff")); err == nil && diff.Size() > 0 {
		d.HasWorkspaceDiff = true
	}
}

func portableBase(path string) string {
	path = strings.TrimSpace(strings.ReplaceAll(path, `\`, "/"))
	if index := strings.LastIndexByte(path, '/'); index >= 0 {
		path = path[index+1:]
	}
	return path
}

// StreamDigester builds a Digest incrementally from raw agent-stream lines as
// they arrive during `acta run`, so the bundle need not be re-opened and
// re-decoded after the agent exits. Arrival times are stamped directly, so
// the event-times sidecar join (applyEventTimes) is only for FromRunDir
// re-digestion.
type StreamDigester struct {
	claude *claudeParseState
	codex  *codexParseState
	lineNo int
}

// ProviderOutcome returns the provider's terminal decision without finalizing
// or mutating the projection. Runners can reconcile it before closing the root
// trace, including the important provider-failed/process-exit-zero case.
func (sd *StreamDigester) ProviderOutcome() Termination {
	if sd == nil {
		return Termination{Outcome: OutcomeError, ProviderReason: "missing_stream_digester"}
	}
	if sd.codex != nil {
		if sd.codex.d.Termination.Outcome != "" {
			return sd.codex.d.Termination
		}
		return Termination{Outcome: OutcomeError, ProviderReason: "stream_ended_without_terminal_turn"}
	}
	if sd.claude != nil {
		if sd.claude.d.Termination.Outcome != "" {
			return sd.claude.d.Termination
		}
		if !sd.claude.haveResult {
			return Termination{Outcome: OutcomeError, ProviderReason: "stream_ended_without_result"}
		}
		return Termination{Outcome: OutcomeError, ProviderReason: "invalid_result"}
	}
	return Termination{Outcome: OutcomeError, ProviderReason: "unknown_provider_stream"}
}

// PreviewOutcome reconciles current runner state with ProviderOutcome without
// mutating either object.
func (sd *StreamDigester) PreviewOutcome(record *runrecord.Record) OutcomeResolution {
	return ResolveOutcome(record, &Digest{Termination: sd.ProviderOutcome()})
}

type Options struct {
	// EvidenceExclusions are workspace-relative generated directories omitted
	// from live per-write snapshots (for example a custom runs directory).
	EvidenceExclusions []string
	// WorkspaceIsRepo distinguishes an intentional non-Git workspace (where an
	// initial Git listing is inapplicable) from a repository listing failure.
	WorkspaceIsRepo bool
}

// NewStreamDigester creates a live digester for the given agent, resolving the
// workspace from workspaceDir (usually the run's CWD).
func NewStreamDigester(agent, workspaceDir string) (*StreamDigester, error) {
	// Legacy callers predate explicit Git context and retain the historical
	// initial-workspace capture behavior. Runner code uses WithOptions.
	return NewStreamDigesterWithOptions(agent, workspaceDir, Options{WorkspaceIsRepo: true})
}

func NewStreamDigesterWithOptions(agent, workspaceDir string, options Options) (*StreamDigester, error) {
	ws := newWorkspace(workspaceDir)
	switch agent {
	case "codex":
		state := newCodexState(ws)
		state.writeTracker = newFileWriteTrackerForWorkspace(ws, options.WorkspaceIsRepo, options.EvidenceExclusions...)
		return &StreamDigester{codex: state}, nil
	case "claude":
		return &StreamDigester{claude: &claudeParseState{
			d:            &Digest{},
			ws:           ws,
			writeTracker: newFileWriteTrackerForWorkspace(ws, options.WorkspaceIsRepo, options.EvidenceExclusions...),
			pending:      map[string]int{},
			usageSeen:    map[string]bool{},
		}}, nil
	default:
		return nil, fmt.Errorf("unknown agent %q", agent)
	}
}

// Line feeds one raw stream line with its arrival time. A malformed line is
// counted (countParseError, which ignores blanks) and skipped, but subsequent
// lines are still consumed — matching the offline pull parser so a live digest
// and a re-digest of the same bundle produce identical output. Err() reports
// the accumulated parse errors afterwards, so `acta run` still fails visibly.
func (sd *StreamDigester) Line(raw []byte, at time.Time) {
	sd.lineNo++
	switch {
	case sd.codex != nil:
		var event CodexEvent
		if err := reasoning.UnmarshalProviderLine(raw, &event); err != nil {
			sd.codex.d.countParseError(raw)
			return
		}
		sd.codex.consume(&event, sd.lineNo, at)
	case sd.claude != nil:
		var item ClaudeItem
		if err := reasoning.UnmarshalProviderLine(raw, &item); err != nil {
			sd.claude.d.countParseError(raw)
			return
		}
		sd.claude.consume(&item, sd.lineNo, at)
	}
}

// Err reports a non-nil error when any raw line failed to parse, so the run is
// marked failed even though the digest still captures every line that did parse.
func (sd *StreamDigester) Err() error {
	var parseErr error
	var semanticErr error
	switch {
	case sd.codex != nil:
		if n := sd.codex.d.Metrics.ParseErrors; n > 0 {
			parseErr = fmt.Errorf("parse codex stream: %d malformed JSONL line(s)", n)
		}
		semanticErr = sd.codex.semanticError()
	case sd.claude != nil:
		if n := sd.claude.d.Metrics.ParseErrors; n > 0 {
			parseErr = fmt.Errorf("parse claude stream: %d malformed JSONL line(s)", n)
		}
		semanticErr = sd.claude.semanticError()
	}
	return errors.Join(parseErr, semanticErr)
}

// Finalize applies the run record and returns the completed digest, ready to
// Write. Call after the agent exits and workspace.diff has been written.
func (sd *StreamDigester) Finalize(record *runrecord.Record, runDir string) *Digest {
	var d *Digest
	if sd.claude != nil {
		d = sd.claude.finalize()
	} else {
		d = sd.codex.finalize()
	}
	attachCapturedFilePatches(d)
	applyRecord(d, record, runDir)
	return d
}

// Write serializes the digest to digest.json inside the run bundle.
func Write(runDir string, d *Digest) error {
	payload, err := MarshalEvaluation(d)
	if err != nil {
		return fmt.Errorf("marshal digest: %w", err)
	}
	if len(payload)+1 > MaxDigestBytes {
		return fmt.Errorf("digest is %d bytes; maximum is %d", len(payload)+1, MaxDigestBytes)
	}
	path := filepath.Join(runDir, "digest.json")
	if err := securefile.WriteFile(path, append(payload, '\n')); err != nil {
		return fmt.Errorf("write digest: %w", err)
	}
	return nil
}

// MarshalEvaluation serializes the structural/evaluation view of a digest.
// Provider-private reasoning text is removed even when the input originated
// from an older in-memory or decoded digest representation.
func MarshalEvaluation(d *Digest) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("digest is nil")
	}
	copy := *d
	copy.Timeline = append([]Event(nil), d.Timeline...)
	RedactReasoning(&copy)
	return json.MarshalIndent(&copy, "", "  ")
}

func statusFromRecord(record runrecord.Record) string {
	switch {
	case record.Timeout:
		return "timeout"
	case record.OK:
		return "ok"
	default:
		return "error"
	}
}

// assembleFiles folds the timeline into a per-file read/edit summary.
func assembleFiles(timeline []Event) []FileTouch {
	byPath := map[string]*FileTouch{}
	touch := func(path string) *FileTouch {
		if t, ok := byPath[path]; ok {
			return t
		}
		t := &FileTouch{Path: path}
		byPath[path] = t
		return t
	}
	for _, event := range timeline {
		edited := event.Kind == KindFileEdit
		for _, path := range event.Files {
			t := touch(path)
			if edited {
				t.Edited = true
			} else {
				t.Read = true
			}
		}
		for path, spans := range event.Spans {
			t := touch(path)
			if !edited {
				t.Read = true
				t.ReadSpans = append(t.ReadSpans, spans...)
			}
		}
	}
	files := make([]FileTouch, 0, len(byPath))
	for _, t := range byPath {
		t.ReadSpans = mergeSpans(t.ReadSpans)
		files = append(files, *t)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files
}

// mergeSpans sorts and coalesces overlapping or adjacent line spans.
func mergeSpans(spans []Span) []Span {
	if len(spans) < 2 {
		return spans
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].Start != spans[j].Start {
			return spans[i].Start < spans[j].Start
		}
		return spans[i].End < spans[j].End
	})
	merged := spans[:1]
	for _, s := range spans[1:] {
		last := &merged[len(merged)-1]
		if s.Start <= last.End+1 {
			if s.End > last.End {
				last.End = s.End
			}
			continue
		}
		merged = append(merged, s)
	}
	return merged
}

// applyEventTimes joins the event-times.jsonl sidecar (raw line number →
// arrival timestamp) onto the timeline. Bundles from before the sidecar
// existed simply keep ObservedAt unset.
func applyEventTimes(runDir string, timeline []Event) error {
	return applyEventTimesContext(context.Background(), runDir, timeline)
}

func applyEventTimesContext(ctx context.Context, runDir string, timeline []Event) error {
	// Only a handful of the run's raw lines produced timeline events; collect
	// those source lines first so we buffer timestamps for them alone, not for
	// every line of a multi-hour run.
	wanted := make(map[int]struct{}, len(timeline))
	for i := range timeline {
		if err := ctx.Err(); err != nil {
			return err
		}
		if timeline[i].srcLine > 0 {
			wanted[timeline[i].srcLine] = struct{}{}
		}
		if timeline[i].completedLine > 0 {
			wanted[timeline[i].completedLine] = struct{}{}
		}
	}
	if len(wanted) == 0 {
		return nil
	}

	f, err := securefile.OpenRegular(runDir, filepath.Join(runDir, "event-times.jsonl"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil // bundle predates the sidecar; ObservedAt stays unset
		}
		return fmt.Errorf("open event-times sidecar: %w", err)
	}
	defer f.Close()

	times := make(map[int]time.Time, len(wanted))
	var parseErr error
	if err := forEachLine(contextReader{ctx: ctx, reader: f}, func(_ int, line []byte) {
		if parseErr != nil {
			return
		}
		var entry struct {
			Line int       `json:"line"`
			T    time.Time `json:"t"`
		}
		if err := json.Unmarshal(line, &entry); err != nil {
			parseErr = fmt.Errorf("parse event-times sidecar: %w", err)
			return
		}
		if _, ok := wanted[entry.Line]; ok {
			times[entry.Line] = entry.T
		}
	}); err != nil {
		return fmt.Errorf("read event-times sidecar: %w", err)
	}
	if parseErr != nil {
		return parseErr
	}
	for i := range timeline {
		if t, ok := times[timeline[i].srcLine]; ok {
			ts := t
			timeline[i].ObservedAt = &ts
		}
		if t, ok := times[timeline[i].completedLine]; ok {
			ts := t
			timeline[i].CompletedAt = &ts
		}
	}
	return nil
}

// Truncate returns s cut to at most limit bytes without splitting a UTF-8
// rune, so the result is always valid UTF-8. A byte-boundary slice can leave a
// half rune that json.Marshal coerces to U+FFFD and that OTLP's protobuf
// marshal rejects outright (dropping the whole span batch).
func Truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	// Back off to the start of the rune straddling the limit.
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit]
}

// capOutput returns the stored (rune-safe truncated) output and the original
// size in characters. The field is output_chars, so count runes, not bytes.
func capOutput(text string) (string, int) {
	return Truncate(text, MaxEventOutputChars), utf8.RuneCountInString(text)
}

// capText applies the normalized free-text byte limit while preserving the
// original character count and an explicit structural truncation marker.
func capText(text string) (string, int, bool) {
	bounded := Truncate(text, MaxEventTextBytes)
	return bounded, utf8.RuneCountInString(text), len(bounded) < len(text)
}

func setEventOutput(event *Event, text string) {
	event.Output, event.OutputChars = capOutput(text)
	event.OutputTruncated = event.OutputChars > utf8.RuneCountInString(event.Output)
}

func setEventInput(event *Event, raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	event.InputChars = utf8.RuneCount(raw)
	event.InputTruncated = len(raw) > MaxEventInputChars
	event.Input = capInput(raw)
}

func setEventResult(event *Event, raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	event.ResultChars = utf8.RuneCount(raw)
	event.ResultTruncated = len(raw) > MaxEventInputChars
	event.Result = capInput(raw)
}

func rawEventLines(lines ...int) []int {
	seen := map[int]bool{}
	result := make([]int, 0, len(lines))
	for _, line := range lines {
		if line > 0 && !seen[line] {
			seen[line] = true
			result = append(result, line)
		}
	}
	return result
}

func (d *Digest) countUnsupported(name string) {
	if strings.TrimSpace(name) == "" {
		name = "unknown"
	}
	if d.Metrics.UnsupportedEvents == nil {
		d.Metrics.UnsupportedEvents = map[string]int{}
	}
	d.Metrics.UnsupportedEvents[name]++
}

func unsupportedEventsError(d *Digest) error {
	if d == nil || len(d.Metrics.UnsupportedEvents) == 0 {
		return nil
	}
	names := make([]string, 0, len(d.Metrics.UnsupportedEvents))
	total := 0
	for name, count := range d.Metrics.UnsupportedEvents {
		names = append(names, name)
		total += count
	}
	sort.Strings(names)
	return fmt.Errorf("provider stream contains %d unsupported event(s): %s", total, strings.Join(names, ", "))
}

// capInput keeps small tool inputs verbatim; oversized inputs are replaced with
// a valid-JSON size marker so digest.json stays compact (raw fidelity lives in
// the JSONL bundle). Truncating the raw JSON bytes directly would produce
// invalid JSON, so an over-limit input is dropped in favor of the marker.
func capInput(raw json.RawMessage) json.RawMessage {
	if len(raw) <= MaxEventInputChars {
		return raw
	}
	return json.RawMessage(fmt.Sprintf(`{"_truncated_bytes":%d}`, len(raw)))
}

// maxLineBytes caps a single raw stream line during offline re-digestion so a
// pathological newline-free blob in a captured stream cannot exhaust memory.
// Matches the live tee's per-line cap (internal/runner/tee.go): a longer line is
// truncated (and thus counted as a parse error), never buffered whole.
const maxLineBytes = 16 << 20 // 16 MiB

// forEachLine calls fn for each newline-terminated (or final unterminated)
// non-empty line of r, numbering them from 1, capping each line at maxLineBytes.
// It returns any read error other than io.EOF. Shared by the two stream parsers
// and the sidecar reader so the scan mechanics live in one place.
func forEachLine(r io.Reader, fn func(n int, line []byte)) error {
	reader := bufio.NewReaderSize(r, 64<<10)
	n := 0
	for {
		line, err := readBoundedLine(reader, maxLineBytes)
		if len(line) > 0 {
			n++
			fn(n, line)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// readBoundedLine reads one '\n'-terminated line, returning at most max bytes.
// Bytes beyond max are read and discarded rather than buffered, so an
// arbitrarily long line uses O(max) memory. A truncated line is returned as-is
// — it will not parse as JSON, so callers count it as a parse error.
func readBoundedLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if room := max - len(line); room > 0 {
			if len(chunk) > room {
				line = append(line, chunk[:room]...)
			} else {
				line = append(line, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue // line longer than the reader buffer; keep draining to '\n'
		}
		return line, err // nil (hit '\n'), io.EOF, or a real read error
	}
}
