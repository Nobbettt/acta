package runrecord

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/nobbettt/acta/internal/schemaversion"
	"github.com/nobbettt/acta/internal/version"
)

// MaxRecordBytes is the largest run.json payload Acta will write or read.
const (
	MaxRecordBytes   int64 = 4 << 20
	SchemaVersion          = 3
	MinSchemaVersion       = 2
)

// Producer identifies the Acta build which projected an artifact. Version is
// intended to be a release version and Commit may identify a development
// build. Name and Version are required by the published schemas.
type Producer struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Commit  string `json:"commit,omitempty"`
	Date    string `json:"date,omitempty"`
}

func CurrentProducer() Producer {
	build := version.Current()
	return Producer{Name: "acta", Version: build.Version, Commit: build.Commit, Date: build.Date}
}

// SupportsV3Fields reports whether a run-record, digest, or event schema
// version includes the fields and enum values introduced in schema v3.
func SupportsV3Fields(schemaVersion int) bool {
	return schemaVersion >= 3
}

// SupportsOTLPStatus reports whether status belongs to the closed vocabulary
// for schemaVersion. Callers decide whether an empty status is allowed.
func SupportsOTLPStatus(schemaVersion int, status string) bool {
	return slices.Contains([]string{"not_configured", "exported", "failed"}, status) ||
		SupportsV3Fields(schemaVersion) && slices.Contains([]string{"not_sampled", "pending"}, status)
}

type Record struct {
	SchemaVersion int      `json:"schema_version,omitempty"`
	Producer      Producer `json:"producer,omitempty"`
	ID            string   `json:"id"`
	TraceID       string   `json:"trace_id,omitempty"`
	Agent         string   `json:"agent"`
	AgentVersion  string   `json:"agent_version,omitempty"`
	CWD           string   `json:"cwd"`
	BaseCommitSHA string   `json:"base_commit_sha,omitempty"`
	BaseBranch    string   `json:"base_branch,omitempty"`
	// BaseDirty is a pointer so "verified clean" (false) still serializes;
	// absent means the workspace was not a git repo or capture failed.
	BaseDirty         *bool     `json:"base_dirty,omitempty"`
	HeadCommitSHA     string    `json:"head_commit_sha,omitempty"`
	Model             string    `json:"model,omitempty"`
	Repository        string    `json:"repository,omitempty"`
	IssueNumber       int       `json:"issue_number,omitempty"`
	IssueTitle        string    `json:"issue_title,omitempty"`
	IssueBody         *string   `json:"issue_body,omitempty"`
	TaskTitle         string    `json:"task_title,omitempty"`
	RunDir            string    `json:"run_dir"`
	RecoveryDir       string    `json:"recovery_dir,omitempty"`
	Command           []string  `json:"command"`
	StartedAt         time.Time `json:"started_at"`
	CompletedAt       time.Time `json:"completed_at"`
	DurationMillis    int64     `json:"duration_ms"`
	ExitCode          *int      `json:"exit_code,omitempty"`
	OK                bool      `json:"ok"`
	Timeout           bool      `json:"timeout"`
	TerminationReason string    `json:"termination_reason,omitempty"`
	Error             string    `json:"error,omitempty"`
	RawStdoutPath     string    `json:"raw_stdout_path"`
	RawStderrPath     string    `json:"raw_stderr_path"`
	// Artifact paths are portable, bundle-relative paths. Absolute host paths
	// remain above for provenance.
	RawStdoutArtifact          string `json:"raw_stdout_artifact,omitempty"`
	RawStderrArtifact          string `json:"raw_stderr_artifact,omitempty"`
	PromptSource               string `json:"prompt_source"`
	PromptCaptured             bool   `json:"prompt_captured,omitempty"`
	OTLPStatus                 string `json:"otlp_status,omitempty"`
	OTLPError                  string `json:"otlp_error,omitempty"`
	RawOutputLimitBytes        int64  `json:"raw_output_limit_bytes,omitempty"`
	RawOutputLimitExceeded     bool   `json:"raw_output_limit_exceeded,omitempty"`
	WorkspaceDiffLimitBytes    int64  `json:"workspace_diff_limit_bytes,omitempty"`
	WorkspaceDiffLimitExceeded bool   `json:"workspace_diff_limit_exceeded,omitempty"`
	ProcessContainment         string `json:"process_containment,omitempty"`
	AgentConfigMode            string `json:"agent_config_mode,omitempty"`
	RuntimeBundleSHA256        string `json:"runtime_bundle_sha256,omitempty"`
	// ReasoningRedactionState records whether provider-private reasoning text
	// remains in the local-only raw/normalized streams, was removed from the
	// bundle entirely, could not be redacted, or has an ambiguous partial commit.
	// Reasoning text is never written to digest.json or OTLP.
	ReasoningRedactionState string `json:"reasoning_redaction_state,omitempty"`
	// PublishedBundle is populated only by an Acta-owned publication path. A
	// launcher may reuse this digest-bound reference instead of trusting a
	// similarly shaped claim emitted by the coding agent.
	PublishedBundle *PublishedBundle `json:"published_bundle,omitempty"`

	presentV3Fields []string
}

// UnmarshalJSON remembers v3-only property presence independently of Go zero
// values so Validate can reject, for example, an explicitly false future
// boolean in a v2-labeled document.
func (r *Record) UnmarshalJSON(data []byte) error {
	type plainRecord Record
	var decoded plainRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	fields, err := schemaversion.PresentV3OnlyFieldsJSON(schemaversion.RunRecord, data)
	if err != nil {
		return err
	}
	*r = Record(decoded)
	r.presentV3Fields = fields
	return nil
}

type PublishedBundle struct {
	ArtifactID string `json:"artifact_id"`
	SHA256     string `json:"sha256"`
}

// PublishedBundleArtifactIDPattern is shared with the published run-record
// schema and defines the complete machine-ID syntax.
const PublishedBundleArtifactIDPattern = `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`

var publishedBundleArtifactIDRegexp = regexp.MustCompile(PublishedBundleArtifactIDPattern)

// Validate rejects records from schemas this build cannot interpret.
func (r *Record) Validate() error {
	if r == nil {
		return fmt.Errorf("run record is nil")
	}
	if r.SchemaVersion < MinSchemaVersion || r.SchemaVersion > SchemaVersion {
		return fmt.Errorf("unsupported run record schema_version %d (supported %d..%d)", r.SchemaVersion, MinSchemaVersion, SchemaVersion)
	}
	if !SupportsV3Fields(r.SchemaVersion) {
		field, found, err := schemaversion.FirstPresentV3OnlyField(schemaversion.RunRecord, r, r.presentV3Fields)
		if err != nil {
			return fmt.Errorf("inspect run record versioned fields: %w", err)
		}
		if found {
			return fmt.Errorf("run record schema_version %d does not support %s", r.SchemaVersion, field)
		}
	}
	if r.SchemaVersion >= 2 && (strings.TrimSpace(r.Producer.Name) == "" || strings.TrimSpace(r.Producer.Version) == "") {
		return fmt.Errorf("run record schema_version %d requires producer name and version", r.SchemaVersion)
	}
	if r.SchemaVersion >= 2 {
		if r.Producer.Name != "acta" {
			return fmt.Errorf("run record producer name must be acta")
		}
		if !slices.Contains([]string{"codex", "claude"}, r.Agent) || strings.TrimSpace(r.AgentVersion) == "" {
			return fmt.Errorf("run record requires a supported agent and agent_version")
		}
		if strings.TrimSpace(r.CWD) == "" || strings.TrimSpace(r.RunDir) == "" || len(r.Command) == 0 || strings.TrimSpace(r.Command[0]) == "" {
			return fmt.Errorf("run record requires cwd, run_dir, and a nonempty command")
		}
		if strings.TrimSpace(r.RawStdoutPath) == "" || strings.TrimSpace(r.RawStderrPath) == "" {
			return fmt.Errorf("run record requires raw stdout and stderr paths")
		}
		if r.StartedAt.IsZero() || r.CompletedAt.IsZero() || r.CompletedAt.Before(r.StartedAt) || r.DurationMillis < 0 {
			return fmt.Errorf("run record has invalid timestamps or duration")
		}
		if !slices.Contains([]string{"flag", "args", "stdin", "internal", "test"}, r.PromptSource) {
			return fmt.Errorf("run record has invalid prompt_source %q", r.PromptSource)
		}
		if !slices.Contains([]string{"completed", "timeout", "cancelled", "process_error", "resource_limit", "acta_error", "failed", "error", "interrupted", "degraded"}, r.TerminationReason) {
			return fmt.Errorf("run record has invalid termination_reason %q", r.TerminationReason)
		}
		if r.Timeout && (r.OK || r.TerminationReason != "timeout") || r.OK && r.TerminationReason != "completed" || !r.OK && r.TerminationReason == "completed" {
			return fmt.Errorf("run record outcome fields are inconsistent")
		}
		if r.OK && (r.ExitCode == nil || *r.ExitCode != 0) {
			return fmt.Errorf("successful run record requires exit_code 0")
		}
		if !SupportsOTLPStatus(r.SchemaVersion, r.OTLPStatus) || r.OTLPStatus == "failed" && strings.TrimSpace(r.OTLPError) == "" || r.OTLPStatus != "failed" && r.OTLPError != "" {
			return fmt.Errorf("run record OTLP status and error are inconsistent")
		}
		if (r.OTLPStatus == "exported" || r.OTLPStatus == "pending") && strings.TrimSpace(r.TraceID) == "" ||
			r.OTLPStatus != "exported" && r.OTLPStatus != "pending" && r.TraceID != "" {
			return fmt.Errorf("run record OTLP status and trace_id are inconsistent")
		}
		if !slices.Contains([]string{"posix_process_group", "windows_job", "direct_process"}, r.ProcessContainment) {
			return fmt.Errorf("run record has invalid process_containment %q", r.ProcessContainment)
		}
		if !slices.Contains([]string{"ambient_ephemeral", "project_only_ephemeral", "authoritative_bundle"}, r.AgentConfigMode) {
			return fmt.Errorf("run record has invalid agent_config_mode %q", r.AgentConfigMode)
		}
		if r.ReasoningRedactionState != "" && !slices.Contains([]string{"retained_local", "redacted", "failed", "partial"}, r.ReasoningRedactionState) {
			return fmt.Errorf("run record has invalid reasoning_redaction_state %q", r.ReasoningRedactionState)
		}
		if r.PublishedBundle != nil {
			if !validPublishedBundleArtifactID(r.PublishedBundle.ArtifactID) {
				return fmt.Errorf("published_bundle.artifact_id is invalid")
			}
			if !isLowerHexSHA256(r.PublishedBundle.SHA256) {
				return fmt.Errorf("published_bundle.sha256 must be 64 lowercase hexadecimal characters")
			}
		}
		if r.AgentConfigMode == "authoritative_bundle" && r.RuntimeBundleSHA256 == "" || r.AgentConfigMode != "authoritative_bundle" && r.RuntimeBundleSHA256 != "" {
			return fmt.Errorf("run record agent_config_mode and runtime_bundle_sha256 are inconsistent")
		}
		if r.RawOutputLimitBytes < 0 || r.WorkspaceDiffLimitBytes < 0 || r.RawOutputLimitExceeded && r.RawOutputLimitBytes == 0 || r.WorkspaceDiffLimitExceeded && r.WorkspaceDiffLimitBytes == 0 {
			return fmt.Errorf("run record capture limits are inconsistent")
		}
		if r.RecoveryDir != "" && r.OK {
			return fmt.Errorf("successful run record must not have recovery_dir")
		}
	}
	if r.SchemaVersion >= 2 && (strings.TrimSpace(r.RawStdoutArtifact) == "" || strings.TrimSpace(r.RawStderrArtifact) == "") {
		return fmt.Errorf("run record schema_version %d requires portable raw stdout and stderr artifact paths", r.SchemaVersion)
	}
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("run record id is empty")
	}
	if r.RuntimeBundleSHA256 != "" && !isLowerHexSHA256(r.RuntimeBundleSHA256) {
		return fmt.Errorf("runtime_bundle_sha256 must be 64 lowercase hexadecimal characters")
	}
	return nil
}

// MarshalFile returns the validated, bounded bytes written to run.json.
func MarshalFile(record *Record) ([]byte, error) {
	if err := record.Validate(); err != nil {
		return nil, fmt.Errorf("validate run record: %w", err)
	}
	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal run record: %w", err)
	}
	payload = append(payload, '\n')
	if int64(len(payload)) > MaxRecordBytes {
		return nil, fmt.Errorf("run record exceeds %d-byte limit", MaxRecordBytes)
	}
	return payload, nil
}

func validPublishedBundleArtifactID(value string) bool {
	return publishedBundleArtifactIDRegexp.MatchString(value)
}

func isLowerHexSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			if char < 'a' || char > 'f' {
				return false
			}
		}
	}
	return true
}
