package runner

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nobbettt/acta/internal/actaevents"
	"github.com/nobbettt/acta/internal/agents"
	"github.com/nobbettt/acta/internal/digest"
	"github.com/nobbettt/acta/internal/gitdiff"
	"github.com/nobbettt/acta/internal/reporting"
	"github.com/nobbettt/acta/internal/runrecord"
	"github.com/nobbettt/acta/internal/runtimebundle"
	"github.com/nobbettt/acta/internal/securefile"
	"github.com/nobbettt/acta/internal/tracing"
)

// gitCaptureTimeout bounds each git evidence capture (workspace info, diff,
// head commit) so a wedged git never hangs a run or its teardown.
const gitCaptureTimeout = 30 * time.Second

const agentVersionTimeout = 5 * time.Second

// MaxIssueBodyBytes keeps optional issue metadata comfortably within the
// bounded run.json payload even when JSON escaping expands every input byte.
const MaxIssueBodyBytes int64 = 512 << 10

// MaxPromptBytes is the hard limit for every prompt source. CapturePrompt has
// a smaller derived-artifact limit below, but direct Run callers must not be
// able to bypass the CLI's bounded prompt ingestion.
const MaxPromptBytes int64 = 8 << 20

// DefaultMaxRawOutputBytes is the CLI's default combined raw stdout/stderr
// budget. Direct API callers may pass zero for explicitly unlimited capture.
const DefaultMaxRawOutputBytes int64 = 1 << 30

// DefaultMaxWorkspaceDiffBytes is the CLI's default streamed diff-artifact
// budget. Direct API callers may pass zero for explicitly unlimited capture.
const DefaultMaxWorkspaceDiffBytes int64 = 256 << 20

const DefaultUploadTimeout = 2 * time.Minute

const (
	OTLPExportFailurePolicyBestEffort = "best-effort"
	OTLPExportFailurePolicyRequired   = "required"
	// TelemetryOnlyFailureExitCode is returned by the CLI only when the agent
	// run and its durable bundle succeeded but required OTLP delivery failed.
	// Launchers must also validate run.json before treating this code as a
	// warning, because an agent process may independently use the same code.
	TelemetryOnlyFailureExitCode = 86
)

var ErrTelemetryOnlyFailure = errors.New("required telemetry export failed after a successful run")

// DefaultRunsDir is the workspace-relative bundle root shared by every
// command that resolves a runs directory.
const DefaultRunsDir = ".acta/runs"

// A retained prompt becomes one JSONL event and must remain below the event
// reader and upload batch limits after worst-case JSON escaping.
const maxCapturedPromptBytes = 1 << 20

type Options struct {
	Agent         string
	CWD           string
	Prompt        string
	PromptSource  string
	CapturePrompt bool
	Model         string
	Repository    string
	IssueNumber   int
	IssueTitle    string
	IssueBody     *string
	TaskTitle     string
	RunsDir       string
	Timeout       time.Duration
	UploadTimeout time.Duration
	// MaxRawOutputBytes bounds stdout+stderr combined. Zero explicitly keeps
	// full fidelity without a byte limit. Crossing a positive limit terminates
	// the process tree and fails the run; it never silently truncates success.
	MaxRawOutputBytes       int64
	MaxWorkspaceDiffBytes   int64
	MaxUploadBytes          int64
	MaxRedactionLineBytes   int
	Stream                  bool
	AgentWritableDirs       []string
	CodexSandbox            string
	ClaudePermissionMode    string
	OTLPEndpoint            string
	OTLPIncludeOutput       bool
	OTLPExportFailurePolicy string
	// OTLPBestEffort is a deprecated programmatic compatibility switch. The
	// default and the preferred explicit policy are both best-effort.
	OTLPBestEffort                 bool
	OTLPForceRoot                  bool
	RedactReasoning                bool
	AllowUnredactedRemoteReasoning bool
	RunID                          string
	BackendURL                     string
	ReportToken                    string
	ReportTokenEnv                 string
	OrganizationID                 string
	RepositoryID                   string
	ReportMode                     string
	RuntimeBundlePath              string
	AllowInsecureHTTP              bool
	// GitEvidenceExcludes are workspace-relative generated/control paths to
	// omit in addition to the run's bundle root, which is always excluded so
	// prior bundles never leak into captured evidence.
	GitEvidenceExcludes []string
}

func Run(ctx context.Context, opts Options, stdout io.Writer, stderr io.Writer) (*runrecord.Record, error) {
	if opts.Timeout < 0 {
		return nil, fmt.Errorf("--timeout must not be negative")
	}
	if opts.UploadTimeout < 0 {
		return nil, fmt.Errorf("--upload-timeout must not be negative")
	}
	if opts.MaxRawOutputBytes < 0 {
		return nil, fmt.Errorf("--max-raw-output-bytes must not be negative")
	}
	if opts.MaxWorkspaceDiffBytes < 0 {
		return nil, fmt.Errorf("--max-workspace-diff-bytes must not be negative")
	}
	if opts.MaxUploadBytes < 0 {
		return nil, fmt.Errorf("--max-upload-bytes must not be negative")
	}
	if opts.MaxRedactionLineBytes < 0 {
		return nil, fmt.Errorf("--max-redaction-line-bytes must not be negative")
	}
	if err := validateGitEvidenceExcludes(opts.GitEvidenceExcludes); err != nil {
		return nil, err
	}
	if err := validateReportOptions(opts); err != nil {
		return nil, err
	}
	if err := validateRetainedContent(opts); err != nil {
		return nil, err
	}
	otlpFailurePolicy, err := normalizeOTLPExportFailurePolicy(opts)
	if err != nil {
		return nil, err
	}
	if otlpFailurePolicy == OTLPExportFailurePolicyRequired {
		if reason := tracing.DeliveryUnavailableReason(opts.OTLPEndpoint); reason != "" {
			return nil, fmt.Errorf("--otlp-export-failure-policy required cannot deliver traces: %s", reason)
		}
	}

	adapter, err := agents.Get(opts.Agent)
	if err != nil {
		return nil, err
	}

	cwd, err := filepath.Abs(opts.CWD)
	if err != nil {
		return nil, fmt.Errorf("resolve cwd: %w", err)
	}
	if info, err := os.Stat(cwd); err != nil {
		return nil, fmt.Errorf("stat cwd: %w", err)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("cwd is not a directory: %s", cwd)
	}
	runsDir := strings.TrimSpace(opts.RunsDir)
	if runsDir == "" {
		runsDir = DefaultRunsDir
	}
	if !filepath.IsAbs(runsDir) {
		runsDir = filepath.Join(cwd, runsDir)
	}
	runsDir, err = filepath.Abs(runsDir)
	if err != nil {
		return nil, fmt.Errorf("resolve runs directory: %w", err)
	}
	runsDir = filepath.Clean(runsDir)
	defaultRunsDir := filepath.Join(cwd, filepath.FromSlash(DefaultRunsDir))

	runID := strings.TrimSpace(opts.RunID)
	if runID == "" {
		runID, err = newRunID(adapter.Name())
		if err != nil {
			return nil, err
		}
	} else if err := validateRunID(runID); err != nil {
		return nil, err
	}
	runsDirInfo, err := prepareRunsDir(runsDir, runsDir == defaultRunsDir)
	if err != nil {
		return nil, err
	}
	runDir := filepath.Join(runsDir, runID)
	if err := ensureBundleDestinationAvailable(runDir); err != nil {
		return nil, err
	}
	writableDirs, err := validateAgentWritableDirs(opts.AgentWritableDirs, runDir)
	if err != nil {
		return nil, err
	}
	stagingDir, err := createBundleStagingDir(cwd, writableDirs)
	if err != nil {
		return nil, err
	}
	stagingPublished := false
	defer func() {
		if !stagingPublished {
			_ = os.RemoveAll(stagingDir)
		}
	}()
	if strings.TrimSpace(opts.RuntimeBundlePath) != "" && adapter.Name() == "codex" {
		if err := rejectProjectCodexConfig(cwd); err != nil {
			return nil, err
		}
	}
	preparedRuntime, err := runtimebundle.Prepare(opts.RuntimeBundlePath, stagingDir, opts.Agent, opts.Model)
	if err != nil {
		return nil, fmt.Errorf("prepare runtime bundle: %w", err)
	}
	runtimeCleaned := false
	defer func() {
		if !runtimeCleaned {
			_ = preparedRuntime.Cleanup()
		}
	}()
	opts.Model = preparedRuntime.Model
	configMode := preparedRuntime.ConfigMode
	if configMode == "" {
		configMode = adapter.DefaultConfigMode()
	}

	req := agents.RunRequest{
		CWD:                  cwd,
		Prompt:               opts.Prompt,
		Model:                opts.Model,
		WritableDirs:         writableDirs,
		CodexSandbox:         opts.CodexSandbox,
		ClaudePermissionMode: opts.ClaudePermissionMode,
		ExtraArgs:            preparedRuntime.AgentArgs,
	}
	spec, err := adapter.BuildCommand(req)
	if err != nil {
		return nil, err
	}
	agentVersion, err := probeAgentVersion(ctx, adapter, spec, agentEnvironment(opts))
	if err != nil {
		return nil, err
	}

	stdoutPath := filepath.Join(runDir, spec.StdoutFilename)
	stderrPath := filepath.Join(runDir, spec.StderrFilename)
	stagedStdoutPath := filepath.Join(stagingDir, spec.StdoutFilename)
	stagedStderrPath := filepath.Join(stagingDir, spec.StderrFilename)
	rawStdout, err := securefile.CreateExclusive(stagedStdoutPath)
	if err != nil {
		return nil, fmt.Errorf("create raw stdout: %w", err)
	}
	defer rawStdout.Close()
	rawStderr, err := securefile.CreateExclusive(stagedStderrPath)
	if err != nil {
		return nil, fmt.Errorf("create raw stderr: %w", err)
	}
	defer rawStderr.Close()
	sidecar, err := securefile.CreateExclusive(filepath.Join(stagingDir, "event-times.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("create event-times sidecar: %w", err)
	}
	defer sidecar.Close()

	// Establish Git evidence before execution. A capture error is not equivalent
	// to a non-repository and must fail closed rather than produce a plausible
	// record with silently missing provenance.
	gitExcludes := evidenceExcludes(cwd, runDir, opts.GitEvidenceExcludes)
	infoCtx, cancelInfo := context.WithTimeout(ctx, gitCaptureTimeout)
	gitInfo, gitErr := gitdiff.WorkspaceInfo(infoCtx, cwd, gitExcludes...)
	cancelInfo()
	if gitErr != nil {
		return nil, fmt.Errorf("capture initial git context: %w", gitErr)
	}
	var baseDirty *bool
	if gitInfo.IsRepo {
		baseDirty = &gitInfo.Dirty
	}
	// Build the digest after exact evidence exclusions are resolved so live
	// per-write snapshots omit only generated/control paths, just like the
	// cumulative workspace diff.
	digester, err := digest.NewStreamDigesterWithOptions(adapter.Name(), cwd, digest.Options{
		EvidenceExclusions: gitExcludes,
		WorkspaceIsRepo:    gitInfo.IsRepo,
	})
	if err != nil {
		return nil, err
	}

	var tr *tracing.Run
	otlpStatus := "not_configured"
	otlpError := ""
	var telemetryErr error
	if tracing.Enabled(opts.OTLPEndpoint) {
		otlpStatus = "configured"
		traceStartedAt := time.Now().UTC()
		tr, err = tracing.Setup(ctx, tracing.Config{
			Endpoint:      opts.OTLPEndpoint,
			IncludeOutput: opts.OTLPIncludeOutput,
			ForceRoot:     opts.OTLPForceRoot,
			RunID:         runID,
			Agent:         adapter.Name(),
			Provider:      adapter.Provider(),
			Model:         strings.TrimSpace(opts.Model),
			PromptSource:  opts.PromptSource,
			StartedAt:     traceStartedAt,
		})
		if err != nil {
			otlpStatus = "failed"
			otlpError = err.Error()
			if otlpFailurePolicy == OTLPExportFailurePolicyRequired {
				telemetryErr = fmt.Errorf("required OTLP export failed during setup: %w", err)
			}
			fmt.Fprintf(stderr, "acta: OTLP export disabled: %v\n", err)
			tr = nil
		}
	}

	record := &runrecord.Record{
		SchemaVersion:           runrecord.SchemaVersion,
		Producer:                runrecord.CurrentProducer(),
		ID:                      runID,
		TraceID:                 tr.TraceID(),
		Agent:                   adapter.Name(),
		AgentVersion:            agentVersion,
		CWD:                     cwd,
		BaseCommitSHA:           gitInfo.CommitSHA,
		BaseBranch:              gitInfo.Branch,
		BaseDirty:               baseDirty,
		Model:                   strings.TrimSpace(opts.Model),
		Repository:              strings.TrimSpace(opts.Repository),
		IssueNumber:             opts.IssueNumber,
		IssueTitle:              strings.TrimSpace(opts.IssueTitle),
		IssueBody:               opts.IssueBody,
		TaskTitle:               taskTitle(opts),
		RunDir:                  runDir,
		Command:                 spec.CommandForRecord(),
		RawStdoutPath:           stdoutPath,
		RawStderrPath:           stderrPath,
		RawStdoutArtifact:       spec.StdoutFilename,
		RawStderrArtifact:       spec.StderrFilename,
		PromptSource:            opts.PromptSource,
		PromptCaptured:          opts.CapturePrompt,
		OTLPStatus:              otlpStatus,
		OTLPError:               otlpError,
		RawOutputLimitBytes:     opts.MaxRawOutputBytes,
		WorkspaceDiffLimitBytes: opts.MaxWorkspaceDiffBytes,
		ProcessContainment:      processContainmentName(),
		AgentConfigMode:         configMode,
		RuntimeBundleSHA256:     preparedRuntime.BundleSHA256,
		ReasoningRedactionState: "retained_local",
	}

	cmd := exec.Command(spec.Path, spec.Args...)
	// WaitDelay remains a final guard for inherited pipes that do not close
	// promptly. runProcessTree owns cancellation and terminates the platform
	// documented platform process container before waiting.
	cmd.WaitDelay = 10 * time.Second
	cmd.Dir = spec.Dir
	cmd.Env = agentEnvironment(opts)
	if spec.Stdin != "" {
		cmd.Stdin = strings.NewReader(spec.Stdin)
	}

	streamStdout := io.Discard
	streamStderr := io.Discard
	if opts.Stream {
		streamStdout = stdout
		streamStderr = stderr
	}
	// tee before streamStdout so arrival is stamped before a slow/paused
	// consumer drains the line (else backpressure skews all timings).
	// onLine is assigned unconditionally: tracing.Run.OnLine is nil-receiver
	// safe, so no guard is needed here.
	sidecarBuf := bufio.NewWriter(sidecar)
	// One decode pass drives both the digest and (when enabled) tracing; the
	// arrival time flows to observed_at directly (tr.OnLine is nil-safe).
	tee := &lineTee{sidecar: sidecarBuf, onLine: func(line []byte, at time.Time) {
		digester.Line(line, at)
		tr.OnLine(line, at)
	}}
	var cancelProcess func()
	rawBudget := newRawOutputBudget(opts.MaxRawOutputBytes, func() {
		if cancelProcess != nil {
			cancelProcess()
		}
	})
	cmd.Stdout = io.MultiWriter(rawBudget.writer(rawStdout), tee, streamStdout)
	cmd.Stderr = io.MultiWriter(rawBudget.writer(rawStderr), streamStderr)

	// Both the recorded duration and timeout begin immediately around process
	// execution. time.Sub uses the monotonic component retained in these local
	// values; UTC conversion is only for serialized wall-clock timestamps.
	baseRunCtx, cancelBaseRun := context.WithCancel(ctx)
	cancelProcess = cancelBaseRun
	runCtx := baseRunCtx
	cancelTimeout := func() {}
	if opts.Timeout > 0 {
		runCtx, cancelTimeout = context.WithTimeout(baseRunCtx, opts.Timeout)
	}
	processStarted := time.Now()
	record.StartedAt = processStarted.UTC()
	runErr := runProcessTree(runCtx, cmd)
	runContextErr := runCtx.Err()
	cancelTimeout()
	cancelBaseRun()
	if cleanupErr := preparedRuntime.Cleanup(); cleanupErr != nil {
		runErr = errors.Join(runErr, fmt.Errorf("clean up runtime bundle materialization: %w", cleanupErr))
	}
	runtimeCleaned = true
	processCompleted := time.Now()
	completedAt := processCompleted.UTC()
	record.CompletedAt = completedAt
	record.DurationMillis = processCompleted.Sub(processStarted).Milliseconds()
	record.Timeout = errors.Is(runContextErr, context.DeadlineExceeded)
	outputLimitErr := rawBudget.Err()
	runErr = errors.Join(runErr, outputLimitErr)
	switch {
	case record.Timeout:
		record.TerminationReason = "timeout"
	case outputLimitErr != nil:
		record.TerminationReason = "resource_limit"
	case errors.Is(runContextErr, context.Canceled):
		record.TerminationReason = "cancelled"
	case runErr != nil:
		record.TerminationReason = "process_error"
	default:
		record.TerminationReason = "completed"
	}

	// Flush the arrival-time sidecar before postRun reads it, and surface a
	// write failure instead of silently shipping an incomplete sidecar.
	tee.Flush()
	if err := errors.Join(tee.writeErr, tee.lineErr, sidecarBuf.Flush()); err != nil {
		err = fmt.Errorf("record stdout timing/digest: %w", err)
		fmt.Fprintf(stderr, "acta: %v\n", err)
		runErr = errors.Join(runErr, err)
	}
	if err := digester.Err(); err != nil {
		err = fmt.Errorf("digest raw stream: %w", err)
		fmt.Fprintf(stderr, "acta: %v\n", err)
		runErr = errors.Join(runErr, err)
	}
	if err := errors.Join(rawStdout.Sync(), rawStderr.Sync(), sidecar.Sync(), rawStdout.Close(), rawStderr.Close(), sidecar.Close()); err != nil {
		err = fmt.Errorf("close raw run artifacts: %w", err)
		fmt.Fprintf(stderr, "acta: %v\n", err)
		runErr = errors.Join(runErr, err)
	}

	if cmd.ProcessState != nil {
		exitCode := cmd.ProcessState.ExitCode()
		record.ExitCode = &exitCode
	}
	record.RawOutputLimitBytes = opts.MaxRawOutputBytes
	record.RawOutputLimitExceeded = outputLimitErr != nil
	FinalizeRecordOutcome(record, runErr)
	preview := digester.PreviewOutcome(record)
	record.OK = preview.OK
	record.TerminationReason = preview.TerminationReason
	record.Error = preview.Error
	traceSampled := tr != nil && tr.Sampled()
	if err := tr.Finish(record, completedAt); err != nil {
		fmt.Fprintf(stderr, "acta: OTLP flush failed: %v\n", err)
		otlpStatus = "failed"
		otlpError = err.Error()
		record.TraceID = ""
		if otlpFailurePolicy == OTLPExportFailurePolicyRequired {
			telemetryErr = errors.Join(telemetryErr, fmt.Errorf("required OTLP export failed during flush: %w", err))
		}
	} else if tr != nil {
		if traceSampled {
			otlpStatus = "exported"
		} else {
			otlpStatus = "not_sampled"
			record.TraceID = ""
		}
	}
	record.OTLPStatus = otlpStatus
	record.OTLPError = otlpError
	FinalizeRecordOutcome(record, runErr)

	reasoningRedacted := false
	if opts.RedactReasoning {
		maxRedactionLineBytes := opts.MaxRedactionLineBytes
		if maxRedactionLineBytes == 0 {
			maxRedactionLineBytes = reporting.DefaultMaxRedactionLineBytes
		}
		redactionState, redactErr := redactReasoningRawStream(stagedStdoutPath, maxRedactionLineBytes)
		if redactErr != nil {
			// Treat redaction as a late Acta failure, but continue derivation and
			// publication. A post-rename commit error is marked partial unless the
			// pre-computed original hash verifies byte-identical retention.
			record.ReasoningRedactionState = redactionState
			if redactionState == "partial" {
				redactErr = fmt.Errorf("reasoning redaction partially committed; original raw stream retention was not verified: %w", redactErr)
			} else {
				redactErr = fmt.Errorf("reasoning redaction failed; raw stream was not replaced or was hash-verified unchanged: %w", redactErr)
			}
			fmt.Fprintf(stderr, "acta: %v\n", redactErr)
			runErr = errors.Join(runErr, redactErr)
			FinalizeRecordOutcome(record, runErr)
		} else {
			record.ReasoningRedactionState = redactionState
			reasoningRedacted = true
		}
	}

	if writeErr := WriteRecord(stagingDir, record); writeErr != nil {
		runErr = errors.Join(runErr, writeErr)
		FinalizeRecordOutcome(record, runErr)
	}
	capturedPrompt := ""
	if opts.CapturePrompt {
		capturedPrompt = opts.Prompt
	}
	finalDigest, postErr := postRun(ctx, record, stagingDir, gitExcludes, opts.MaxWorkspaceDiffBytes, digester, capturedPrompt, reasoningRedacted, stderr, runErr)
	if postErr != nil {
		runErr = errors.Join(runErr, postErr)
	}
	if writeErr := WriteRecord(stagingDir, record); writeErr != nil {
		runErr = errors.Join(runErr, writeErr)
		FinalizeRecordOutcome(record, runErr)
	}
	if completenessErr := verifyCompleteBundle(stagingDir, record); completenessErr != nil {
		runErr = errors.Join(runErr, completenessErr)
		FinalizeRecordOutcome(record, runErr)
		if rewriteErr := rewriteRecoveryArtifacts(stagingDir, record, finalDigest, capturedPrompt, stderr); rewriteErr != nil {
			runErr = errors.Join(runErr, rewriteErr)
		}
		if remainingErr := verifyCompleteBundle(stagingDir, record); remainingErr != nil {
			runErr = errors.Join(runErr, remainingErr)
			FinalizeRecordOutcome(record, runErr)
			record.RecoveryDir = stagingDir
			_ = WriteRecord(stagingDir, record)
			stagingPublished = true
			return record, fmt.Errorf("%w; incomplete bundle retained for recovery at %s", runErr, stagingDir)
		}
	}
	if err := verifyRunsDir(runsDir, runsDirInfo); err != nil {
		runErr = errors.Join(runErr, err)
		FinalizeRecordOutcome(record, runErr)
		record.RecoveryDir = stagingDir
		if rewriteErr := rewriteRecoveryArtifacts(stagingDir, record, finalDigest, capturedPrompt, stderr); rewriteErr != nil {
			runErr = errors.Join(runErr, rewriteErr)
		}
		stagingPublished = true // retain the protected, recoverable staging bundle
		return record, fmt.Errorf("%w; completed bundle retained at %s", runErr, stagingDir)
	}
	published, publishErr := publishBundle(stagingDir, runDir)
	if publishErr != nil {
		runErr = errors.Join(runErr, fmt.Errorf("publish run bundle: %w", publishErr))
		FinalizeRecordOutcome(record, runErr)
		if published {
			record.RecoveryDir = ""
			if rewriteErr := rewriteRecoveryArtifacts(runDir, record, finalDigest, capturedPrompt, stderr); rewriteErr != nil {
				runErr = errors.Join(runErr, rewriteErr)
			}
			stagingPublished = true
			return record, fmt.Errorf("%w; bundle was published at %s but durability confirmation failed", runErr, runDir)
		}
		record.RecoveryDir = stagingDir
		if rewriteErr := rewriteRecoveryArtifacts(stagingDir, record, finalDigest, capturedPrompt, stderr); rewriteErr != nil {
			runErr = errors.Join(runErr, rewriteErr)
		}
		stagingPublished = true // publication leaves staging intact on failure
		return record, fmt.Errorf("%w; completed bundle retained at %s", runErr, stagingDir)
	}
	stagingPublished = true
	if reportMode(opts) == "hybrid" {
		reportCtx := ctx
		cancel := func() {}
		if opts.UploadTimeout > 0 {
			reportCtx, cancel = context.WithTimeout(ctx, opts.UploadTimeout)
		}
		defer cancel()
		if err := reporting.UploadRun(reportCtx, reporting.Config{
			BackendURL:                     opts.BackendURL,
			ReportToken:                    opts.ReportToken,
			OrganizationID:                 opts.OrganizationID,
			RepositoryID:                   opts.RepositoryID,
			AllowInsecureHTTP:              opts.AllowInsecureHTTP,
			MaxUploadBytes:                 opts.MaxUploadBytes,
			MaxRedactionLineBytes:          opts.MaxRedactionLineBytes,
			AllowUnredactedRemoteReasoning: opts.AllowUnredactedRemoteReasoning,
		}, record); err != nil {
			err = fmt.Errorf("upload report: %w", err)
			fmt.Fprintf(stderr, "acta: %v\n", err)
			// Upload is an operation on an already-finalized run bundle. Return
			// its failure to the caller, but do not rewrite the recorded agent
			// outcome: a later `acta upload` must retain the original terminal
			// event/status and be able to retry a successful execution as such.
			runErr = errors.Join(runErr, err)
		} else {
			fmt.Fprintf(stderr, "acta: uploaded run report to %s\n", strings.TrimRight(opts.BackendURL, "/"))
		}
	}
	if telemetryErr != nil {
		if runErr == nil && record.OK {
			return record, fmt.Errorf("%w: %v", ErrTelemetryOnlyFailure, telemetryErr)
		}
		runErr = errors.Join(runErr, telemetryErr)
	}
	if runErr != nil {
		return record, runErr
	}
	return record, nil
}

func normalizeOTLPExportFailurePolicy(opts Options) (string, error) {
	policy := strings.ToLower(strings.TrimSpace(opts.OTLPExportFailurePolicy))
	if opts.OTLPBestEffort && policy == OTLPExportFailurePolicyRequired {
		return "", fmt.Errorf("--otlp-best-effort cannot be combined with --otlp-export-failure-policy=%s", OTLPExportFailurePolicyRequired)
	}
	if policy == "" || opts.OTLPBestEffort {
		policy = OTLPExportFailurePolicyBestEffort
	}
	switch policy {
	case OTLPExportFailurePolicyBestEffort, OTLPExportFailurePolicyRequired:
		return policy, nil
	default:
		return "", fmt.Errorf("--otlp-export-failure-policy must be %q or %q", OTLPExportFailurePolicyBestEffort, OTLPExportFailurePolicyRequired)
	}
}

// rejectProjectCodexConfig prevents a repository-local Codex config layer from
// silently modifying an authoritative runtime bundle. Codex's
// --ignore-user-config intentionally ignores only CODEX_HOME/config.toml.
func rejectProjectCodexConfig(cwd string) error {
	current := filepath.Clean(cwd)
	for {
		configPath := filepath.Join(current, ".codex", "config.toml")
		if _, err := os.Lstat(configPath); err == nil {
			return fmt.Errorf("authoritative runtime bundle cannot be combined with project Codex config %s", configPath)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect project Codex config %s: %w", configPath, err)
		}
		if _, err := os.Lstat(filepath.Join(current, ".git")); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect project root %s: %w", current, err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return nil
}

func verifyCompleteBundle(bundleDir string, record *runrecord.Record) error {
	required := []string{
		"run.json",
		record.RawStdoutArtifact,
		record.RawStderrArtifact,
		"event-times.jsonl",
		"digest.json",
		actaevents.Filename,
	}
	for _, name := range required {
		if strings.TrimSpace(name) == "" || filepath.Base(name) != name {
			return fmt.Errorf("complete bundle has invalid required artifact name %q", name)
		}
		info, err := os.Lstat(filepath.Join(bundleDir, name))
		if err != nil {
			return fmt.Errorf("complete bundle is missing required artifact %s: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("complete bundle artifact %s is not a regular file", name)
		}
	}
	return nil
}

// postRun captures derived evidence into artifactDir. artifactDir remains
// private staging until every final/failed artifact has been generated; the
// caller publishes the complete directory atomically afterwards.
func postRun(ctx context.Context, record *runrecord.Record, artifactDir string, gitExcludes []string, maxWorkspaceDiffBytes int64, digester *digest.StreamDigester, capturedPrompt string, redactReasoning bool, stderr io.Writer, priorErr error) (*digest.Digest, error) {
	var postErr error
	refreshOutcome := func() {
		FinalizeRecordOutcome(record, errors.Join(priorErr, postErr))
	}
	writeCurrentRecord := func() {
		if err := WriteRecord(artifactDir, record); err != nil {
			fmt.Fprintf(stderr, "acta: write run record failed: %v\n", err)
			postErr = errors.Join(postErr, err)
			refreshOutcome()
		}
	}

	completionCtx, cancelCompletion := context.WithTimeout(context.WithoutCancel(ctx), gitCaptureTimeout)
	completionInfo, completionErr := gitdiff.WorkspaceInfo(completionCtx, record.CWD, gitExcludes...)
	cancelCompletion()
	switch {
	case completionErr != nil:
		fmt.Fprintf(stderr, "acta: final git context capture failed: %v\n", completionErr)
		postErr = errors.Join(postErr, fmt.Errorf("final git context: %w", completionErr))
	case record.BaseDirty != nil && !completionInfo.IsRepo:
		err := fmt.Errorf("workspace was a git repository at run start but is not a repository at completion")
		fmt.Fprintf(stderr, "acta: %v\n", err)
		postErr = errors.Join(postErr, err)
	}

	diffCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), gitCaptureTimeout)
	defer cancel()
	destPath := filepath.Join(artifactDir, "workspace.diff")
	if _, err := gitdiff.WorkspaceDiffWithLimit(diffCtx, record.CWD, destPath, maxWorkspaceDiffBytes, gitExcludes...); err != nil {
		if errors.Is(err, gitdiff.ErrWorkspaceDiffLimit) {
			record.WorkspaceDiffLimitExceeded = true
		}
		fmt.Fprintf(stderr, "acta: workspace diff failed: %v\n", err)
		postErr = errors.Join(postErr, fmt.Errorf("workspace diff: %w", err))
	}
	// Head capture is always attempted (an agent can `git init` and commit in a
	// previously non-git or unborn-HEAD workspace), gets its own budget so a
	// slow diff can't starve it, and its failure marks the bundle incomplete —
	// a silently missing head would read as "no commits were made".
	headCtx, cancelHead := context.WithTimeout(context.WithoutCancel(ctx), gitCaptureTimeout)
	defer cancelHead()
	head, headErr := gitdiff.HeadCommit(headCtx, record.CWD)
	switch {
	case headErr != nil:
		fmt.Fprintf(stderr, "acta: git head capture failed: %v\n", headErr)
		postErr = errors.Join(postErr, fmt.Errorf("git head capture: %w", headErr))
	case head == "" && record.BaseCommitSHA != "":
		err := fmt.Errorf("workspace was a git repository with a HEAD commit at run start but has no HEAD commit at completion")
		fmt.Fprintf(stderr, "acta: %v\n", err)
		postErr = errors.Join(postErr, err)
	default:
		record.HeadCommitSHA = head
	}
	refreshOutcome()

	// Finalize AFTER the diff is written so HasWorkspaceDiff sees it. No
	// re-decode of the raw stream, no sidecar re-read — times are already set.
	d := digester.Finalize(record, artifactDir)
	if redactReasoning {
		digest.RedactReasoning(d)
	}
	digest.ReconcileRecord(record, d)
	if !record.OK && priorErr == nil && postErr == nil {
		postErr = errors.New(record.Error)
	}
	if err := digest.Write(artifactDir, d); err != nil {
		fmt.Fprintf(stderr, "acta: write digest failed: %v\n", err)
		postErr = errors.Join(postErr, fmt.Errorf("write digest: %w", err))
		refreshOutcome()
		digest.ReconcileRecord(record, d)
	}
	writeCurrentRecord()
	if err := actaevents.WriteForRecordWithPrompt(artifactDir, record, d, capturedPrompt); err != nil {
		fmt.Fprintf(stderr, "acta: write events failed: %v\n", err)
		postErr = errors.Join(postErr, fmt.Errorf("write events: %w", err))
		refreshOutcome()
		digest.ReconcileRecord(record, d)
		if rewriteErr := digest.Write(artifactDir, d); rewriteErr != nil {
			postErr = errors.Join(postErr, fmt.Errorf("rewrite digest after event failure: %w", rewriteErr))
		}
		writeCurrentRecord()
	}
	return d, postErr
}

func rewriteRecoveryArtifacts(bundleDir string, record *runrecord.Record, d *digest.Digest, capturedPrompt string, stderr io.Writer) error {
	var rewriteErr error
	if d != nil {
		digest.ReconcileRecord(record, d)
		if err := digest.Write(bundleDir, d); err != nil {
			fmt.Fprintf(stderr, "acta: rewrite recovery digest failed: %v\n", err)
			rewriteErr = errors.Join(rewriteErr, fmt.Errorf("rewrite recovery digest: %w", err))
		}
	}
	if rewriteErr != nil {
		FinalizeRecordOutcome(record, errors.Join(errors.New(record.Error), rewriteErr))
		digest.ReconcileRecord(record, d)
	}
	if err := WriteRecord(bundleDir, record); err != nil {
		fmt.Fprintf(stderr, "acta: rewrite recovery run record failed: %v\n", err)
		rewriteErr = errors.Join(rewriteErr, fmt.Errorf("rewrite recovery run record: %w", err))
	}
	if d != nil {
		if err := actaevents.WriteForRecordWithPrompt(bundleDir, record, d, capturedPrompt); err != nil {
			fmt.Fprintf(stderr, "acta: rewrite recovery events failed: %v\n", err)
			rewriteErr = errors.Join(rewriteErr, fmt.Errorf("rewrite recovery events: %w", err))
			FinalizeRecordOutcome(record, errors.Join(errors.New(record.Error), rewriteErr))
			digest.ReconcileRecord(record, d)
			if digestErr := digest.Write(bundleDir, d); digestErr != nil {
				rewriteErr = errors.Join(rewriteErr, fmt.Errorf("rewrite final recovery digest: %w", digestErr))
			}
			if recordErr := WriteRecord(bundleDir, record); recordErr != nil {
				rewriteErr = errors.Join(rewriteErr, fmt.Errorf("rewrite final recovery run record: %w", recordErr))
			}
		}
	}
	return rewriteErr
}

// FinalizeRecordOutcome applies runner/Acta failures without overwriting a
// stronger process/provider reason. It is exported so replay/projection paths
// can share the same late-failure invariant before digest reconciliation.
func FinalizeRecordOutcome(record *runrecord.Record, runErr error) {
	if runErr != nil || record.Timeout {
		record.OK = false
		if runErr != nil {
			record.Error = runErr.Error()
			if record.TerminationReason == "" || record.TerminationReason == "completed" {
				record.TerminationReason = "acta_error"
			}
		}
		return
	}
	record.OK = true
	record.Error = ""
}

// runsDirExclude returns the whole runs root relative to the workspace, so
// that neither this run's bundle nor a prior sibling bundle ever enters
// captured evidence or dirty detection: a leftover bundle holds raw agent
// streams and captured prompts, and leaking it into workspace.diff would
// republish that evidence. Files deliberately tracked under the runs root are
// hidden from workspace diffs as a consequence.
func runsDirExclude(cwd, runDir string) []string {
	rel, err := filepath.Rel(cwd, filepath.Dir(runDir))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil
	}
	if rel == "." {
		// The runs root is the workspace itself; excluding "." would blank
		// all evidence, so fall back to this run's exact bundle path.
		if rel, err = filepath.Rel(cwd, runDir); err != nil {
			return nil
		}
	}
	return []string{filepath.ToSlash(rel)}
}

func evidenceExcludes(cwd, runDir string, configured []string) []string {
	result := runsDirExclude(cwd, runDir)
	for _, value := range configured {
		result = append(result, filepath.ToSlash(filepath.Clean(strings.TrimSpace(value))))
	}
	return result
}

func validateGitEvidenceExcludes(values []string) error {
	for _, value := range values {
		value = strings.TrimSpace(value)
		clean := filepath.Clean(value)
		if value == "" || clean == "." || clean == ".." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("git evidence exclude must be a non-empty workspace-relative path: %q", value)
		}
	}
	return nil
}

func WriteRecord(runDir string, record *runrecord.Record) error {
	if err := record.Validate(); err != nil {
		return fmt.Errorf("validate run record: %w", err)
	}
	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal run record: %w", err)
	}
	payload = append(payload, '\n')
	if int64(len(payload)) > runrecord.MaxRecordBytes {
		return fmt.Errorf("run record exceeds %d-byte limit", runrecord.MaxRecordBytes)
	}
	path := filepath.Join(runDir, "run.json")
	if err := securefile.WriteFile(path, payload); err != nil {
		return fmt.Errorf("write run record: %w", err)
	}
	return nil
}

func ReadRecord(runDir string) (*runrecord.Record, error) {
	resolvedRunDir, err := filepath.Abs(runDir)
	if err != nil {
		return nil, fmt.Errorf("resolve run dir: %w", err)
	}
	payload, err := securefile.ReadRegularFile(resolvedRunDir, filepath.Join(resolvedRunDir, "run.json"), runrecord.MaxRecordBytes)
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
	record.RunDir = resolvedRunDir
	return &record, nil
}

func newRunID(agent string) (string, error) {
	now := time.Now().UTC().Format("20060102T150405Z")
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("generate run id entropy: %w", err)
	}
	return fmt.Sprintf("%s-%s-%s", now, agent, hex.EncodeToString(suffix[:])), nil
}

func reportMode(opts Options) string {
	mode := strings.ToLower(strings.TrimSpace(opts.ReportMode))
	if mode == "" {
		return "local"
	}
	return mode
}

func agentEnvironment(opts Options) []string {
	return prepareAgentEnvironment(os.Environ(), opts.ReportTokenEnv)
}

func prepareAgentEnvironment(environment []string, reportTokenEnv string) []string {
	environment = environmentWithoutKeys(environment, reportTokenEnv)
	filtered := environment[:0]
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(key)), "OTEL_") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func probeAgentVersion(ctx context.Context, adapter agents.Adapter, spec agents.CommandSpec, environment []string) (string, error) {
	policy := adapter.VersionPolicy()
	versionCtx, cancel := context.WithTimeout(ctx, agentVersionTimeout)
	defer cancel()
	capture := &boundedCapture{maxBytes: 16 << 10}
	cmd := exec.CommandContext(versionCtx, spec.Path, policy.Args...)
	cmd.Dir = spec.Dir
	cmd.Env = environment
	cmd.Stdout = capture
	cmd.Stderr = capture
	runErr := cmd.Run()
	output, overflow := capture.result()
	if errors.Is(versionCtx.Err(), context.DeadlineExceeded) {
		return "", fmt.Errorf("check %s CLI version: timed out after %s", adapter.Name(), agentVersionTimeout)
	}
	if overflow {
		return "", fmt.Errorf("check %s CLI version: output exceeds 16384-byte limit", adapter.Name())
	}
	if runErr != nil {
		return "", fmt.Errorf("check %s CLI version: %w: %s", adapter.Name(), runErr, strings.TrimSpace(output))
	}
	version, err := policy.ParseAndValidate(output)
	if err != nil {
		return "", fmt.Errorf("check %s CLI version: %w", adapter.Name(), err)
	}
	return version, nil
}

func validateAgentWritableDirs(values []string, runDir string) ([]string, error) {
	runParent, err := filepath.EvalSymlinks(filepath.Dir(runDir))
	if err != nil {
		return nil, fmt.Errorf("resolve run directory parent: %w", err)
	}
	runRoot := filepath.Join(runParent, filepath.Base(runDir))
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || !filepath.IsAbs(value) {
			return nil, fmt.Errorf("agent writable directory must be an absolute path")
		}
		info, err := os.Lstat(value)
		if err != nil {
			return nil, fmt.Errorf("stat agent writable directory: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("agent writable directory must be a real directory: %s", value)
		}
		resolved, err := filepath.EvalSymlinks(value)
		if err != nil {
			return nil, fmt.Errorf("resolve agent writable directory: %w", err)
		}
		resolved = filepath.Clean(resolved)
		overlaps, err := pathsOverlap(resolved, runRoot)
		if err != nil {
			return nil, err
		}
		if overlaps {
			return nil, fmt.Errorf("agent writable directory must not contain or be contained by the run bundle: %s", resolved)
		}
		if _, duplicate := seen[resolved]; duplicate {
			continue
		}
		seen[resolved] = struct{}{}
		result = append(result, resolved)
	}
	return result, nil
}

func pathsOverlap(left string, right string) (bool, error) {
	leftContainsRight, err := pathContains(left, right)
	if err != nil {
		return false, err
	}
	rightContainsLeft, err := pathContains(right, left)
	if err != nil {
		return false, err
	}
	return leftContainsRight || rightContainsLeft, nil
}

func pathContains(root string, candidate string) (bool, error) {
	// filepath.Rel cannot represent a relationship across Windows volumes and
	// returns an error. Different drive letters or UNC shares are necessarily
	// disjoint, so that is a valid non-containment result rather than a failure.
	rootVolume := filepath.VolumeName(root)
	candidateVolume := filepath.VolumeName(candidate)
	if rootVolume != "" && candidateVolume != "" && !strings.EqualFold(rootVolume, candidateVolume) {
		return false, nil
	}
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return false, fmt.Errorf("compare agent writable directory boundaries: %w", err)
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)), nil
}

func environmentWithoutKeys(env []string, keys ...string) []string {
	blocked := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key != "" {
			blocked[key] = struct{}{}
		}
	}
	if len(blocked) == 0 {
		return append([]string(nil), env...)
	}

	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, ok := strings.Cut(entry, "=")
		if ok {
			if _, found := blocked[key]; found {
				continue
			}
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func taskTitle(opts Options) string {
	candidates := []string{opts.TaskTitle, opts.IssueTitle}
	for _, candidate := range candidates {
		if title := cleanTaskTitle(candidate); title != "" {
			return title
		}
	}
	return ""
}

func cleanTaskTitle(value string) string {
	title := strings.Join(strings.Fields(value), " ")
	const maxTitleRunes = 140
	runes := []rune(title)
	if len(runes) <= maxTitleRunes {
		return title
	}
	return strings.TrimSpace(string(runes[:maxTitleRunes-3])) + "..."
}

func validateReportOptions(opts Options) error {
	if opts.IssueNumber < 0 {
		return fmt.Errorf("--issue-number must not be negative")
	}
	mode := reportMode(opts)
	switch mode {
	case "local":
		if strings.TrimSpace(opts.BackendURL) != "" {
			return fmt.Errorf("--backend-url requires --report-mode hybrid")
		}
		if strings.TrimSpace(opts.ReportToken) != "" {
			return fmt.Errorf("--report-token requires --report-mode hybrid")
		}
		if strings.TrimSpace(opts.OrganizationID) != "" {
			return fmt.Errorf("--organization-id requires --report-mode hybrid")
		}
		if strings.TrimSpace(opts.RepositoryID) != "" {
			return fmt.Errorf("--repository-id requires --report-mode hybrid")
		}
	case "hybrid":
		if strings.TrimSpace(opts.BackendURL) == "" {
			return fmt.Errorf("--backend-url is required when --report-mode hybrid")
		}
		if strings.TrimSpace(opts.ReportToken) == "" {
			return fmt.Errorf("--report-token or --report-token-env is required when --report-mode hybrid")
		}
		if (strings.TrimSpace(opts.OrganizationID) == "") != (strings.TrimSpace(opts.RepositoryID) == "") {
			return fmt.Errorf("--organization-id and --repository-id must be provided together")
		}
		if strings.TrimSpace(opts.OrganizationID) != "" && strings.TrimSpace(opts.RunID) == "" {
			return fmt.Errorf("--run-id is required when scoped --organization-id and --repository-id are used")
		}
		if _, err := reporting.ValidateBackendURL(opts.BackendURL, opts.AllowInsecureHTTP); err != nil {
			return err
		}
	case "stream":
		return fmt.Errorf("--report-mode stream is not implemented yet; use local or hybrid")
	default:
		return fmt.Errorf("unknown --report-mode %q; expected local, hybrid, or stream", opts.ReportMode)
	}
	return nil
}

func validateRetainedContent(opts Options) error {
	if int64(len(opts.Prompt)) > MaxPromptBytes {
		return fmt.Errorf("prompt exceeds %d-byte limit", MaxPromptBytes)
	}
	if opts.IssueBody != nil && int64(len(*opts.IssueBody)) > MaxIssueBodyBytes {
		return fmt.Errorf("issue body exceeds %d-byte limit", MaxIssueBodyBytes)
	}
	if opts.CapturePrompt && len(opts.Prompt) > maxCapturedPromptBytes {
		return fmt.Errorf("captured prompt exceeds %d-byte limit", maxCapturedPromptBytes)
	}
	return nil
}

func validateRunID(runID string) error {
	if runID == "" {
		return fmt.Errorf("--run-id must not be empty")
	}
	if len(runID) > 128 {
		return fmt.Errorf("--run-id exceeds 128-byte portable limit")
	}
	if strings.HasSuffix(runID, ".") {
		return fmt.Errorf("--run-id must not end with '.'")
	}
	for index, r := range runID {
		allowed := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.'
		validStart := index != 0 || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if !allowed || !validStart {
			return fmt.Errorf("--run-id must use portable ASCII letters, digits, '.', '-', or '_' and start with a letter or digit")
		}
	}
	base := strings.ToUpper(strings.SplitN(runID, ".", 2)[0])
	switch base {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return fmt.Errorf("--run-id uses a reserved portable filename")
	}
	return nil
}
