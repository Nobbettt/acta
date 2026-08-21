package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nobbettt/acta/internal/actaevents"
	"github.com/nobbettt/acta/internal/digest"
	"github.com/nobbettt/acta/internal/doctor"
	"github.com/nobbettt/acta/internal/reporting"
	"github.com/nobbettt/acta/internal/runner"
	"github.com/nobbettt/acta/internal/version"
)

func Execute(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "run":
		return runCommand(ctx, args[1:], stdin, stdout, stderr)
	case "upload":
		return uploadCommand(ctx, args[1:], stdout, stderr)
	case "digest":
		return digestCommand(ctx, args[1:], stdout, stderr)
	case "doctor":
		return doctorCommand(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, version.String())
		return 0
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("acta run", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var opts runner.Options
	var ingestToken string
	var reportTokenEnv string
	var ingestTokenEnv string
	var issueBodyFile string
	fs.StringVar(&opts.Agent, "agent", "", "agent to run: codex or claude")
	fs.StringVar(&opts.CWD, "cwd", ".", "working directory for the agent")
	fs.StringVar(&opts.Prompt, "prompt", "", "task prompt; if empty, remaining args or piped stdin are used")
	fs.BoolVar(&opts.CapturePrompt, "capture-prompt", false, "retain the complete prompt in the normalized event stream; may contain sensitive data")
	fs.StringVar(&opts.Model, "model", "", "optional model passed through to the agent")
	fs.StringVar(&opts.RuntimeBundlePath, "runtime-bundle", "", "private versioned runtime bundle supplied by the control plane")
	fs.StringVar(&opts.Repository, "repo", "", "repository display name such as owner/name")
	fs.IntVar(&opts.IssueNumber, "issue-number", 0, "GitHub issue number used as the task basis")
	fs.StringVar(&opts.IssueTitle, "issue-title", "", "GitHub issue title used as the task basis")
	fs.StringVar(&issueBodyFile, "issue-body-file", "", "markdown/text file containing the issue body to store as run metadata")
	fs.StringVar(&opts.TaskTitle, "title", "", "display title for the run; defaults to the issue title")
	fs.StringVar(&opts.RunsDir, "runs-dir", runner.DefaultRunsDir, "directory for Acta run bundles")
	fs.DurationVar(&opts.Timeout, "timeout", 0, "optional timeout such as 30m or 1h; 0 disables timeout")
	fs.Int64Var(&opts.MaxRawOutputBytes, "max-raw-output-bytes", runner.DefaultMaxRawOutputBytes, "combined stdout/stderr byte limit; 0 explicitly disables the limit")
	fs.Int64Var(&opts.MaxWorkspaceDiffBytes, "max-workspace-diff-bytes", runner.DefaultMaxWorkspaceDiffBytes, "workspace diff byte limit; 0 explicitly disables the limit")
	fs.BoolVar(&opts.Stream, "stream", true, "stream agent stdout and stderr while recording")
	fs.Func("agent-writable-dir", "additional absolute directory the agent may write; repeatable", func(value string) error {
		opts.AgentWritableDirs = append(opts.AgentWritableDirs, value)
		return nil
	})
	fs.StringVar(&opts.CodexSandbox, "codex-sandbox", "workspace-write", "Codex sandbox mode")
	fs.StringVar(&opts.ClaudePermissionMode, "claude-permission-mode", "acceptEdits", "Claude permission mode")
	fs.StringVar(&opts.OTLPEndpoint, "otlp-endpoint", "", "OTLP/HTTP endpoint URL for live trace export (OTEL_EXPORTER_OTLP_* env also honored)")
	fs.BoolVar(&opts.OTLPIncludeOutput, "otlp-include-output", false, "include tool outputs and message text in exported spans")
	fs.BoolVar(&opts.OTLPBestEffort, "otlp-best-effort", false, "allow agent execution to succeed while recording a configured OTLP export failure")
	fs.StringVar(&opts.RunID, "run-id", "", "optional stable run id; defaults to a generated id")
	fs.StringVar(&opts.BackendURL, "backend-url", "", "backend API base URL for report upload")
	fs.StringVar(&opts.ReportToken, "report-token", "", "bearer token for report upload")
	fs.StringVar(&ingestToken, "ingest-token", "", "bearer token for report upload")
	fs.StringVar(&reportTokenEnv, "report-token-env", "", "environment variable containing the report token")
	fs.StringVar(&ingestTokenEnv, "ingest-token-env", "", "environment variable containing the ingest token")
	fs.StringVar(&opts.OrganizationID, "organization-id", "", "organization UUID for scoped report upload")
	fs.StringVar(&opts.RepositoryID, "repository-id", "", "repository UUID for scoped report upload")
	fs.StringVar(&opts.ReportMode, "report-mode", "local", "report mode: local, hybrid, or stream")
	fs.DurationVar(&opts.UploadTimeout, "upload-timeout", runner.DefaultUploadTimeout, "hybrid upload timeout such as 30s or 2m; 0 disables the upload deadline")
	fs.Int64Var(&opts.MaxUploadBytes, "max-upload-bytes", reporting.DefaultMaxUploadBytes, "total immutable upload snapshot byte limit; 0 explicitly disables the limit")
	fs.BoolVar(&opts.AllowInsecureHTTP, "allow-insecure-http", false, "allow plaintext HTTP report upload to a non-loopback backend")
	fs.Func("git-evidence-exclude", "workspace-relative generated/control path to omit from Git evidence; repeatable", func(value string) error {
		opts.GitEvidenceExcludes = append(opts.GitEvidenceExcludes, value)
		return nil
	})

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if opts.Timeout < 0 {
		fmt.Fprintln(stderr, "--timeout must not be negative")
		return 2
	}
	if opts.MaxRawOutputBytes < 0 {
		fmt.Fprintln(stderr, "--max-raw-output-bytes must not be negative")
		return 2
	}
	if opts.MaxWorkspaceDiffBytes < 0 {
		fmt.Fprintln(stderr, "--max-workspace-diff-bytes must not be negative")
		return 2
	}
	if opts.UploadTimeout < 0 {
		fmt.Fprintln(stderr, "--upload-timeout must not be negative")
		return 2
	}
	if opts.MaxUploadBytes < 0 {
		fmt.Fprintln(stderr, "--max-upload-bytes must not be negative")
		return 2
	}
	if err := applyUploadAliases(&opts.ReportToken, ingestToken, &reportTokenEnv, ingestTokenEnv, &opts.ReportMode); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	opts.ReportTokenEnv = strings.TrimSpace(reportTokenEnv)
	if err := applyTokenFromEnv(&opts.ReportToken, reportTokenEnv); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	opts.Agent = strings.TrimSpace(opts.Agent)
	if opts.Agent == "" {
		fmt.Fprintln(stderr, "--agent is required")
		return 2
	}

	promptSource := "flag"
	if strings.TrimSpace(opts.Prompt) == "" && fs.NArg() > 0 {
		opts.Prompt = strings.Join(fs.Args(), " ")
		promptSource = "args"
	}
	if strings.TrimSpace(opts.Prompt) == "" {
		prompt, err := readPromptFromStdin(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "read stdin prompt: %v\n", err)
			return 1
		}
		opts.Prompt = prompt
		promptSource = "stdin"
	}
	if strings.TrimSpace(opts.Prompt) == "" {
		fmt.Fprintln(stderr, "provide a prompt with --prompt, trailing args, or piped stdin")
		return 2
	}
	if int64(len(opts.Prompt)) > runner.MaxPromptBytes {
		fmt.Fprintf(stderr, "prompt exceeds %d-byte limit\n", runner.MaxPromptBytes)
		return 2
	}
	opts.PromptSource = promptSource
	if issueBodyFile != "" {
		issueBody, err := readIssueBodyFile(issueBodyFile)
		if err != nil {
			fmt.Fprintf(stderr, "read issue body file: %v\n", err)
			return 1
		}
		opts.IssueBody = &issueBody
	}

	record, err := runner.Run(ctx, opts, stdout, stderr)
	if record != nil {
		if record.RecoveryDir != "" {
			fmt.Fprintf(stderr, "\nActa recovery bundle retained: %s\n", record.RecoveryDir)
		} else {
			fmt.Fprintf(stderr, "\nActa run saved: %s\n", record.RunDir)
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "acta run failed: %v\n", err)
		if record != nil && record.ExitCode != nil && *record.ExitCode > 0 {
			return *record.ExitCode
		}
		return 1
	}
	return 0
}

func uploadCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("acta upload", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var runDir string
	var backendURL string
	var reportToken string
	var ingestToken string
	var reportTokenEnv string
	var ingestTokenEnv string
	var organizationID string
	var repositoryID string
	var timeout time.Duration
	var maxUploadBytes int64
	var allowInsecureHTTP bool
	fs.StringVar(&runDir, "run-dir", "", "Acta run bundle directory; can also be passed as the single argument")
	fs.StringVar(&backendURL, "backend-url", "", "backend API base URL for report upload")
	fs.StringVar(&reportToken, "report-token", "", "bearer token for report upload")
	fs.StringVar(&ingestToken, "ingest-token", "", "bearer token for report upload")
	fs.StringVar(&reportTokenEnv, "report-token-env", "", "environment variable containing the report token")
	fs.StringVar(&ingestTokenEnv, "ingest-token-env", "", "environment variable containing the ingest token")
	fs.StringVar(&organizationID, "organization-id", "", "organization UUID for scoped report upload")
	fs.StringVar(&repositoryID, "repository-id", "", "repository UUID for scoped report upload")
	fs.DurationVar(&timeout, "timeout", 2*time.Minute, "upload timeout such as 30s or 2m; 0 disables timeout")
	fs.Int64Var(&maxUploadBytes, "max-upload-bytes", reporting.DefaultMaxUploadBytes, "total immutable upload snapshot byte limit; 0 explicitly disables the limit")
	fs.BoolVar(&allowInsecureHTTP, "allow-insecure-http", false, "allow plaintext HTTP upload to a non-loopback backend")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if timeout < 0 {
		fmt.Fprintln(stderr, "--timeout must not be negative")
		return 2
	}
	if maxUploadBytes < 0 {
		fmt.Fprintln(stderr, "--max-upload-bytes must not be negative")
		return 2
	}
	if err := applyUploadAliases(&reportToken, ingestToken, &reportTokenEnv, ingestTokenEnv, nil); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := applyTokenFromEnv(&reportToken, reportTokenEnv); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if strings.TrimSpace(runDir) == "" && fs.NArg() == 1 {
		runDir = fs.Arg(0)
	} else if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: acta upload --backend-url URL (--ingest-token TOKEN | --ingest-token-env ENV) [--run-dir DIR] <run-dir>")
		return 2
	}
	runDir = strings.TrimSpace(runDir)
	if runDir == "" {
		fmt.Fprintln(stderr, "--run-dir or a run directory argument is required")
		return 2
	}
	if strings.TrimSpace(backendURL) == "" {
		fmt.Fprintln(stderr, "--backend-url is required")
		return 2
	}
	if strings.TrimSpace(reportToken) == "" {
		fmt.Fprintln(stderr, "--ingest-token or --ingest-token-env is required")
		return 2
	}

	record, err := runner.ReadRecord(runDir)
	if err != nil {
		fmt.Fprintf(stderr, "acta upload failed: %v\n", err)
		return 1
	}

	uploadCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		uploadCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	if err := reporting.UploadRun(uploadCtx, reporting.Config{
		BackendURL:        backendURL,
		ReportToken:       reportToken,
		OrganizationID:    organizationID,
		RepositoryID:      repositoryID,
		MaxUploadBytes:    maxUploadBytes,
		AllowInsecureHTTP: allowInsecureHTTP,
	}, record); err != nil {
		fmt.Fprintf(stderr, "acta upload failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "Uploaded Acta run %s to %s\n", record.ID, strings.TrimRight(backendURL, "/"))
	return 0
}

func digestCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("acta digest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	workspace := fs.String("workspace", "", "override the workspace root recorded in run.json")
	allowPartial := fs.Bool("allow-partial", false, "write a degraded projection when the raw bundle cannot be fully re-digested")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: acta digest [--workspace DIR] [--allow-partial] <run-dir>")
		return 2
	}
	runDir := fs.Arg(0)

	// A nil digest is a hard failure; a non-nil digest with an error is a soft
	// one (e.g. unreadable arrival-time sidecar) — still write it, but signal.
	d, softErr := digest.FromRunDirContext(ctx, runDir, *workspace)
	if d == nil {
		fmt.Fprintf(stderr, "digest: %v\n", softErr)
		return 1
	}
	if softErr != nil && !*allowPartial {
		fmt.Fprintf(stderr, "digest: %v\n", softErr)
		fmt.Fprintln(stderr, "digest: existing derived artifacts were left unchanged; pass --allow-partial to replace them with a degraded projection")
		return 1
	}
	if err := actaevents.WriteProjectionForRunDir(runDir, d); err != nil {
		fmt.Fprintf(stderr, "digest: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, filepath.Join(runDir, "digest.json"))
	if softErr != nil {
		fmt.Fprintf(stderr, "digest: wrote explicitly allowed degraded projection: %v\n", softErr)
	}
	return 0
}

func doctorCommand(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("acta doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cwd := "."
	runsDir := runner.DefaultRunsDir
	agent := ""
	fs.StringVar(&cwd, "cwd", ".", "working directory to check")
	fs.StringVar(&runsDir, "runs-dir", runner.DefaultRunsDir, "directory for Acta run bundles")
	fs.StringVar(&agent, "agent", "", "agent CLI to check: codex or claude; empty checks both")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	checks := doctor.RunWithOptions(doctor.Options{CWD: cwd, RunsDir: runsDir, Agent: agent})
	exitCode := 0
	for _, check := range checks {
		status := "OK"
		if !check.OK {
			status = "FAIL"
			exitCode = 1
		}
		fmt.Fprintf(stdout, "%-5s %-10s %s\n", status, check.Name, check.Message)
	}
	return exitCode
}

func applyUploadAliases(reportToken *string, ingestToken string, reportTokenEnv *string, ingestTokenEnv string, reportMode *string) error {
	if strings.TrimSpace(ingestToken) != "" {
		if strings.TrimSpace(*reportToken) != "" && strings.TrimSpace(*reportToken) != strings.TrimSpace(ingestToken) {
			return fmt.Errorf("--report-token and --ingest-token disagree")
		}
		*reportToken = strings.TrimSpace(ingestToken)
		if reportMode != nil && strings.EqualFold(strings.TrimSpace(*reportMode), "local") {
			*reportMode = "hybrid"
		}
	}
	if reportTokenEnv != nil && strings.TrimSpace(ingestTokenEnv) != "" {
		if strings.TrimSpace(*reportTokenEnv) != "" && strings.TrimSpace(*reportTokenEnv) != strings.TrimSpace(ingestTokenEnv) {
			return fmt.Errorf("--report-token-env and --ingest-token-env disagree")
		}
		*reportTokenEnv = strings.TrimSpace(ingestTokenEnv)
		if reportMode != nil && strings.EqualFold(strings.TrimSpace(*reportMode), "local") {
			*reportMode = "hybrid"
		}
	}
	return nil
}

func applyTokenFromEnv(reportToken *string, reportTokenEnv string) error {
	reportTokenEnv = strings.TrimSpace(reportTokenEnv)
	if reportTokenEnv == "" {
		return nil
	}
	if strings.TrimSpace(*reportToken) != "" {
		return fmt.Errorf("token value and token environment variable cannot both be provided")
	}
	value, ok := os.LookupEnv(reportTokenEnv)
	if !ok {
		return fmt.Errorf("token environment variable %s is not set", reportTokenEnv)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("token environment variable %s is empty", reportTokenEnv)
	}
	*reportToken = value
	return nil
}

func readPromptFromStdin(stdin io.Reader) (string, error) {
	if file, ok := stdin.(*os.File); ok {
		info, err := file.Stat()
		if err == nil && (info.Mode()&os.ModeCharDevice) != 0 {
			return "", nil
		}
	}
	data, err := io.ReadAll(io.LimitReader(stdin, runner.MaxPromptBytes+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > runner.MaxPromptBytes {
		return "", fmt.Errorf("prompt exceeds %d-byte limit", runner.MaxPromptBytes)
	}
	prompt := string(data)
	if strings.TrimSpace(prompt) == "" {
		return "", nil
	}
	return prompt, nil
}

func readIssueBodyFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("path is empty")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, runner.MaxIssueBodyBytes+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > runner.MaxIssueBodyBytes {
		return "", fmt.Errorf("issue body exceeds %d-byte limit", runner.MaxIssueBodyBytes)
	}
	return string(data), nil
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `acta records noninteractive coding-agent runs.

Usage:
  acta run --agent codex --cwd . --prompt "Summarize this repo"
  acta run --agent claude --cwd . --prompt "Summarize this repo"
  cat task.md | acta run --agent codex --cwd .
  acta upload --backend-url http://localhost:8080 --ingest-token-env ACTA_INGEST_TOKEN .acta/runs/RUN_ID
  acta doctor
  acta version

Commands:
  run       Run an agent and save a local run bundle
  upload    Upload an existing local run bundle to the configured backend
  digest    (Re)build digest.json for an existing run bundle
  doctor    Check local Acta and agent CLI prerequisites
  version   Print version and build metadata
  help      Show this help

`)
}
