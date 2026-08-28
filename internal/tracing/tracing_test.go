package tracing

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/nobbettt/acta/internal/agents"
	"github.com/nobbettt/acta/internal/runrecord"
)

var testStart = time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

const (
	testParentTraceID = "11111111111111111111111111111111"
	testParentSpanID  = "2222222222222222"
	testTraceparent   = "00-" + testParentTraceID + "-" + testParentSpanID + "-01"
)

func newTestRun(t *testing.T, agent string) (*tracetest.SpanRecorder, *Run) {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	r, err := newRun(context.Background(), provider, Config{
		Agent:     agent,
		RunID:     "test-run",
		StartedAt: testStart,
	})
	if err != nil {
		t.Fatal(err)
	}
	return recorder, r
}

func newTestRunOutput(t *testing.T, agent string, includeOutput bool) (*tracetest.SpanRecorder, *Run) {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	r, err := newRun(context.Background(), provider, Config{
		Agent:         agent,
		RunID:         "test-run",
		StartedAt:     testStart,
		IncludeOutput: includeOutput,
	})
	if err != nil {
		t.Fatal(err)
	}
	return recorder, r
}

// Tool-call arguments (command text, edit contents) and file paths can carry
// secrets or local absolute paths, so they must be exported only under
// --otlp-include-output. By default a span carries structural metadata only.
func TestContentAttributesGatedByIncludeOutput(t *testing.T) {
	fixtures := map[string]string{
		"claude": "claude-output.jsonl",
		"codex":  "codex-events.jsonl",
	}
	scan := func(agent string, includeOutput bool) (args, paths bool) {
		recorder, r := newTestRunOutput(t, agent, includeOutput)
		completedAt := feedFixture(t, r, fixtures[agent], 0)
		finish(t, r, true, completedAt)
		for _, span := range recorder.Ended() {
			if _, ok := attrValue(span, attrToolCallArguments); ok {
				args = true
			}
			if _, ok := attrValue(span, attrFilePath); ok {
				paths = true
			}
		}
		return
	}
	for agent := range fixtures {
		if args, paths := scan(agent, false); args || paths {
			t.Errorf("%s default: arguments=%v file_path=%v, want both absent without --otlp-include-output", agent, args, paths)
		}
		if args, paths := scan(agent, true); !args || !paths {
			t.Errorf("%s with include-output: arguments=%v file_path=%v, want both present", agent, args, paths)
		}
	}
}

func TestReasoningTextNeverEntersTelemetry(t *testing.T) {
	const secret = "private-reasoning-telemetry-8842"
	lines := map[string]string{
		"codex":  `{"type":"item.completed","item":{"id":"r1","type":"reasoning","text":"` + secret + `"}}`,
		"claude": `{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"` + secret + `"}]}}`,
	}
	for agent, line := range lines {
		recorder, run := newTestRunOutput(t, agent, true)
		run.OnLine([]byte(line), testStart.Add(time.Millisecond))
		finish(t, run, true, testStart.Add(time.Second))
		reasoningEvents := 0
		for _, span := range recorder.Ended() {
			for _, value := range span.Attributes() {
				if strings.Contains(fmt.Sprint(value.Value.AsInterface()), secret) {
					t.Fatalf("%s span attribute %s leaked reasoning text", agent, value.Key)
				}
			}
			for _, event := range span.Events() {
				if event.Name == "acta.reasoning" {
					reasoningEvents++
				}
				for _, value := range event.Attributes {
					if value.Key == "text" || strings.Contains(fmt.Sprint(value.Value.AsInterface()), secret) {
						t.Fatalf("%s event attribute %s leaked reasoning text", agent, value.Key)
					}
				}
			}
		}
		if reasoningEvents != 1 {
			t.Fatalf("%s reasoning structural events = %d, want 1", agent, reasoningEvents)
		}
	}
}

// feedFixture replays a fixture line by line with synthetic arrival times
// 10ms apart, then finishes the run.
func feedFixture(t *testing.T, r *Run, fixture string, lines int) time.Time {
	t.Helper()
	f, err := os.Open("../digest/testdata/" + fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	at := testStart
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	n := 0
	for scanner.Scan() {
		n++
		if lines > 0 && n > lines {
			break
		}
		at = at.Add(10 * time.Millisecond)
		r.OnLine(scanner.Bytes(), at)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return at.Add(10 * time.Millisecond)
}

func finish(t *testing.T, r *Run, ok bool, completedAt time.Time) {
	t.Helper()
	exit := 0
	if !ok {
		exit = 1
	}
	if err := r.Finish(&runrecord.Record{OK: ok, ExitCode: &exit}, completedAt); err != nil {
		t.Fatal(err)
	}
}

// failingShutdown is a span processor whose Shutdown errors, so we can assert
// Finish surfaces a failed final flush instead of swallowing it.
type failingShutdown struct{ sdktrace.SpanProcessor }

func (failingShutdown) Shutdown(context.Context) error { return errTestFlush }

var errTestFlush = errorString("flush boom")

type errorString string

func (e errorString) Error() string { return string(e) }

func TestFinishSurfacesFlushError(t *testing.T) {
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(failingShutdown{tracetest.NewSpanRecorder()}))
	r, err := newRun(context.Background(), provider, Config{Agent: "codex", RunID: "t", StartedAt: testStart})
	if err != nil {
		t.Fatal(err)
	}
	exit := 0
	if err := r.Finish(&runrecord.Record{OK: true, ExitCode: &exit}, testStart.Add(time.Second)); err == nil {
		t.Fatal("Finish must surface the provider flush/Shutdown error")
	}

	var nilRun *Run
	if err := nilRun.Finish(&runrecord.Record{}, testStart); err != nil {
		t.Fatalf("nil Run Finish should be a no-op, got %v", err)
	}
}

func TestEnabledHonorsStandardDisableControls(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://collector.test/v1/traces")
	t.Setenv("OTEL_SDK_DISABLED", "true")
	if Enabled("") {
		t.Fatal("OTEL_SDK_DISABLED=true must disable tracing")
	}
	t.Setenv("OTEL_SDK_DISABLED", "false")
	t.Setenv("OTEL_TRACES_EXPORTER", "none")
	if Enabled("https://explicit.test/v1/traces") {
		t.Fatal("OTEL_TRACES_EXPORTER=none must disable an explicit endpoint")
	}
}

func TestEndpointConfigurationRequiresAbsoluteHTTPURL(t *testing.T) {
	for _, name := range []string{
		"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_SDK_DISABLED", "OTEL_TRACES_EXPORTER",
	} {
		t.Setenv(name, "")
	}
	tests := []struct {
		name     string
		endpoint string
		wantErr  bool
	}{
		{name: "invalid escape", endpoint: "%invalid", wantErr: true},
		{name: "missing scheme", endpoint: "collector.test/v1/traces", wantErr: true},
		{name: "missing host", endpoint: "https:///v1/traces", wantErr: true},
		{name: "wrong scheme", endpoint: "grpc://collector.test/v1/traces", wantErr: true},
		{name: "http", endpoint: "http://collector.test/v1/traces"},
		{name: "https", endpoint: "https://collector.test/v1/traces"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := EndpointConfigurationError(test.endpoint)
			if got := err != nil; got != test.wantErr {
				t.Fatalf("endpoint configuration error = %v, present %v; want present %v", err, got, test.wantErr)
			}
			if got := Enabled(test.endpoint); got == test.wantErr {
				t.Fatalf("Enabled(%q) = %v, want %v", test.endpoint, got, !test.wantErr)
			}
		})
	}
}

func TestEndpointConfigurationUsesExporterPrecedenceForEnvironment(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "%invalid-generic")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://traces.test/v1/traces")
	if err := EndpointConfigurationError(""); err != nil {
		t.Fatalf("valid traces-specific endpoint did not override generic endpoint: %v", err)
	}

	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "%invalid-traces")
	if err := EndpointConfigurationError(""); err == nil ||
		!strings.Contains(err.Error(), "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") {
		t.Fatalf("environment endpoint error = %v, want traces-specific source", err)
	}
	if err := EndpointConfigurationError("https://explicit.test/v1/traces"); err != nil {
		t.Fatalf("valid explicit endpoint did not override environment: %v", err)
	}
}

func TestSetupRejectsInvalidExplicitEndpointBeforeAmbientFallback(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://ambient.test/v1/traces")
	_, err := Setup(context.Background(), Config{
		Endpoint:  "%invalid",
		Agent:     "codex",
		RunID:     "invalid-endpoint",
		StartedAt: testStart,
	})
	if err == nil || !strings.Contains(err.Error(), "--otlp-endpoint must be an absolute http(s) URL with a host") {
		t.Fatalf("Setup error = %v, want invalid explicit endpoint error", err)
	}
}

func TestDeliveryUnavailableReasonRejectsEffectivelyZeroParentBasedRootRatio(t *testing.T) {
	tests := []struct {
		name        string
		ratio       string
		traceparent string
		forceRoot   bool
		wantReason  bool
	}{
		{name: "zero without parent", ratio: "0", wantReason: true},
		{name: "effectively zero without parent", ratio: "1e-20", wantReason: true},
		{name: "zero with malformed parent", ratio: "0", traceparent: "malformed", wantReason: true},
		{name: "zero with unsampled parent", ratio: "0", traceparent: "00-11111111111111111111111111111111-2222222222222222-00", wantReason: true},
		{name: "zero with sampled parent", ratio: "0", traceparent: testTraceparent},
		{name: "zero with ignored sampled parent", ratio: "0", traceparent: testTraceparent, forceRoot: true, wantReason: true},
		{name: "usable root ratio without parent", ratio: "0.5"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("OTEL_SDK_DISABLED", "")
			t.Setenv("OTEL_TRACES_EXPORTER", "")
			t.Setenv("OTEL_TRACES_SAMPLER", "parentbased_traceidratio")
			t.Setenv("OTEL_TRACES_SAMPLER_ARG", test.ratio)
			t.Setenv("TRACEPARENT", test.traceparent)
			reason := DeliveryUnavailableReasonWithForceRoot("http://127.0.0.1:4318/v1/traces", test.forceRoot)
			if got := reason != ""; got != test.wantReason {
				t.Fatalf("delivery unavailable reason = %q, present %v; want present %v", reason, got, test.wantReason)
			}
			if reason != "" && !strings.Contains(reason, "parentbased_traceidratio") {
				t.Fatalf("delivery unavailable reason = %q, want sampler name", reason)
			}
		})
	}
}

func TestSamplerFromEnvironmentHonorsSamplerAndArgument(t *testing.T) {
	t.Setenv("OTEL_TRACES_SAMPLER", "traceidratio")
	t.Setenv("OTEL_TRACES_SAMPLER_ARG", "0")
	parameters := sdktrace.SamplingParameters{Name: "test"}
	if decision := samplerFromEnvironment().ShouldSample(parameters).Decision; decision != sdktrace.Drop {
		t.Fatalf("traceidratio=0 decision = %v, want drop", decision)
	}
	t.Setenv("OTEL_TRACES_SAMPLER_ARG", "1")
	if decision := samplerFromEnvironment().ShouldSample(parameters).Decision; decision != sdktrace.RecordAndSample {
		t.Fatalf("traceidratio=1 decision = %v, want record and sample", decision)
	}
	t.Setenv("OTEL_TRACES_SAMPLER", "always_off")
	if decision := samplerFromEnvironment().ShouldSample(parameters).Decision; decision != sdktrace.Drop {
		t.Fatalf("always_off decision = %v, want drop", decision)
	}
}

func TestUnsampledRunHasNoExportableTraceID(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.NeverSample()),
		sdktrace.WithSpanProcessor(recorder),
	)
	run, err := newRun(context.Background(), provider, Config{Agent: "codex", RunID: "unsampled", StartedAt: testStart})
	if err != nil {
		t.Fatal(err)
	}
	if run.Sampled() || run.TraceID() != "" {
		t.Fatalf("unsampled run reported sampled=%v trace_id=%q", run.Sampled(), run.TraceID())
	}
	finish(t, run, true, testStart.Add(time.Second))
	if len(recorder.Ended()) != 0 {
		t.Fatalf("unsampled ended spans = %d, want 0", len(recorder.Ended()))
	}
}

// Every registered agent must resolve a trace mapper and declare a provider, so
// adding an agent without wiring tracing fails here instead of silently
// exporting no spans at runtime.
func TestEveryAgentHasTraceMapper(t *testing.T) {
	for _, a := range agents.All() {
		recorder := tracetest.NewSpanRecorder()
		provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
		if _, err := newRun(context.Background(), provider, Config{Agent: a.Name(), Provider: a.Provider(), RunID: "t", StartedAt: testStart}); err != nil {
			t.Errorf("agent %q: newRun: %v", a.Name(), err)
		}
		if a.Provider() == "" {
			t.Errorf("agent %q: empty provider", a.Name())
		}
	}
}

// The provider name from the agent adapter must reach the exported root span
// (gen_ai.provider.name), not just Config.
func TestProviderAttributeOnRootSpan(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	r, err := newRun(context.Background(), provider, Config{Agent: "claude", Provider: "anthropic", RunID: "t", StartedAt: testStart})
	if err != nil {
		t.Fatal(err)
	}
	finish(t, r, true, testStart.Add(time.Second))

	var root sdktrace.ReadOnlySpan
	for _, span := range recorder.Ended() {
		if span.Name() == "invoke_agent claude" {
			root = span
		}
	}
	if root == nil {
		t.Fatal("root span not ended")
	}
	if v, ok := attrValue(root, attrProviderName); !ok || v.AsString() != "anthropic" {
		t.Fatalf("gen_ai.provider.name = %v (ok=%v), want anthropic", v, ok)
	}
}

func TestRunRootUsesW3CParentContext(t *testing.T) {
	t.Setenv("TRACEPARENT", testTraceparent)
	t.Setenv("TRACESTATE", "vendor=opaque")

	root := recordedRoot(t, Config{Agent: "codex", RunID: "child", StartedAt: testStart})
	parent := root.Parent()
	if !parent.IsValid() || !parent.IsRemote() {
		t.Fatalf("parent = %v, want valid remote parent", parent)
	}
	if got := root.SpanContext().TraceID().String(); got != testParentTraceID {
		t.Errorf("root trace id = %q, want %q", got, testParentTraceID)
	}
	if got := parent.TraceID().String(); got != testParentTraceID {
		t.Errorf("parent trace id = %q, want %q", got, testParentTraceID)
	}
	if got := parent.SpanID().String(); got != testParentSpanID {
		t.Errorf("parent span id = %q, want %q", got, testParentSpanID)
	}
}

func TestRunRootWithoutParentContext(t *testing.T) {
	t.Setenv("TRACEPARENT", "")
	t.Setenv("TRACESTATE", "")

	root := recordedRoot(t, Config{Agent: "codex", RunID: "standalone", StartedAt: testStart})
	if parent := root.Parent(); parent.IsValid() || parent.IsRemote() {
		t.Fatalf("parent = %v, want standalone root with no remote parent", parent)
	}
}

func TestRunRootIgnoresMalformedTraceparent(t *testing.T) {
	t.Setenv("TRACEPARENT", "not-w3c-trace-context")
	t.Setenv("TRACESTATE", "vendor=opaque")

	root := recordedRoot(t, Config{Agent: "codex", RunID: "malformed", StartedAt: testStart})
	if parent := root.Parent(); parent.IsValid() || parent.IsRemote() {
		t.Fatalf("parent = %v, want standalone root for malformed TRACEPARENT", parent)
	}
}

func TestRunRootForceRootIgnoresValidParent(t *testing.T) {
	t.Setenv("TRACEPARENT", testTraceparent)
	t.Setenv("TRACESTATE", "vendor=opaque")

	root := recordedRoot(t, Config{Agent: "codex", RunID: "forced-root", StartedAt: testStart, ForceRoot: true})
	if parent := root.Parent(); parent.IsValid() || parent.IsRemote() {
		t.Fatalf("parent = %v, want standalone root with ForceRoot", parent)
	}
	if got := root.SpanContext().TraceID().String(); got == testParentTraceID {
		t.Errorf("root trace id = parent trace id %q despite ForceRoot", got)
	}
}

func TestRunRootPropagatesTracestate(t *testing.T) {
	const want = "vendor=opaque,other=value"
	t.Setenv("TRACEPARENT", testTraceparent)
	t.Setenv("TRACESTATE", want)

	root := recordedRoot(t, Config{Agent: "claude", RunID: "state", StartedAt: testStart})
	if got := root.Parent().TraceState().String(); got != want {
		t.Fatalf("parent tracestate = %q, want %q", got, want)
	}
}

func TestTextEventCountsCharactersNotBytes(t *testing.T) {
	recorder, r := newTestRun(t, "codex")
	r.addTextEvent("acta.message", "a€", testStart)
	finish(t, r, true, testStart.Add(time.Second))

	for _, span := range recorder.Ended() {
		for _, event := range span.Events() {
			if event.Name != "acta.message" {
				continue
			}
			for _, attr := range event.Attributes {
				if attr.Key == attrEventChars && attr.Value.AsInt64() == 2 {
					return
				}
			}
			t.Fatal("acta.event.chars did not report two Unicode characters")
		}
	}
	t.Fatal("acta.message event not found")
}

func attrValue(span sdktrace.ReadOnlySpan, key attribute.Key) (attribute.Value, bool) {
	for _, kv := range span.Attributes() {
		if kv.Key == key {
			return kv.Value, true
		}
	}
	return attribute.Value{}, false
}

func recordedRoot(t *testing.T, cfg Config) sdktrace.ReadOnlySpan {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	r, err := newRun(context.Background(), provider, cfg)
	if err != nil {
		t.Fatal(err)
	}
	finish(t, r, true, cfg.StartedAt.Add(time.Second))
	for _, span := range recorder.Ended() {
		if span.Name() == "invoke_agent "+cfg.Agent {
			return span
		}
	}
	t.Fatalf("root span for %q not ended", cfg.Agent)
	return nil
}

func TestClaudeFixtureSpans(t *testing.T) {
	recorder, r := newTestRun(t, "claude")
	completedAt := feedFixture(t, r, "claude-output.jsonl", 0)
	finish(t, r, true, completedAt)

	spans := recorder.Ended()
	var root sdktrace.ReadOnlySpan
	toolSpans := map[string]int{}
	for _, span := range spans {
		if span.Name() == "invoke_agent claude" {
			root = span
			continue
		}
		if v, ok := attrValue(span, attrToolName); ok {
			toolSpans[v.AsString()]++
		}
		if !span.Parent().IsValid() {
			t.Errorf("tool span %q has no parent", span.Name())
		}
		if span.EndTime().Before(span.StartTime()) {
			t.Errorf("span %q ends before it starts", span.Name())
		}
	}
	if root == nil {
		t.Fatal("root span not ended")
	}
	// The synthetic fixture has four tool_use blocks, all with matching results.
	total := 0
	for _, n := range toolSpans {
		total += n
	}
	if total != 4 {
		t.Errorf("tool spans = %d (%v), want 4", total, toolSpans)
	}
	if toolSpans["Read"] != 1 || toolSpans["Bash"] != 1 {
		t.Errorf("tool span counts = %v, want Read 1 / Bash 1", toolSpans)
	}

	if v, ok := attrValue(root, attrUsageOutputTokens); !ok || v.AsInt64() != 20 {
		t.Errorf("root output tokens = %v, want 20", v)
	}
	if v, ok := attrValue(root, attrUsageCacheRead); !ok || v.AsInt64() != 30 {
		t.Errorf("root cache read = %v, want 30", v)
	}
	if v, ok := attrValue(root, attrResponseModel); !ok || v.AsString() == "" {
		t.Error("root missing response model from system init")
	}
	if root.Status().Code != codes.Ok {
		t.Errorf("root status = %v, want Ok", root.Status())
	}
	if !root.StartTime().Equal(testStart) {
		t.Errorf("root start = %v, want %v (backdated)", root.StartTime(), testStart)
	}

	// Root span events: two texts plus one synthetic thinking event.
	events := 0
	for _, e := range root.Events() {
		if e.Name == "acta.message" || e.Name == "acta.reasoning" {
			events++
		}
	}
	if events != 3 {
		t.Errorf("root text events = %d, want 3", events)
	}
}

func TestClaudeUnclosedSpansOnKill(t *testing.T) {
	recorder, r := newTestRun(t, "claude")
	// Feed only the first three lines, stopping after Read starts but before its result.
	completedAt := feedFixture(t, r, "claude-output.jsonl", 3)
	finish(t, r, false, completedAt)

	errored := 0
	for _, span := range recorder.Ended() {
		if span.Name() == "invoke_agent claude" {
			if span.Status().Code != codes.Error {
				t.Errorf("root status = %v, want Error for failed run", span.Status())
			}
			continue
		}
		if span.Status().Code == codes.Error && span.Status().Description == "unclosed at run end" {
			errored++
			if !span.EndTime().Equal(completedAt) {
				t.Errorf("unclosed span end = %v, want %v", span.EndTime(), completedAt)
			}
		}
	}
	if errored == 0 {
		t.Error("expected at least one unclosed span ended with Error status")
	}
}

func TestCodexFixtureSpans(t *testing.T) {
	recorder, r := newTestRun(t, "codex")
	completedAt := feedFixture(t, r, "codex-events.jsonl", 0)
	finish(t, r, true, completedAt)

	var root sdktrace.ReadOnlySpan
	commands, fileChanges := 0, 0
	for _, span := range recorder.Ended() {
		switch span.Name() {
		case "invoke_agent codex":
			root = span
		case "execute_tool command_execution":
			commands++
			// started via item.started, ended via item.completed: real duration
			if !span.EndTime().After(span.StartTime()) {
				t.Errorf("command span has no duration: %v .. %v", span.StartTime(), span.EndTime())
			}
		case "execute_tool file_change":
			fileChanges++
			if !span.EndTime().Equal(span.StartTime()) {
				t.Error("file_change span should be zero-duration")
			}
		}
	}
	if root == nil {
		t.Fatal("root span not ended")
	}
	if commands != 2 {
		t.Errorf("command spans = %d, want 2", commands)
	}
	if fileChanges != 1 {
		t.Errorf("file_change spans = %d, want 1", fileChanges)
	}
	if v, ok := attrValue(root, attrUsageInputTokens); !ok || v.AsInt64() != 120 {
		t.Errorf("root input tokens = %v, want 120", v)
	}
	if v, ok := attrValue(root, attrConversationID); !ok || v.AsString() == "" {
		t.Error("root missing conversation id from thread.started")
	}
}

func TestNilRunIsSafe(t *testing.T) {
	var r *Run
	if r.TraceID() != "" {
		t.Error("nil TraceID should be empty")
	}
	r.OnLine([]byte("{}"), time.Now())
	if err := r.Finish(&runrecord.Record{}, time.Now()); err != nil {
		t.Fatal(err)
	}
}
