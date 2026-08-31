// Package tracing exports agent runs as OpenTelemetry traces over OTLP/HTTP:
// one trace per run, a root invoke_agent span, one execute_tool child span
// per tool call or command, and span events for assistant messages. Spans are
// stamped with line arrival times observed live during the run — the raw
// agent streams carry no timestamps, so live emission is the only way to get
// a real timeline.
package tracing

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/nobbettt/acta/internal/runrecord"
)

type Config struct {
	Endpoint      string // --otlp-endpoint override; "" uses OTEL_EXPORTER_OTLP_* env
	IncludeOutput bool   // export tool outputs and message text
	ForceRoot     bool   // ignore TRACEPARENT/TRACESTATE and start a new trace
	RunID         string
	Agent         string // codex | claude
	Provider      string // GenAI provider name (from the agent adapter)
	Model         string
	PromptSource  string
	StartedAt     time.Time
}

// Enabled reports whether OTLP export should be set up at all: an explicit
// flag or one of the standard endpoint env vars. Otherwise no provider is
// constructed and runs carry zero tracing overhead.
func Enabled(endpointFlag string) bool {
	if sdkDisabled() {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("OTEL_TRACES_EXPORTER")), "none") {
		return false
	}
	return endpointConfigured(endpointFlag) && EndpointConfigurationError(endpointFlag) == nil
}

// EndpointConfigurationError reports whether the effective OTLP endpoint is
// unsafe to pass to the exporter. The explicit flag takes precedence over the
// traces-specific and generic environment variables, matching the exporter.
func EndpointConfigurationError(endpointFlag string) error {
	endpoint, source := configuredEndpoint(endpointFlag)
	if endpoint == "" {
		return nil
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("%s must be an absolute http(s) URL with a host and valid port", source)
	}
	scheme := strings.ToLower(parsed.Scheme)
	hostname := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if hostname == "" || portErr != nil || portNumber == 0 || (scheme != "http" && scheme != "https") {
		return fmt.Errorf("%s must be an absolute http(s) URL with a host and valid port", source)
	}
	return nil
}

// DeliveryUnavailableReason reports startup configuration which makes a
// required trace export impossible rather than merely fallible.
func DeliveryUnavailableReason(endpointFlag string) string {
	return deliveryUnavailableReason(endpointFlag, false)
}

// DeliveryUnavailableReasonWithForceRoot also accounts for the caller
// deliberately ignoring otherwise valid inbound trace context.
func DeliveryUnavailableReasonWithForceRoot(endpointFlag string, forceRoot bool) string {
	return deliveryUnavailableReason(endpointFlag, forceRoot)
}

func deliveryUnavailableReason(endpointFlag string, forceRoot bool) string {
	if sdkDisabled() {
		return "OTEL_SDK_DISABLED=true disables OpenTelemetry"
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("OTEL_TRACES_EXPORTER")), "none") {
		return "OTEL_TRACES_EXPORTER=none disables trace export"
	}
	if !endpointConfigured(endpointFlag) {
		return "no OTLP endpoint is configured; set --otlp-endpoint, OTEL_EXPORTER_OTLP_ENDPOINT, or OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"
	}
	if err := EndpointConfigurationError(endpointFlag); err != nil {
		return err.Error()
	}
	sampler := strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER")))
	if sampler == "always_off" {
		return "OTEL_TRACES_SAMPLER=always_off disables sampling"
	}
	if sampler == "parentbased_always_off" {
		parent := inboundParentSpanContext()
		if forceRoot || !parent.IsValid() || !parent.IsSampled() {
			return "OTEL_TRACES_SAMPLER=parentbased_always_off disables sampling without a sampled inbound parent context"
		}
	}
	if sampler == "traceidratio" && samplerRatioEffectivelyZero() {
		return "OTEL_TRACES_SAMPLER=traceidratio with OTEL_TRACES_SAMPLER_ARG=0 disables sampling"
	}
	if sampler == "parentbased_traceidratio" && samplerRatioEffectivelyZero() {
		parent := inboundParentSpanContext()
		if forceRoot || !parent.IsValid() || !parent.IsSampled() {
			return "OTEL_TRACES_SAMPLER=parentbased_traceidratio with an effectively zero root ratio disables sampling without a sampled inbound parent context"
		}
	}
	return ""
}

func samplerRatioEffectivelyZero() bool {
	ratio, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER_ARG")), 64)
	return err == nil && ratio >= 0 && ratio <= 1 && uint64(ratio*(1<<63)) == 0
}

func sdkDisabled() bool {
	disabled, err := strconv.ParseBool(strings.TrimSpace(os.Getenv("OTEL_SDK_DISABLED")))
	return err == nil && disabled
}

func endpointConfigured(endpointFlag string) bool {
	endpoint, _ := configuredEndpoint(endpointFlag)
	return endpoint != ""
}

func configuredEndpoint(endpointFlag string) (endpoint, source string) {
	if endpoint := strings.TrimSpace(endpointFlag); endpoint != "" {
		return endpoint, "--otlp-endpoint"
	}
	if endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")); endpoint != "" {
		return endpoint, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"
	}
	if endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")); endpoint != "" {
		return endpoint, "OTEL_EXPORTER_OTLP_ENDPOINT"
	}
	return "", ""
}

func inboundParentSpanContext() trace.SpanContext {
	parentCtx := propagation.TraceContext{}.Extract(context.Background(), propagation.MapCarrier{
		"traceparent": os.Getenv("TRACEPARENT"),
		"tracestate":  os.Getenv("TRACESTATE"),
	})
	return trace.SpanContextFromContext(parentCtx)
}

// Run is one live-traced agent run. All methods are nil-receiver safe so the
// runner can call them unconditionally.
type Run struct {
	provider      *sdktrace.TracerProvider
	exportErrors  *errorCapturingExporter
	spanDelivery  *dropCountingSpanProcessor
	tracer        trace.Tracer
	rootCtx       context.Context
	root          trace.Span
	sampled       bool
	mapper        mapper
	includeOutput bool
}

// errorCapturingExporter retains failures from batches exported by the
// processor's background worker. The SDK reports those failures to its global
// error handler instead of returning them from a later ForceFlush.
type errorCapturingExporter struct {
	exporter  sdktrace.SpanExporter
	mu        sync.Mutex
	err       error
	forwarded atomic.Uint64
}

func (e *errorCapturingExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	e.forwarded.Add(uint64(len(spans)))
	err := e.exporter.ExportSpans(ctx, spans)
	if err != nil {
		e.mu.Lock()
		e.err = errors.Join(e.err, err)
		e.mu.Unlock()
	}
	return err
}

// dropCountingSpanProcessor compares every sampled span handed to the batch
// processor with the spans that reach its exporter. The SDK's non-blocking
// queue otherwise discards overflow without returning an error from OnEnd or
// a later ForceFlush.
type dropCountingSpanProcessor struct {
	processor sdktrace.SpanProcessor
	exporter  *errorCapturingExporter
	ended     atomic.Uint64
}

func (p *dropCountingSpanProcessor) OnStart(ctx context.Context, span sdktrace.ReadWriteSpan) {
	p.processor.OnStart(ctx, span)
}

func (p *dropCountingSpanProcessor) OnEnd(span sdktrace.ReadOnlySpan) {
	p.ended.Add(1)
	p.processor.OnEnd(span)
}

func (p *dropCountingSpanProcessor) Shutdown(ctx context.Context) error {
	return p.processor.Shutdown(ctx)
}

func (p *dropCountingSpanProcessor) ForceFlush(ctx context.Context) error {
	return p.processor.ForceFlush(ctx)
}

func (p *dropCountingSpanProcessor) DropError() error {
	if p == nil || p.exporter == nil {
		return nil
	}
	ended := p.ended.Load()
	forwarded := p.exporter.forwarded.Load()
	if ended <= forwarded {
		return nil
	}
	return fmt.Errorf("batch span processor dropped %d of %d ended spans", ended-forwarded, ended)
}

func (e *errorCapturingExporter) Shutdown(ctx context.Context) error {
	return e.exporter.Shutdown(ctx)
}

func (e *errorCapturingExporter) Err() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}

// mapper turns one raw agent output line into span operations.
type mapper interface {
	onLine(r *Run, line []byte, at time.Time)
	// openSpans returns spans still open at run end (killed mid-flight).
	openSpans() []trace.Span
}

func Setup(ctx context.Context, cfg Config) (*Run, error) {
	if err := EndpointConfigurationError(cfg.Endpoint); err != nil {
		return nil, fmt.Errorf("create OTLP exporter: %w", err)
	}
	var expOpts []otlptracehttp.Option
	if endpoint := strings.TrimSpace(cfg.Endpoint); endpoint != "" {
		expOpts = append(expOpts, otlptracehttp.WithEndpointURL(endpoint))
	}
	exporter, err := otlptracehttp.New(ctx, expOpts...)
	if err != nil {
		return nil, fmt.Errorf("create OTLP exporter: %w", err)
	}

	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		attribute.String("service.name", "acta"),
	))
	if err != nil {
		res = resource.Default()
	}
	capturingExporter := &errorCapturingExporter{exporter: exporter}
	batchProcessor := sdktrace.NewBatchSpanProcessor(capturingExporter)
	dropCountingProcessor := &dropCountingSpanProcessor{
		processor: batchProcessor,
		exporter:  capturingExporter,
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(dropCountingProcessor),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(samplerFromEnvironment()),
	)
	run, err := newRun(ctx, provider, cfg)
	if err != nil {
		_ = provider.Shutdown(context.Background())
		return nil, err
	}
	run.exportErrors = capturingExporter
	run.spanDelivery = dropCountingProcessor
	return run, nil
}

// samplerFromEnvironment implements the standard built-in
// OTEL_TRACES_SAMPLER values. Unknown names and invalid ratio arguments use
// the SDK default (parent-based always-on) instead of silently forcing a
// different sampling policy.
func samplerFromEnvironment() sdktrace.Sampler {
	defaultSampler := sdktrace.ParentBased(sdktrace.AlwaysSample())
	ratio := func() sdktrace.Sampler {
		value, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER_ARG")), 64)
		if err != nil || value < 0 || value > 1 {
			value = 1
		}
		return sdktrace.TraceIDRatioBased(value)
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER"))) {
	case "":
		return defaultSampler
	case "always_on":
		return sdktrace.AlwaysSample()
	case "always_off":
		return sdktrace.NeverSample()
	case "traceidratio":
		return ratio()
	case "parentbased_always_on":
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	case "parentbased_always_off":
		return sdktrace.ParentBased(sdktrace.NeverSample())
	case "parentbased_traceidratio":
		return sdktrace.ParentBased(ratio())
	default:
		return defaultSampler
	}
}

// newRun starts the root span on an existing provider (split from Setup so
// tests can inject an in-memory provider).
func newRun(ctx context.Context, provider *sdktrace.TracerProvider, cfg Config) (*Run, error) {
	var m mapper
	switch cfg.Agent {
	case "codex":
		m = &codexMapper{spans: map[string]trace.Span{}}
	case "claude":
		m = &claudeMapper{spans: map[string]trace.Span{}}
	default:
		return nil, fmt.Errorf("no trace mapper for agent %q", cfg.Agent)
	}

	r := &Run{
		provider:      provider,
		tracer:        provider.Tracer("acta"),
		mapper:        m,
		includeOutput: cfg.IncludeOutput,
	}
	attrs := []attribute.KeyValue{
		attrOperationName.String("invoke_agent"),
		attrAgentName.String(cfg.Agent),
		attrProviderName.String(cfg.Provider),
		attrRunID.String(cfg.RunID),
		attrPromptSource.String(cfg.PromptSource),
	}
	if cfg.Model != "" {
		attrs = append(attrs, attrRequestModel.String(cfg.Model))
	}
	startCtx := ctx
	startOpts := []trace.SpanStartOption{
		trace.WithTimestamp(cfg.StartedAt),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	}
	if cfg.ForceRoot {
		startOpts = append(startOpts, trace.WithNewRoot())
	} else if parent := inboundParentSpanContext(); parent.IsValid() {
		startCtx = trace.ContextWithRemoteSpanContext(ctx, parent)
	}
	r.rootCtx, r.root = r.tracer.Start(startCtx, "invoke_agent "+cfg.Agent, startOpts...)
	r.sampled = r.root.IsRecording() && r.root.SpanContext().IsSampled()
	return r, nil
}

// Sampled reports whether the root is recording and selected for export. It
// must be checked before Finish ends the root span.
func (r *Run) Sampled() bool {
	if r == nil {
		return false
	}
	return r.sampled
}

// TraceID returns the sampled run's trace id for run.json correlation. A
// dropped root has a locally generated context but no remotely queryable
// trace, so exposing that ID would be misleading.
func (r *Run) TraceID() string {
	if !r.Sampled() {
		return ""
	}
	return r.root.SpanContext().TraceID().String()
}

// OnLine feeds one raw agent output line (arrival-stamped by the runner tee).
// Must never panic or error — it sits on the recording path.
func (r *Run) OnLine(line []byte, at time.Time) {
	if r == nil {
		return
	}
	r.mapper.onLine(r, line, at)
}

// Finish closes any spans left open by a killed run, finalizes the root span
// from the run record, and flushes the exporter. The parent context is
// already canceled on SIGINT/timeout, so shutdown gets a detached context.
func (r *Run) Finish(record *runrecord.Record, completedAt time.Time) error {
	if r == nil {
		return nil
	}
	for _, span := range r.mapper.openSpans() {
		span.SetStatus(codes.Error, "unclosed at run end")
		span.End(trace.WithTimestamp(completedAt))
	}
	r.root.SetAttributes(
		attrRunOK.Bool(record.OK),
		attrRunTimeout.Bool(record.Timeout),
	)
	if record.ExitCode != nil {
		r.root.SetAttributes(attrRunExitCode.Int(*record.ExitCode))
	}
	if record.OK {
		r.root.SetStatus(codes.Ok, "")
	} else {
		r.root.SetStatus(codes.Error, record.Error)
	}
	r.root.End(trace.WithTimestamp(completedAt))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The wrappers retain errors from batches already handled by the background
	// worker and detect spans discarded before reaching the exporter. ForceFlush
	// and Shutdown cover the final batch and teardown. The run recorded a
	// trace_id, so any lost span must be surfaced.
	flushErr := r.provider.ForceFlush(ctx)
	shutdownErr := r.provider.Shutdown(ctx)
	dropErr := r.spanDelivery.DropError()
	if err := errors.Join(r.exportErrors.Err(), dropErr, flushErr, shutdownErr); err != nil {
		return fmt.Errorf("flush traces: %w", err)
	}
	return nil
}

// startToolSpan opens an execute_tool child span at the given time.
func (r *Run) startToolSpan(tool string, at time.Time, attrs ...attribute.KeyValue) trace.Span {
	all := append([]attribute.KeyValue{
		attrOperationName.String("execute_tool"),
		attrToolName.String(tool),
	}, attrs...)
	_, span := r.tracer.Start(r.rootCtx, "execute_tool "+tool,
		trace.WithTimestamp(at),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(all...),
	)
	return span
}

// addTextEvent records surfaced assistant message text as a span event on the
// root span. Provider-private reasoning uses addReasoningEvent and is never
// attached to telemetry, even when output export is enabled.
func (r *Run) addTextEvent(name, text string, at time.Time) {
	attrs := []attribute.KeyValue{attrEventChars.Int(utf8.RuneCountInString(text))}
	if r.includeOutput {
		attrs = append(attrs, attribute.String("text", capString(text, maxResultChars)))
	}
	r.root.AddEvent(name, trace.WithTimestamp(at), trace.WithAttributes(attrs...))
}

func (r *Run) addReasoningEvent(text string, at time.Time) {
	r.root.AddEvent("acta.reasoning", trace.WithTimestamp(at), trace.WithAttributes(
		attrEventChars.Int(utf8.RuneCountInString(text)),
	))
}
