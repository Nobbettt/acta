// Package tracing exports agent runs as OpenTelemetry traces over OTLP/HTTP:
// one trace per run, a root invoke_agent span, one execute_tool child span
// per tool call or command, and span events for assistant messages. Spans are
// stamped with line arrival times observed live during the run — the raw
// agent streams carry no timestamps, so live emission is the only way to get
// a real timeline.
package tracing

import (
	"context"
	"fmt"
	"os"
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
	return endpointFlag != "" ||
		os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" ||
		os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != ""
}

// Run is one live-traced agent run. All methods are nil-receiver safe so the
// runner can call them unconditionally.
type Run struct {
	provider      *sdktrace.TracerProvider
	tracer        trace.Tracer
	rootCtx       context.Context
	root          trace.Span
	mapper        mapper
	includeOutput bool
}

// mapper turns one raw agent output line into span operations.
type mapper interface {
	onLine(r *Run, line []byte, at time.Time)
	// openSpans returns spans still open at run end (killed mid-flight).
	openSpans() []trace.Span
}

func Setup(ctx context.Context, cfg Config) (*Run, error) {
	var expOpts []otlptracehttp.Option
	if cfg.Endpoint != "" {
		expOpts = append(expOpts, otlptracehttp.WithEndpointURL(cfg.Endpoint))
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
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	return newRun(ctx, provider, cfg)
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
	} else {
		startCtx = propagation.TraceContext{}.Extract(ctx, propagation.MapCarrier{
			"traceparent": os.Getenv("TRACEPARENT"),
			"tracestate":  os.Getenv("TRACESTATE"),
		})
	}
	r.rootCtx, r.root = r.tracer.Start(startCtx, "invoke_agent "+cfg.Agent, startOpts...)
	return r, nil
}

// TraceID returns the run's trace id for run.json correlation.
func (r *Run) TraceID() string {
	if r == nil {
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
	// ForceFlush returns the exporter's error; Shutdown alone swallows export
	// failures into otel's global error handler. The run recorded a trace_id, so
	// a dropped export leaves it pointing at spans that never reached the
	// backend — surface it.
	flushErr := r.provider.ForceFlush(ctx)
	if err := r.provider.Shutdown(ctx); err != nil && flushErr == nil {
		flushErr = err
	}
	if flushErr != nil {
		return fmt.Errorf("flush traces: %w", flushErr)
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

// addTextEvent records assistant message/reasoning text as a span event on
// the root span. Text content is exported only under --otlp-include-output;
// the event itself (with size) is always recorded.
func (r *Run) addTextEvent(name, text string, at time.Time) {
	attrs := []attribute.KeyValue{attrEventChars.Int(utf8.RuneCountInString(text))}
	if r.includeOutput {
		attrs = append(attrs, attribute.String("text", capString(text, maxResultChars)))
	}
	r.root.AddEvent(name, trace.WithTimestamp(at), trace.WithAttributes(attrs...))
}
