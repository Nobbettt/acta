package tracing

import (
	"maps"
	"slices"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/nobbettt/acta/internal/digest"
	"github.com/nobbettt/acta/internal/reasoning"
)

// codexMapper maps codex exec --json events to spans: item.started opens an
// execute_tool span, item.completed ends it (items that only emit completed —
// file_change — become zero-duration spans), agent_message becomes a root
// span event, turn.completed carries usage onto the root.
type codexMapper struct {
	spans map[string]trace.Span // item id → open span
}

func (m *codexMapper) onLine(r *Run, line []byte, at time.Time) {
	var event digest.CodexEvent
	if reasoning.UnmarshalProviderLine(line, &event) != nil {
		return
	}
	switch event.Type {
	case "thread.started":
		if event.ThreadID != "" {
			r.root.SetAttributes(attrConversationID.String(event.ThreadID))
		}
	case "turn.completed":
		if event.Usage != nil {
			r.root.SetAttributes(
				attrUsageInputTokens.Int64(event.Usage.InputTokens),
				attrUsageOutputTokens.Int64(event.Usage.OutputTokens),
				attrUsageCacheRead.Int64(event.Usage.CachedInputTokens),
			)
		}
	case "item.started":
		if item := event.Item; item != nil && spanWorthy(item.Type) {
			span := r.startToolSpan(codexToolName(item), at, codexItemAttrs(item, r.includeOutput)...)
			if item.ID != "" {
				m.spans[item.ID] = span
			} else {
				span.End(trace.WithTimestamp(at)) // no id to match a completion; don't orphan
			}
		}
	case "item.completed":
		item := event.Item
		if item == nil {
			return
		}
		switch {
		case spanWorthy(item.Type):
			span, ok := m.spans[item.ID]
			if !ok {
				span = r.startToolSpan(codexToolName(item), at, codexItemAttrs(item, r.includeOutput)...)
			}
			delete(m.spans, item.ID)
			if item.ExitCode != nil {
				span.SetAttributes(attrCommandExitCode.Int(*item.ExitCode))
			}
			if item.Failed() {
				span.SetStatus(codes.Error, "item "+item.Status)
			}
			if r.includeOutput && item.AggregatedOutput != "" {
				span.SetAttributes(attrToolCallResult.String(capString(item.AggregatedOutput, maxResultChars)))
			}
			if r.includeOutput && len(item.Result) > 0 {
				span.SetAttributes(attrToolCallResult.String(capString(string(item.Result), maxResultChars)))
			}
			span.End(trace.WithTimestamp(at))
		case item.Type == "file_change":
			var attrs []attribute.KeyValue
			if r.includeOutput { // paths are local/absolute; gate like other content
				var paths []string
				for _, change := range item.Changes {
					paths = append(paths, change.Path)
				}
				attrs = append(attrs, attribute.StringSlice(string(attrFilePath), paths))
			}
			span := r.startToolSpan("file_change", at, attrs...)
			span.End(trace.WithTimestamp(at))
		case item.Type == "agent_message":
			if strings.TrimSpace(item.Text) != "" {
				r.addTextEvent("acta.message", item.Text, at)
			}
		case item.Type == "reasoning":
			if strings.TrimSpace(item.Text) != "" {
				r.addReasoningEvent(item.Text, at)
			}
		}
	}
}

// spanWorthy reports whether a codex item type gets its own execute_tool
// span: command executions and tool/MCP calls do; messages and todo lists
// become events or are skipped.
func spanWorthy(itemType string) bool {
	if itemType == "command_execution" || itemType == "web_search" {
		return true
	}
	if itemType == "todo_list" {
		return false
	}
	return strings.Contains(itemType, "tool") || strings.Contains(itemType, "mcp")
}

func codexItemAttrs(item *digest.CodexItem, includeOutput bool) []attribute.KeyValue {
	attrs := []attribute.KeyValue{attrToolCallID.String(item.ID)}
	if includeOutput && item.Command != "" { // command text can carry secrets
		attrs = append(attrs, attrToolCallArguments.String(capString(item.Command, maxArgumentChars)))
	}
	if includeOutput && len(item.Arguments) > 0 {
		attrs = append(attrs, attrToolCallArguments.String(capString(string(item.Arguments), maxArgumentChars)))
	}
	if includeOutput && item.Query != "" {
		attrs = append(attrs, attrToolCallArguments.String(capString(item.Query, maxArgumentChars)))
	}
	return attrs
}

func codexToolName(item *digest.CodexItem) string {
	if item.Tool == "" {
		return item.Type
	}
	if item.Server == "" {
		return item.Tool
	}
	return item.Server + "/" + item.Tool
}

func (m *codexMapper) openSpans() []trace.Span {
	return slices.Collect(maps.Values(m.spans))
}
