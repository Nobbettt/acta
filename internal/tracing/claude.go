package tracing

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/nobbettt/acta/internal/digest"
)

// claudeMapper maps claude stream-json lines to spans: tool_use starts an
// execute_tool span, the matching tool_result ends it, text/thinking become
// root span events, and the final result item carries usage onto the root.
type claudeMapper struct {
	spans map[string]trace.Span // tool_use_id → open span
}

func (m *claudeMapper) onLine(r *Run, line []byte, at time.Time) {
	var item digest.ClaudeItem
	if json.Unmarshal(line, &item) != nil {
		return
	}
	switch item.Type {
	case "system":
		if item.Subtype != "init" {
			return
		}
		if item.Model != "" {
			r.root.SetAttributes(attrResponseModel.String(item.Model))
		}
		if item.SessionID != "" {
			r.root.SetAttributes(attrConversationID.String(item.SessionID))
		}
	case "assistant":
		if item.Message == nil {
			return
		}
		for _, content := range item.Message.Content {
			m.onAssistantContent(r, &content, at)
		}
	case "user":
		if item.Message == nil {
			return
		}
		for _, content := range item.Message.Content {
			if content.Type == "tool_result" {
				m.onToolResult(r, &content, item.ToolUseResult, at)
			}
		}
	case "result":
		if item.Usage != nil {
			r.root.SetAttributes(
				attrUsageInputTokens.Int64(item.Usage.InputTokens),
				attrUsageOutputTokens.Int64(item.Usage.OutputTokens),
				attrUsageCacheRead.Int64(item.Usage.CacheReadInputTokens),
				attrUsageCacheCreation.Int64(item.Usage.CacheCreationInputTokens),
			)
		}
		r.root.SetAttributes(
			attrRunNumTurns.Int(item.NumTurns),
			attrRunCostUSD.Float64(item.TotalCostUSD),
		)
	}
}

func (m *claudeMapper) onAssistantContent(r *Run, content *digest.ClaudeContent, at time.Time) {
	switch content.Type {
	case "tool_use":
		attrs := []attribute.KeyValue{}
		if content.ID != "" {
			attrs = append(attrs, attrToolCallID.String(content.ID))
		}
		// Arguments and file paths can carry secrets (a command with an inline
		// token, an Edit's new_string) or local absolute paths, so export them
		// only under --otlp-include-output — same gate as results/message text.
		if r.includeOutput {
			if len(content.Input) > 0 {
				attrs = append(attrs, attrToolCallArguments.String(capString(string(content.Input), maxArgumentChars)))
			}
			var input struct {
				FilePath     string `json:"file_path"`
				NotebookPath string `json:"notebook_path"`
			}
			_ = json.Unmarshal(content.Input, &input)
			filePath := input.FilePath
			if filePath == "" {
				filePath = input.NotebookPath // NotebookEdit reports notebook_path
			}
			if filePath != "" {
				attrs = append(attrs, attrFilePath.String(filePath))
			}
		}
		span := r.startToolSpan(content.Name, at, attrs...)
		if content.ID != "" {
			m.spans[content.ID] = span
		} else {
			span.End(trace.WithTimestamp(at))
		}
	case "text":
		if strings.TrimSpace(content.Text) != "" {
			r.addTextEvent("acta.message", content.Text, at)
		}
	case "thinking":
		if strings.TrimSpace(content.Thinking) != "" {
			r.addTextEvent("acta.reasoning", content.Thinking, at)
		}
	}
}

func (m *claudeMapper) onToolResult(r *Run, content *digest.ClaudeContent, toolUseResult json.RawMessage, at time.Time) {
	span, ok := m.spans[content.ToolUseID]
	if !ok {
		return
	}
	delete(m.spans, content.ToolUseID)
	if code, ok := digest.ExitCodeFromToolUseResult(toolUseResult); ok {
		span.SetAttributes(attrCommandExitCode.Int(code))
	}
	if content.IsError {
		span.SetStatus(codes.Error, "tool result reported error")
	}
	if r.includeOutput {
		if text := digest.ToolResultText(content.Content); text != "" {
			span.SetAttributes(attrToolCallResult.String(capString(text, maxResultChars)))
		}
	}
	span.End(trace.WithTimestamp(at))
}

func (m *claudeMapper) openSpans() []trace.Span {
	return slices.Collect(maps.Values(m.spans))
}
