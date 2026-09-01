// Package reasoning identifies provider-private reasoning blocks by their
// exact discriminator and position in supported provider event shapes.
package reasoning

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"unicode/utf8"
)

const (
	actaReasoningKind       = "reasoning"
	codexItemStartedEvent   = "item.started"
	codexItemUpdatedEvent   = "item.updated"
	codexItemCompletedEvent = "item.completed"
	claudeAssistantEvent    = "assistant"
	claudeThinkingBlock     = "thinking"
	claudeRedactedThinking  = "redacted_thinking"

	// RedactedMarker replaces private string content while preserving its JSON
	// type. Other JSON values use their corresponding zero value.
	RedactedMarker = "[REDACTED]"

	// MaxTextBytes is the normalized event-text limit used when recording the
	// original size of reasoning text before it is masked in a raw stream.
	MaxTextBytes = 64 << 10
)

type traversalProvenance uint8

const (
	providerData traversalProvenance = iota
	actaNormalizedData
)

// TraversalContext records who wrote the value being inspected. Envelope
// exemptions are available only to Acta-normalized values; provider data is
// always traversed conservatively.
type TraversalContext struct {
	provenance   traversalProvenance
	envelopeType string
}

// ProviderTraversal returns the conservative context for raw or opaque
// provider data.
func ProviderTraversal() TraversalContext {
	return TraversalContext{provenance: providerData}
}

// NormalizedTraversal returns the context for an Acta-written value.
// envelopeType identifies the containing Acta envelope when the value itself
// is its payload, or "digest" for a digest root.
func NormalizedTraversal(envelopeType string) TraversalContext {
	return TraversalContext{provenance: actaNormalizedData, envelopeType: envelopeType}
}

// Enter returns the context for a child field and whether that field is an
// exempt surfaced-data value. This is the single envelope-exemption decision
// point shared by all reasoning-boundary traversals.
func (traversal TraversalContext) Enter(parent map[string]any, key string) (TraversalContext, bool) {
	if traversal.provenance != actaNormalizedData {
		return ProviderTraversal(), false
	}
	if normalizedEnvelopePayloadKey(parent, traversal.envelopeType, key) {
		return ProviderTraversal(), true
	}

	child := ProviderTraversal()
	if traversal.envelopeType == "digest" && key == "timeline" {
		child = NormalizedTraversal("")
	} else if key == "payload" {
		typ, _ := parent["type"].(string)
		if strings.TrimSpace(typ) != "" {
			child = NormalizedTraversal(typ)
		}
	}
	return child, false
}

// IsCodexBlock reports whether itemType is the exact reasoning discriminator
// at the item position of a supported Codex item event.
func IsCodexBlock(eventType, itemType string) bool {
	switch eventType {
	case codexItemStartedEvent, codexItemUpdatedEvent, codexItemCompletedEvent:
		return itemType == actaReasoningKind
	default:
		return false
	}
}

// IsClaudeBlock reports whether blockType is an exact reasoning discriminator
// at the message.content position of a Claude assistant event.
func IsClaudeBlock(eventType, blockType string) bool {
	if eventType != claudeAssistantEvent {
		return false
	}
	switch blockType {
	case claudeThinkingBlock, claudeRedactedThinking:
		return true
	default:
		return false
	}
}

// IsBlockDiscriminator reports whether value is one of the exact private
// reasoning block discriminators understood across supported providers. It
// does not establish provider position; use IsCodexBlock, IsClaudeBlock, or
// the provider traversal when position is required.
func IsBlockDiscriminator(value string) bool {
	switch value {
	case actaReasoningKind, claudeThinkingBlock, claudeRedactedThinking:
		return true
	default:
		return false
	}
}

// IsNormalizedEvent reports whether an Acta digest event is a normalized
// provider reasoning block. detailType must come from the event's Details.type
// field; pairing it with providerEvent preserves the original provider
// position instead of treating arbitrary lookalike strings as reasoning.
func IsNormalizedEvent(kind, providerEvent, detailType string) bool {
	if kind == actaReasoningKind {
		return true
	}
	if IsCodexBlock(codexItemUpdatedEvent, detailType) &&
		providerEvent == codexItemUpdatedEvent+"."+detailType {
		return true
	}
	return IsClaudeBlock(claudeAssistantEvent, detailType) &&
		providerEvent == claudeAssistantEvent+"."+detailType
}

// RedactValue applies both the exact provider-envelope pass and a defensive
// generic pass for future provider events. The generic pass masks
// reasoning-shaped fields while preserving their JSON types. verified is
// false when the value contains a shape that cannot be inspected safely.
func RedactValue(value any, traversal TraversalContext) (changed, verified bool) {
	changed, verified, _ = RedactValueContext(context.Background(), value, traversal)
	return changed, verified
}

// RedactValueContext is RedactValue with cancellation checks while traversing
// potentially large artifacts.
func RedactValueContext(ctx context.Context, value any, traversal TraversalContext) (changed, verified bool, err error) {
	changed, _, err = redactProviderBlocks(ctx, value, traversal)
	if err != nil {
		return false, false, err
	}
	genericChanged, verified, err := redactReasoningFieldsContext(ctx, value, traversal)
	return genericChanged || changed, verified, err
}

// RedactUnsupportedPayload understands the normalized unsupported-event
// wrapper used by digests and Acta events. Details remain inspectable when
// they consist entirely of JSON objects, arrays, and nulls; opaque scalar
// details are unverified because their contents cannot be classified.
func RedactUnsupportedPayload(value any) (redacted any, changed, verified bool) {
	redacted, changed, verified, _ = RedactUnsupportedPayloadContext(context.Background(), value)
	return redacted, changed, verified
}

// RedactUnsupportedPayloadContext is RedactUnsupportedPayload with
// cancellation checks.
func RedactUnsupportedPayloadContext(ctx context.Context, value any) (redacted any, changed, verified bool, err error) {
	payload, ok := value.(map[string]any)
	if !ok {
		return value, false, false, nil
	}
	kind, _ := payload["kind"].(string)
	if kind != "unsupported" {
		return value, false, false, nil
	}
	providerEvent, _ := payload["provider_event"].(string)
	var detailsType string
	detailsChanged := false
	detailsVerified := false
	if details, exists := payload["details"]; !exists {
		detailsVerified = true
	} else {
		switch typed := details.(type) {
		case nil:
			detailsVerified = true
		case []any:
			detailsChanged, detailsVerified, err = redactUnsupportedDetailsArrayContext(ctx, typed)
		case map[string]any:
			detailsType, _ = typed["type"].(string)
			detailsChanged, detailsVerified, err = RedactValueContext(ctx, typed, ProviderTraversal())
		default:
			return payload, false, false, nil
		}
		if err != nil {
			return payload, false, false, err
		}
	}
	if IsNormalizedEvent(kind, providerEvent, detailsType) {
		changed, verified, err := redactToStructuralReferencesContext(ctx, payload)
		return payload, changed, verified, err
	}
	providerChanged, containsRedacted, err := redactProviderBlocks(ctx, payload, ProviderTraversal())
	if err != nil {
		return payload, false, false, err
	}
	changed = detailsChanged || providerChanged
	if changed || containsRedacted {
		if redacted, _ := payload["redacted"].(bool); !redacted {
			payload["redacted"] = true
			changed = true
		}
	}
	return payload, changed, detailsVerified, nil
}

// RedactToStructuralReferences masks every non-structural value while
// preserving its JSON type. Object fields use the same allowlist and
// verification semantics as provider reasoning redaction.
func RedactToStructuralReferences(value any) (any, bool) {
	payload, ok := value.(map[string]any)
	if !ok {
		return MaskValue(value)
	}
	changed, _, _ := redactToStructuralReferencesContext(context.Background(), payload)
	return payload, changed
}

func redactUnsupportedDetailsArrayContext(ctx context.Context, details []any) (changed, verified bool, err error) {
	verified = true
	for _, detail := range details {
		if err := ctx.Err(); err != nil {
			return false, false, err
		}
		switch typed := detail.(type) {
		case nil:
		case map[string]any:
			itemChanged, itemVerified, err := RedactValueContext(ctx, typed, ProviderTraversal())
			if err != nil {
				return false, false, err
			}
			changed = itemChanged || changed
			verified = itemVerified && verified
		case []any:
			itemChanged, itemVerified, err := redactUnsupportedDetailsArrayContext(ctx, typed)
			if err != nil {
				return false, false, err
			}
			changed = itemChanged || changed
			verified = itemVerified && verified
		default:
			verified = false
		}
	}
	return changed, verified, nil
}

func redactReasoningFieldsContext(ctx context.Context, value any, traversal TraversalContext) (changed, verified bool, err error) {
	if err := ctx.Err(); err != nil {
		return false, false, err
	}
	switch typed := value.(type) {
	case nil, string, bool, json.Number, float64, int:
		return false, true, nil
	case []any:
		verified = true
		for _, item := range typed {
			itemChanged, itemVerified, err := redactReasoningFieldsContext(ctx, item, traversal)
			if err != nil {
				return false, false, err
			}
			changed = itemChanged || changed
			verified = itemVerified && verified
		}
		return changed, verified, nil
	case map[string]any:
		typeDiscriminator, kindDiscriminator := objectDiscriminators(typed)
		if IsBlockDiscriminator(typeDiscriminator) || IsBlockDiscriminator(kindDiscriminator) {
			return redactToStructuralReferencesContext(ctx, typed)
		}
		if traversal.provenance == actaNormalizedData && (typeDiscriminator == "unsupported" || kindDiscriminator == "unsupported") {
			_, changed, verified, err := RedactUnsupportedPayloadContext(ctx, typed)
			return changed, verified, err
		}
		verified = true
		for key, item := range typed {
			if err := ctx.Err(); err != nil {
				return false, false, err
			}
			childTraversal, exempt := traversal.Enter(typed, key)
			if exempt {
				continue
			}
			if isReasoningContentKey(key, item) {
				masked, itemChanged := MaskValue(item)
				if itemChanged {
					typed[key] = masked
					changed = true
				}
				continue
			}
			itemChanged, itemVerified, err := redactReasoningFieldsContext(ctx, item, childTraversal)
			if err != nil {
				return false, false, err
			}
			changed = itemChanged || changed
			verified = itemVerified && verified
		}
		return changed, verified, nil
	default:
		return false, false, nil
	}
}

func isReasoningContentKey(key string, value any) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "reasoning", "thinking", "reasoning_text", "thinking_text", "reasoning_content", "thinking_content", "chain_of_thought":
		// Numeric reasoning-token counters are non-content evidence and must
		// survive redaction. Suspicious text or structured content is masked.
		switch value.(type) {
		case string, []any, map[string]any:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func redactToStructuralReferencesContext(ctx context.Context, payload map[string]any) (changed, verified bool, err error) {
	verified = true
	for key, item := range payload {
		if err := ctx.Err(); err != nil {
			return false, false, err
		}
		if structuralReasoningValue(key, item) {
			continue
		}
		masked, itemChanged := MaskValue(item)
		if itemChanged {
			payload[key] = masked
			changed = true
		}
		verified = maskableValue(item) && verified
	}
	if redacted, _ := payload["redacted"].(bool); !redacted {
		payload["redacted"] = true
		changed = true
	}
	return changed, verified, nil
}

func structuralReasoningValue(key string, value any) bool {
	switch key {
	case "type", "kind", "provider_event", "id", "parent_id", "thread_id", "session_id", "task_id",
		"phase", "status", "visibility", "started_at", "observed_at", "completed_at", "tool", "server":
		_, ok := value.(string)
		return ok
	case "exit_code", "input_chars", "result_chars", "output_chars", "text_chars":
		return structuralInteger(value)
	case "is_error", "input_truncated", "result_truncated", "output_truncated", "text_truncated", "redacted":
		_, ok := value.(bool)
		return ok
	case "raw_event_lines":
		lines, ok := value.([]any)
		if !ok {
			return false
		}
		for _, line := range lines {
			if !structuralInteger(line) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func maskableValue(value any) bool {
	switch value.(type) {
	case nil, string, []any, map[string]any, json.Number, float64, int, bool:
		return true
	default:
		return false
	}
}

func redactProviderBlocks(ctx context.Context, value any, traversal TraversalContext) (changed, containsPreviouslyRedacted bool, err error) {
	if err := ctx.Err(); err != nil {
		return false, false, err
	}
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			itemChanged, itemContained, err := redactProviderBlocks(ctx, item, traversal)
			if err != nil {
				return false, false, err
			}
			changed = itemChanged || changed
			containsPreviouslyRedacted = itemContained || containsPreviouslyRedacted
		}
		return changed, containsPreviouslyRedacted, nil
	case map[string]any:
		changed, containsPreviouslyRedacted = redactCodexBlock(typed)
		claudeChanged, claudeContained := redactClaudeBlocks(typed)
		changed = claudeChanged || changed
		containsPreviouslyRedacted = claudeContained || containsPreviouslyRedacted
		for key, item := range typed {
			childTraversal, exempt := traversal.Enter(typed, key)
			if exempt {
				continue
			}
			itemChanged, itemContained, err := redactProviderBlocks(ctx, item, childTraversal)
			if err != nil {
				return false, false, err
			}
			changed = itemChanged || changed
			containsPreviouslyRedacted = itemContained || containsPreviouslyRedacted
		}
		return changed, containsPreviouslyRedacted, nil
	default:
		return false, false, nil
	}
}

func redactCodexBlock(event map[string]any) (changed, containsPreviouslyRedacted bool) {
	eventType, _ := event["type"].(string)
	item, ok := event["item"].(map[string]any)
	if !ok {
		return false, false
	}
	itemType, _ := item["type"].(string)
	if !IsCodexBlock(eventType, itemType) {
		return false, false
	}
	redacted, _ := item["redacted"].(bool)
	return redactBlock(item, "text"), redacted
}

func redactClaudeBlocks(event map[string]any) (changed, containsPreviouslyRedacted bool) {
	eventType, _ := event["type"].(string)
	message, ok := event["message"].(map[string]any)
	if !ok {
		return false, false
	}
	content, ok := message["content"].([]any)
	if !ok {
		return false, false
	}
	for _, value := range content {
		block, ok := value.(map[string]any)
		if !ok {
			continue
		}
		blockType, _ := block["type"].(string)
		if IsClaudeBlock(eventType, blockType) {
			redacted, _ := block["redacted"].(bool)
			containsPreviouslyRedacted = redacted || containsPreviouslyRedacted
			textField := "thinking"
			if blockType == claudeRedactedThinking {
				textField = "data"
			}
			changed = redactBlock(block, textField) || changed
		}
	}
	return changed, containsPreviouslyRedacted
}

func redactBlock(block map[string]any, textField string) bool {
	changed := false
	text, _ := block[textField].(string)
	redacted, _ := block["redacted"].(bool)
	if !redacted && text != "" {
		textChars := utf8.RuneCountInString(text)
		textTruncated := len(text) > MaxTextBytes
		if block["text_chars"] != textChars {
			block["text_chars"] = textChars
			changed = true
		}
		if block["text_truncated"] != textTruncated {
			block["text_truncated"] = textTruncated
			changed = true
		}
	}
	for key, value := range block {
		if structuralBlockValue(key, value) {
			continue
		}
		masked, valueChanged := MaskValue(value)
		if valueChanged {
			block[key] = masked
			changed = true
		}
	}
	if !redacted {
		block["redacted"] = true
		changed = true
	}
	return changed
}

func structuralBlockValue(key string, value any) bool {
	switch key {
	case "type", "id", "status":
		_, ok := value.(string)
		return ok
	case "redacted", "text_truncated":
		_, ok := value.(bool)
		return ok
	case "text_chars":
		return structuralInteger(value)
	default:
		return false
	}
}

func structuralInteger(value any) bool {
	switch typed := value.(type) {
	case json.Number:
		_, err := typed.Int64()
		return err == nil
	case float64:
		return !math.IsInf(typed, 0) && !math.IsNaN(typed) && math.Trunc(typed) == typed
	case int:
		return true
	default:
		return false
	}
}

// normalizedEnvelopePayloadKey reports whether a field is surfaced user or
// tool data in an Acta-normalized envelope. Callers must first establish Acta
// provenance; object shape alone never reaches this registry.
func normalizedEnvelopePayloadKey(parent map[string]any, envelopeType, key string) bool {
	typeDiscriminator, kindDiscriminator := objectDiscriminators(parent)
	role, _ := parent["role"].(string)
	typeDiscriminator = strings.ToLower(strings.TrimSpace(typeDiscriminator))
	kindDiscriminator = strings.ToLower(strings.TrimSpace(kindDiscriminator))
	role = strings.ToLower(strings.TrimSpace(role))
	payloadKey := strings.ToLower(strings.TrimSpace(key))
	envelopeType = strings.ToLower(strings.TrimSpace(envelopeType))

	if key != payloadKey {
		return false
	}
	value, exists := parent[key]
	if !exists || !maskableValue(value) {
		return false
	}

	switch envelopeType {
	case "digest", "run.completed", "run.failed":
		return key == "structured_output"
	}

	if normalizedDataKind(kindDiscriminator) {
		kind, ok := normalizedEnvelopeKind(parent)
		if !ok {
			return false
		}
		if expectedKind, hasExpectedKind := normalizedEnvelopeTypeKind(envelopeType); hasExpectedKind && expectedKind != kind {
			return false
		}
		return normalizedKindPayloadKey(value, kind, key)
	}

	switch payloadKey {
	case "input":
		return typeDiscriminator == "tool_use"
	case "arguments":
		return typeDiscriminator == "mcp_tool_call" || typeDiscriminator == "collab_tool_call"
	case "result":
		return typeDiscriminator == "mcp_tool_call" || typeDiscriminator == "collab_tool_call"
	case "output":
		return typeDiscriminator == "tool_result"
	case "structured_output":
		return typeDiscriminator == "result"
	case "tool_use_result":
		return typeDiscriminator == "user"
	case "content":
		return typeDiscriminator == "tool_result" || typeDiscriminator == "user" || role == "user"
	default:
		return false
	}
}

func objectDiscriminators(parent map[string]any) (string, string) {
	typeDiscriminator, _ := parent["type"].(string)
	kindDiscriminator, _ := parent["kind"].(string)
	return typeDiscriminator, kindDiscriminator
}

func normalizedDataKind(kind string) bool {
	switch kind {
	case "tool_call", "tool_result", "command", "file_edit", "todo", "web_search", "task", "permission", "structured_output":
		return true
	default:
		return false
	}
}

// normalizedEnvelopeKind positively identifies an Acta-normalized payload.
// A second discriminator must agree with kind; foreign or conflicting types
// leave the object on the conservative provider-data traversal path.
func normalizedEnvelopeKind(parent map[string]any) (string, bool) {
	_, kind := objectDiscriminators(parent)
	kind = strings.ToLower(strings.TrimSpace(kind))
	if !normalizedDataKind(kind) {
		return "", false
	}
	typeValue, hasType := parent["type"]
	if !hasType {
		return kind, true
	}
	typeDiscriminator, ok := typeValue.(string)
	if !ok {
		return "", false
	}
	typeKind, ok := normalizedEnvelopeTypeKind(strings.ToLower(strings.TrimSpace(typeDiscriminator)))
	return kind, ok && typeKind == kind
}

func normalizedEnvelopeTypeKind(discriminator string) (string, bool) {
	switch discriminator {
	case "tool_call", "tool.call.completed", "tool.call.incomplete":
		return "tool_call", true
	case "tool_result", "tool.result.orphaned":
		return "tool_result", true
	case "command", "shell.command.completed", "shell.command.incomplete":
		return "command", true
	case "file_edit", "file.written", "file.write.incomplete":
		return "file_edit", true
	case "todo", "agent.todo", "agent.todo.updated":
		return "todo", true
	case "web_search", "web.search.completed", "web.search.incomplete":
		return "web_search", true
	case "task", "agent.task.started", "agent.task.progress", "agent.task.completed", "agent.task.incomplete":
		return "task", true
	case "permission", "agent.permission.denied":
		return "permission", true
	case "structured_output", "agent.output.structured":
		return "structured_output", true
	default:
		return "", false
	}
}

func normalizedKindPayloadKey(value any, kind, key string) bool {
	switch key {
	case "input":
		switch kind {
		case "tool_call", "command", "file_edit", "todo", "web_search", "task", "permission":
			return true
		}
	case "result":
		switch kind {
		case "tool_call", "tool_result", "command", "file_edit", "todo", "web_search", "task":
			return true
		}
	case "output":
		if _, ok := value.(string); !ok {
			return false
		}
		switch kind {
		case "tool_call", "tool_result", "command", "file_edit", "todo", "web_search", "task":
			return true
		}
	case "details":
		return kind == "structured_output"
	}
	return false
}

// MaskValue returns the type-preserving zero value used at reasoning privacy
// boundaries. Strings use an explicit marker so the redaction remains visible.
func MaskValue(value any) (any, bool) {
	switch typed := value.(type) {
	case string:
		return RedactedMarker, typed != RedactedMarker
	case []any:
		if len(typed) == 0 {
			return typed, false
		}
		return []any{}, true
	case map[string]any:
		if len(typed) == 0 {
			return typed, false
		}
		return map[string]any{}, true
	case json.Number:
		return json.Number("0"), typed != json.Number("0")
	case float64:
		return float64(0), typed != 0
	case int:
		return 0, typed != 0
	case bool:
		return false, typed
	default:
		return value, false
	}
}
