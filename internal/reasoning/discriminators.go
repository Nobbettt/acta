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

// IsRedactedBlock reports whether a reasoning block was previously redacted.
// The explicit flag is provenance; marker text alone may be genuine content.
func IsRedactedBlock(redacted bool) bool {
	return redacted
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
// RedactProviderBlocks when position is required.
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

// RedactProviderBlocks recursively finds reasoning blocks at exact provider
// positions inside a retained raw payload and masks their private fields. It
// deliberately does not classify arbitrary objects with a reasoning-shaped
// type as provider output.
func RedactProviderBlocks(value any) bool {
	changed, _ := redactProviderBlocks(context.Background(), value)
	return changed
}

// RedactProviderBlocksContext is RedactProviderBlocks with cancellation checks
// while traversing potentially large upload artifacts.
func RedactProviderBlocksContext(ctx context.Context, value any) (bool, error) {
	return redactProviderBlocks(ctx, value)
}

func redactProviderBlocks(ctx context.Context, value any) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	switch typed := value.(type) {
	case []any:
		changed := false
		for _, item := range typed {
			itemChanged, err := redactProviderBlocks(ctx, item)
			if err != nil {
				return false, err
			}
			changed = itemChanged || changed
		}
		return changed, nil
	case map[string]any:
		changed := redactCodexBlock(typed)
		changed = redactClaudeBlocks(typed) || changed
		for key, item := range typed {
			if IsUserDataPayloadKey(typed, key) {
				continue
			}
			itemChanged, err := redactProviderBlocks(ctx, item)
			if err != nil {
				return false, err
			}
			changed = itemChanged || changed
		}
		return changed, nil
	default:
		return false, nil
	}
}

func redactCodexBlock(event map[string]any) bool {
	eventType, _ := event["type"].(string)
	item, ok := event["item"].(map[string]any)
	if !ok {
		return false
	}
	itemType, _ := item["type"].(string)
	if !IsCodexBlock(eventType, itemType) {
		return false
	}
	return redactBlock(item, "text")
}

func redactClaudeBlocks(event map[string]any) bool {
	eventType, _ := event["type"].(string)
	message, ok := event["message"].(map[string]any)
	if !ok {
		return false
	}
	content, ok := message["content"].([]any)
	if !ok {
		return false
	}
	changed := false
	for _, value := range content {
		block, ok := value.(map[string]any)
		if !ok {
			continue
		}
		blockType, _ := block["type"].(string)
		if IsClaudeBlock(eventType, blockType) {
			textField := "thinking"
			if blockType == claudeRedactedThinking {
				textField = "data"
			}
			changed = redactBlock(block, textField) || changed
		}
	}
	return changed
}

func redactBlock(block map[string]any, textField string) bool {
	changed := false
	text, _ := block[textField].(string)
	redacted, _ := block["redacted"].(bool)
	if !IsRedactedBlock(redacted) && text != "" {
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
	case float32:
		value := float64(typed)
		return !math.IsInf(value, 0) && !math.IsNaN(value) && float32(math.Trunc(value)) == typed
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	default:
		return false
	}
}

// ContainsRedactedProviderBlock reports whether an exact provider position
// contains a block carrying redaction provenance. It lets owning normalized
// wrappers preserve that provenance after an earlier exact pass has already
// made a later redaction traversal idempotent.
func ContainsRedactedProviderBlock(value any) bool {
	contains, _ := containsRedactedProviderBlock(context.Background(), value)
	return contains
}

// ContainsRedactedProviderBlockContext is ContainsRedactedProviderBlock with
// cancellation checks while traversing potentially large upload artifacts.
func ContainsRedactedProviderBlockContext(ctx context.Context, value any) (bool, error) {
	return containsRedactedProviderBlock(ctx, value)
}

func containsRedactedProviderBlock(ctx context.Context, value any) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			contains, err := containsRedactedProviderBlock(ctx, item)
			if err != nil || contains {
				return contains, err
			}
		}
	case map[string]any:
		if redactedCodexBlock(typed) || redactedClaudeBlock(typed) {
			return true, nil
		}
		for key, item := range typed {
			if IsUserDataPayloadKey(typed, key) {
				continue
			}
			contains, err := containsRedactedProviderBlock(ctx, item)
			if err != nil || contains {
				return contains, err
			}
		}
	}
	return false, nil
}

// IsUserDataPayloadKey reports whether key names a container whose contents
// belong to the user or a tool. Provider-shaped objects inside these values
// are content, not provider envelopes.
func IsUserDataPayloadKey(parent map[string]any, key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "input", "arguments", "result", "output", "structured_output", "tool_use_result":
		return true
	case "details":
		kind, _ := parent["kind"].(string)
		return strings.EqualFold(strings.TrimSpace(kind), "structured_output")
	case "content":
		kind, _ := parent["type"].(string)
		role, _ := parent["role"].(string)
		kind = strings.ToLower(strings.TrimSpace(kind))
		role = strings.ToLower(strings.TrimSpace(role))
		return kind == "tool_result" || kind == "user" || role == "user"
	default:
		return false
	}
}

func redactedCodexBlock(event map[string]any) bool {
	eventType, _ := event["type"].(string)
	item, ok := event["item"].(map[string]any)
	if !ok {
		return false
	}
	itemType, _ := item["type"].(string)
	redacted, _ := item["redacted"].(bool)
	return IsCodexBlock(eventType, itemType) && IsRedactedBlock(redacted)
}

func redactedClaudeBlock(event map[string]any) bool {
	eventType, _ := event["type"].(string)
	message, ok := event["message"].(map[string]any)
	if !ok {
		return false
	}
	content, ok := message["content"].([]any)
	if !ok {
		return false
	}
	for _, value := range content {
		block, ok := value.(map[string]any)
		if !ok {
			continue
		}
		blockType, _ := block["type"].(string)
		redacted, _ := block["redacted"].(bool)
		if IsClaudeBlock(eventType, blockType) && IsRedactedBlock(redacted) {
			return true
		}
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
	case float32:
		return float32(0), typed != 0
	case int:
		return 0, typed != 0
	case int8:
		return int8(0), typed != 0
	case int16:
		return int16(0), typed != 0
	case int32:
		return int32(0), typed != 0
	case int64:
		return int64(0), typed != 0
	case uint:
		return uint(0), typed != 0
	case uint8:
		return uint8(0), typed != 0
	case uint16:
		return uint16(0), typed != 0
	case uint32:
		return uint32(0), typed != 0
	case uint64:
		return uint64(0), typed != 0
	case bool:
		return false, typed
	default:
		return value, false
	}
}
