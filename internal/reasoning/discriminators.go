// Package reasoning identifies provider-private reasoning blocks by their
// exact discriminator and position in supported provider event shapes.
package reasoning

import (
	"context"
	"encoding/json"
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
)

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
		for _, item := range typed {
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
	return redactBlock(item)
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
			changed = redactBlock(block) || changed
		}
	}
	return changed
}

func redactBlock(block map[string]any) bool {
	changed := false
	for key, value := range block {
		switch key {
		case "type", "id", "status", "redacted":
			continue
		}
		masked, valueChanged := MaskValue(value)
		if valueChanged {
			block[key] = masked
			changed = true
		}
	}
	if redacted, _ := block["redacted"].(bool); !redacted {
		block["redacted"] = true
		changed = true
	}
	return changed
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
