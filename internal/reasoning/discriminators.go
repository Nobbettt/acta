// Package reasoning identifies provider-private reasoning blocks by their
// exact discriminator and position in supported provider event shapes.
package reasoning

const (
	actaReasoningKind       = "reasoning"
	codexItemStartedEvent   = "item.started"
	codexItemUpdatedEvent   = "item.updated"
	codexItemCompletedEvent = "item.completed"
	claudeAssistantEvent    = "assistant"
	claudeThinkingBlock     = "thinking"
	claudeRedactedThinking  = "redacted_thinking"
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
