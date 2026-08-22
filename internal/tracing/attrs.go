package tracing

import (
	"go.opentelemetry.io/otel/attribute"

	"github.com/nobbettt/acta/internal/digest"
)

// GenAI semantic-convention keys (Development stability — kept as plain
// constants instead of a pinned semconv package because they still churn;
// gen_ai.system → gen_ai.provider.name already happened upstream).
const (
	attrOperationName      = attribute.Key("gen_ai.operation.name")
	attrAgentName          = attribute.Key("gen_ai.agent.name")
	attrProviderName       = attribute.Key("gen_ai.provider.name")
	attrRequestModel       = attribute.Key("gen_ai.request.model")
	attrResponseModel      = attribute.Key("gen_ai.response.model")
	attrConversationID     = attribute.Key("gen_ai.conversation.id")
	attrUsageInputTokens   = attribute.Key("gen_ai.usage.input_tokens")
	attrUsageOutputTokens  = attribute.Key("gen_ai.usage.output_tokens")
	attrUsageCacheRead     = attribute.Key("gen_ai.usage.cache_read.input_tokens")
	attrUsageCacheCreation = attribute.Key("gen_ai.usage.cache_creation.input_tokens")
	attrToolName           = attribute.Key("gen_ai.tool.name")
	attrToolCallID         = attribute.Key("gen_ai.tool.call.id")
	attrToolCallArguments  = attribute.Key("gen_ai.tool.call.arguments")
	attrToolCallResult     = attribute.Key("gen_ai.tool.call.result")
)

// acta-specific keys for what the semconv does not cover.
const (
	attrRunID           = attribute.Key("acta.run.id")
	attrRunOK           = attribute.Key("acta.run.ok")
	attrRunExitCode     = attribute.Key("acta.run.exit_code")
	attrRunTimeout      = attribute.Key("acta.run.timeout")
	attrRunCostUSD      = attribute.Key("acta.run.cost_usd")
	attrRunNumTurns     = attribute.Key("acta.run.num_turns")
	attrPromptSource    = attribute.Key("acta.prompt.source")
	attrFilePath        = attribute.Key("acta.file.path")
	attrCommandExitCode = attribute.Key("acta.command.exit_code")
	attrEventChars      = attribute.Key("acta.event.chars")
)

// Attribute size caps. Content that can carry secrets or local paths —
// tool-call arguments, file paths, results, and surfaced message text is
// exported only under --otlp-include-output. Provider-private reasoning text
// is never exported; reasoning events carry structural counts only.
const (
	maxArgumentChars = 4_096
	maxResultChars   = 8_192
)

// capString truncates on a rune boundary (valid UTF-8): a half rune makes
// protobuf marshal reject the export, silently dropping the whole span batch.
func capString(s string, limit int) string {
	return digest.Truncate(s, limit)
}
