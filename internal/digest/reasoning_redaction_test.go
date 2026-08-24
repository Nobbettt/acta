package digest

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactReasoningPreservesUnsupportedCodexRethinkingDetails(t *testing.T) {
	raw := strings.Join([]string{
		`{"type":"thread.started","thread_id":"thread-1"}`,
		`{"type":"turn.started"}`,
		`{"type":"item.completed","item":{"id":"future-1","type":"rethinking","diagnostic":"keep this payload"}}`,
		`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`,
	}, "\n") + "\n"
	d, err := parseCodex(strings.NewReader(raw), newWorkspace(""))
	if err == nil || !strings.Contains(err.Error(), "unsupported event") {
		t.Fatalf("parse error = %v, want unsupported-event failure", err)
	}

	event := findTimelineProviderEvent(d.Timeline, "rethinking")
	if event == nil {
		t.Fatalf("rethinking event missing from timeline: %+v", d.Timeline)
	}
	wantDetails := append(json.RawMessage(nil), event.Details...)

	RedactReasoning(d)

	if event.Redacted {
		t.Fatalf("unsupported rethinking event marked redacted: %+v", event)
	}
	if !bytes.Equal(event.Details, wantDetails) {
		t.Fatalf("unsupported rethinking details changed:\n got %s\nwant %s", event.Details, wantDetails)
	}
}

func TestRedactReasoningRedactsExactProviderBlocks(t *testing.T) {
	tests := map[string]Event{
		"codex reasoning": {
			Kind: KindReasoning, ProviderEvent: "reasoning", Text: "private",
			localReasoningText: "private", Details: json.RawMessage(`{"type":"reasoning","text":"private"}`),
		},
		"codex reasoning update": {
			Kind: KindLifecycle, ProviderEvent: "item.updated.reasoning",
			Details: json.RawMessage(`{"type":"reasoning","text":"private"}`),
		},
		"claude thinking": {
			Kind: KindReasoning, ProviderEvent: "assistant.thinking", Text: "private",
			localReasoningText: "private", Details: json.RawMessage(`{"type":"thinking","thinking":"private"}`),
		},
		"claude redacted thinking": {
			Kind: KindUnsupported, ProviderEvent: "assistant.redacted_thinking",
			Details: json.RawMessage(`{"type":"redacted_thinking","data":"private"}`),
		},
	}

	for name, event := range tests {
		t.Run(name, func(t *testing.T) {
			d := &Digest{Timeline: []Event{event}}
			RedactReasoning(d)
			got := d.Timeline[0]
			if !got.Redacted || got.Text != "" || got.LocalReasoningText() != "" || got.Details != nil {
				t.Fatalf("reasoning event was not fully redacted: %+v / %q", got, got.LocalReasoningText())
			}
		})
	}
}

func findTimelineProviderEvent(timeline []Event, providerEvent string) *Event {
	for index := range timeline {
		if timeline[index].ProviderEvent == providerEvent {
			return &timeline[index]
		}
	}
	return nil
}
