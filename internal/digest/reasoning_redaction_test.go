package digest

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/nobbettt/acta/internal/reasoning"
)

func TestUnflaggedReasoningMarkerIsNormalizedAsContentThenRedacted(t *testing.T) {
	tests := []struct {
		name  string
		parse func() (*Digest, error)
	}{
		{
			name: "codex",
			parse: func() (*Digest, error) {
				raw := strings.Join([]string{
					`{"type":"thread.started","thread_id":"thread-1"}`,
					`{"type":"turn.started"}`,
					`{"type":"item.completed","item":{"id":"reason-1","type":"reasoning","text":"[REDACTED]"}}`,
					`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`,
				}, "\n") + "\n"
				return parseCodex(strings.NewReader(raw), newWorkspace(""))
			},
		},
		{
			name: "claude",
			parse: func() (*Digest, error) {
				raw := strings.Join([]string{
					`{"type":"system","subtype":"init","session_id":"session-1"}`,
					`{"type":"assistant","session_id":"session-1","message":{"id":"message-1","content":[{"type":"thinking","thinking":"[REDACTED]"}]}}`,
					`{"type":"result","subtype":"success","session_id":"session-1","is_error":false}`,
				}, "\n") + "\n"
				return parseClaude(strings.NewReader(raw), newWorkspace(""))
			},
		},
	}
	wantChars := utf8.RuneCountInString(reasoning.RedactedMarker)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d, err := test.parse()
			if err != nil {
				t.Fatal(err)
			}
			event := findTimelineKind(d.Timeline, KindReasoning)
			if event == nil {
				t.Fatalf("reasoning event missing: %+v", d.Timeline)
			}
			if event.Redacted || event.LocalReasoningText() != reasoning.RedactedMarker ||
				event.TextChars != wantChars || event.TextTruncated {
				t.Fatalf("unflagged marker was not normalized as content: %+v / %q", event, event.LocalReasoningText())
			}

			RedactReasoning(d)
			if !event.Redacted || event.LocalReasoningText() != "" ||
				event.TextChars != wantChars || event.TextTruncated {
				t.Fatalf("marker content was not redacted with original metadata: %+v / %q", event, event.LocalReasoningText())
			}
		})
	}
}

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

func TestRedactReasoningScrubsIDLessUnsupportedCodexReasoning(t *testing.T) {
	const secret = "private-idless-reasoning-9137"
	raw := strings.Join([]string{
		`{"type":"thread.started","thread_id":"thread-1"}`,
		`{"type":"turn.started"}`,
		`{"type":"item.completed","item":{"type":"reasoning","text":"` + secret + `","summary":["private"]}}`,
		`{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}`,
	}, "\n") + "\n"
	d, err := parseCodex(strings.NewReader(raw), newWorkspace(""))
	if err == nil || !strings.Contains(err.Error(), "unsupported event") {
		t.Fatalf("parse error = %v, want unsupported-event failure", err)
	}

	event := findTimelineProviderEvent(d.Timeline, "item.completed")
	if event == nil || event.Kind != KindUnsupported {
		t.Fatalf("unsupported item.completed event missing: %+v", d.Timeline)
	}

	RedactReasoning(d)

	if !event.Redacted || bytes.Contains(event.Details, []byte(secret)) {
		t.Fatalf("unsupported reasoning was not redacted: %+v / %s", event, event.Details)
	}
	if !bytes.Contains(event.Details, []byte(`"text":"[REDACTED]"`)) ||
		!bytes.Contains(event.Details, []byte(`"summary":[]`)) ||
		!bytes.Contains(event.Details, []byte(`"type":"reasoning"`)) {
		t.Fatalf("unsupported reasoning did not use structural type-preserving masks: %s", event.Details)
	}
}

func TestRedactReasoningMasksUninspectableUnsupportedDetails(t *testing.T) {
	d := &Digest{Timeline: []Event{{
		Kind: KindUnsupported, ProviderEvent: "future.event", Details: json.RawMessage(`{"unterminated":`),
	}}}

	RedactReasoning(d)

	event := d.Timeline[0]
	if !event.Redacted || string(event.Details) != `"[REDACTED]"` {
		t.Fatalf("uninspectable unsupported details = %+v / %s", event, event.Details)
	}
}

func TestRedactReasoningMasksUnknownNormalizedEventConservatively(t *testing.T) {
	d := &Digest{Timeline: []Event{{
		Kind: "future_kind", Text: "possibly private", Details: json.RawMessage(`{"diagnostic":"possibly private"}`),
	}}}

	RedactReasoning(d)

	event := d.Timeline[0]
	if !event.Redacted || event.Text != "" || string(event.Details) != `"[REDACTED]"` {
		t.Fatalf("unknown normalized event was not conservatively redacted: %+v / %s", event, event.Details)
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
