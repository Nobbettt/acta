package reasoning

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactProviderBlocksExactPositionsAndMetadata(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		want        string
		wantChanged bool
	}{
		{
			name: "recurses through exact provider positions",
			raw: `{
				"wrapper": [
					{"type":"item.completed","item":{"type":"reasoning","text":"private","parts":["private"]}},
					{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"private"}]}}
				]
			}`,
			want:        `{"wrapper":[{"item":{"parts":[],"redacted":true,"text":"[REDACTED]","text_chars":7,"text_truncated":false,"type":"reasoning"},"type":"item.completed"},{"message":{"content":[{"redacted":true,"text_chars":7,"text_truncated":false,"thinking":"[REDACTED]","type":"thinking"}]},"type":"assistant"}]}`,
			wantChanged: true,
		},
		{
			name: "preserves prior redaction metadata",
			raw:  `{"type":"item.completed","item":{"type":"reasoning","text":"[REDACTED]","text_chars":123456,"text_truncated":true,"redacted":true}}`,
			want: `{"item":{"redacted":true,"text":"[REDACTED]","text_chars":123456,"text_truncated":true,"type":"reasoning"},"type":"item.completed"}`,
		},
		{
			name:        "treats unflagged marker as content",
			raw:         `{"type":"item.completed","item":{"type":"reasoning","text":"[REDACTED]"}}`,
			want:        `{"item":{"redacted":true,"text":"[REDACTED]","text_chars":10,"text_truncated":false,"type":"reasoning"},"type":"item.completed"}`,
			wantChanged: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var payload any
			if err := json.Unmarshal([]byte(test.raw), &payload); err != nil {
				t.Fatal(err)
			}
			changed, _, err := redactProviderBlocks(context.Background(), payload, ProviderTraversal())
			if err != nil {
				t.Fatal(err)
			}
			if changed != test.wantChanged {
				t.Fatalf("changed = %v, want %v", changed, test.wantChanged)
			}
			encoded, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != test.want {
				t.Fatalf("redacted payload = %s\nwant %s", encoded, test.want)
			}
		})
	}
}

func TestRedactProviderBlocksRequiresExactDiscriminatorAndPosition(t *testing.T) {
	tests := map[string]string{
		"lookalike discriminator": `{"type":"item.completed","item":{"type":"rethinking","text":"keep"}}`,
		"wrong provider position": `{"type":"item.completed","details":{"type":"reasoning","text":"keep"}}`,
		"standalone block":        `{"type":"thinking","thinking":"keep"}`,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			var payload any
			if err := json.Unmarshal([]byte(raw), &payload); err != nil {
				t.Fatal(err)
			}
			changed, _, err := redactProviderBlocks(context.Background(), payload, ProviderTraversal())
			if err != nil {
				t.Fatal(err)
			}
			if changed {
				t.Fatalf("non-provider payload was redacted: %#v", payload)
			}
		})
	}
}

func TestRedactProviderBlocksTraversesRawProviderData(t *testing.T) {
	const fixture = `{"type":"item.completed","item":{"type":"reasoning","text":"fixture"}}`
	tests := map[string]string{
		"result":                    `{"type":"mcp_tool_call","result":` + fixture + `}`,
		"arguments":                 `{"type":"mcp_tool_call","arguments":` + fixture + `}`,
		"input":                     `{"type":"tool_use","input":` + fixture + `}`,
		"normalized lookalike":      `{"kind":"tool_result","provider_event":"user.tool_result","phase":"completed","status":"orphaned","result":` + fixture + `}`,
		"structured output":         `{"type":"result","structured_output":` + fixture + `}`,
		"tool use result":           `{"type":"user","tool_use_result":` + fixture + `}`,
		"structured output details": `{"kind":"structured_output","details":` + fixture + `}`,
		"user content by type":      `{"type":"user","content":[` + fixture + `]}`,
		"user content by role":      `{"role":"user","content":[` + fixture + `]}`,
		"tool result content":       `{"type":"tool_result","content":[` + fixture + `]}`,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			var payload any
			if err := json.Unmarshal([]byte(raw), &payload); err != nil {
				t.Fatal(err)
			}
			changed, _, err := redactProviderBlocks(context.Background(), payload, ProviderTraversal())
			if err != nil {
				t.Fatal(err)
			}
			if !changed {
				t.Fatalf("raw provider data was not traversed: %#v", payload)
			}
			after, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(after), `"text":"fixture"`) || !strings.Contains(string(after), `"redacted":true`) {
				t.Fatalf("nested raw provider reasoning was not redacted: %s", after)
			}
		})
	}
}

func TestRedactProviderBlocksReportsPriorRedactionInRawProviderData(t *testing.T) {
	var payload any
	if err := json.Unmarshal([]byte(`{"type":"mcp_tool_call","result":{"type":"item.completed","item":{"type":"reasoning","redacted":true}}}`), &payload); err != nil {
		t.Fatal(err)
	}
	_, containsPreviouslyRedacted, err := redactProviderBlocks(context.Background(), payload, ProviderTraversal())
	if err != nil {
		t.Fatal(err)
	}
	if !containsPreviouslyRedacted {
		t.Fatal("redacted block nested in raw provider data was not found")
	}
}

func TestRedactValueTraversesPayloadKeysOnUnknownEnvelopes(t *testing.T) {
	const secret = "future-output-reasoning-7421"
	var payload any
	if err := json.Unmarshal([]byte(`{"type":"future.event","output":[{"type":"reasoning","text":"`+secret+`"}]}`), &payload); err != nil {
		t.Fatal(err)
	}
	changed, verified := RedactValue(payload, ProviderTraversal())
	if !changed || !verified {
		t.Fatalf("future output redaction = changed %v, verified %v", changed, verified)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) || !strings.Contains(string(encoded), `"redacted":true`) {
		t.Fatalf("future output reasoning was not redacted: %s", encoded)
	}
}

func TestRedactValueRequiresPositiveNormalizedEnvelopeIdentification(t *testing.T) {
	const secret = "normalized-envelope-secret-5183"
	tests := []struct {
		name       string
		raw        string
		wantChange bool
		wantSecret bool
	}{
		{
			name:       "bare kind in provider data",
			raw:        `{"kind":"tool_call","input":{"thinking":"` + secret + `"}}`,
			wantChange: true,
		},
		{
			name:       "genuine normalized tool call",
			raw:        `{"kind":"tool_call","input":{"thinking":"` + secret + `"}}`,
			wantSecret: true,
		},
		{
			name:       "foreign type",
			raw:        `{"type":"future.event","kind":"tool_result","output":{"thinking":"` + secret + `"}}`,
			wantChange: true,
		},
		{
			name:       "genuine normalized tool result",
			raw:        `{"kind":"tool_result","provider_event":"user.tool_result","phase":"completed","status":"orphaned","result":{"thinking":"` + secret + `"},"output":"tool output"}`,
			wantSecret: true,
		},
		{
			name:       "conflicting recognized type",
			raw:        `{"type":"tool.call.completed","kind":"tool_result","result":{"thinking":"` + secret + `"}}`,
			wantChange: true,
		},
		{
			name:       "wrong normalized shape",
			raw:        `{"kind":"tool_result","input":{"thinking":"` + secret + `"}}`,
			wantChange: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var payload any
			if err := json.Unmarshal([]byte(test.raw), &payload); err != nil {
				t.Fatal(err)
			}
			traversal := NormalizedTraversal("")
			if test.name == "bare kind in provider data" {
				traversal = ProviderTraversal()
			}
			changed, verified := RedactValue(payload, traversal)
			if changed != test.wantChange || !verified {
				t.Fatalf("redaction = changed %v, verified %v; want changed %v, verified true", changed, verified, test.wantChange)
			}
			encoded, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			hasSecret := strings.Contains(string(encoded), secret)
			if hasSecret != test.wantSecret {
				t.Fatalf("secret retained = %v, want %v: %s", hasSecret, test.wantSecret, encoded)
			}
			if test.wantChange && !strings.Contains(string(encoded), `"thinking":"[REDACTED]"`) {
				t.Fatalf("nested reasoning was not masked: %s", encoded)
			}
		})
	}
}
