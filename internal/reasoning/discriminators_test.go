package reasoning

import (
	"encoding/json"
	"testing"
)

func TestRedactProviderBlocksRecursesThroughExactProviderPositions(t *testing.T) {
	var payload any
	if err := json.Unmarshal([]byte(`{
		"wrapper": [
			{"type":"item.completed","item":{"type":"reasoning","text":"private","parts":["private"]}},
			{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"private"}]}}
		]
	}`), &payload); err != nil {
		t.Fatal(err)
	}

	if !RedactProviderBlocks(payload) {
		t.Fatal("nested provider blocks were not redacted")
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"wrapper":[{"item":{"parts":[],"redacted":true,"text":"[REDACTED]","text_chars":7,"text_truncated":false,"type":"reasoning"},"type":"item.completed"},{"message":{"content":[{"redacted":true,"text_chars":7,"text_truncated":false,"thinking":"[REDACTED]","type":"thinking"}]},"type":"assistant"}]}`
	if string(encoded) != want {
		t.Fatalf("redacted payload = %s\nwant %s", encoded, want)
	}
}

func TestRedactProviderBlocksPreservesPriorRedactionMetadata(t *testing.T) {
	const raw = `{"type":"item.completed","item":{"type":"reasoning","text":"[REDACTED]","text_chars":123456,"text_truncated":true,"redacted":true}}`
	var payload any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	if RedactProviderBlocks(payload) {
		t.Fatal("already-redacted provider block changed")
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"item":{"redacted":true,"text":"[REDACTED]","text_chars":123456,"text_truncated":true,"type":"reasoning"},"type":"item.completed"}`
	if string(encoded) != want {
		t.Fatalf("re-redacted payload = %s\nwant %s", encoded, want)
	}
}

func TestRedactProviderBlocksTreatsUnflaggedMarkerAsContent(t *testing.T) {
	const raw = `{"type":"item.completed","item":{"type":"reasoning","text":"[REDACTED]"}}`
	var payload any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	if !RedactProviderBlocks(payload) {
		t.Fatal("unflagged marker content was not redacted with provenance metadata")
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"item":{"redacted":true,"text":"[REDACTED]","text_chars":10,"text_truncated":false,"type":"reasoning"},"type":"item.completed"}`
	if string(encoded) != want {
		t.Fatalf("redacted marker payload = %s\nwant %s", encoded, want)
	}
}

func TestIsRedactedBlockRequiresProvenanceFlag(t *testing.T) {
	if !IsRedactedBlock(true) {
		t.Fatal("redaction flag was not recognized")
	}
	if IsRedactedBlock(false) {
		t.Fatal("unflagged block was classified as previously redacted")
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
			if RedactProviderBlocks(payload) {
				t.Fatalf("non-provider payload was redacted: %#v", payload)
			}
		})
	}
}

func TestRedactProviderBlocksPreservesProviderShapesInsideUserData(t *testing.T) {
	const fixture = `{"type":"item.completed","item":{"type":"reasoning","text":"fixture"}}`
	tests := map[string]string{
		"result":                    `{"result":` + fixture + `}`,
		"arguments":                 `{"arguments":` + fixture + `}`,
		"input":                     `{"input":` + fixture + `}`,
		"output":                    `{"output":` + fixture + `}`,
		"structured output":         `{"structured_output":` + fixture + `}`,
		"tool use result":           `{"tool_use_result":` + fixture + `}`,
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
			before, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			if RedactProviderBlocks(payload) {
				t.Fatalf("provider-shaped user data was redacted: %#v", payload)
			}
			after, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatalf("provider-shaped user data changed:\n got %s\nwant %s", after, before)
			}
		})
	}
}

func TestContainsRedactedProviderBlockIgnoresUserData(t *testing.T) {
	var payload any
	if err := json.Unmarshal([]byte(`{"result":{"type":"item.completed","item":{"type":"reasoning","redacted":true}}}`), &payload); err != nil {
		t.Fatal(err)
	}
	if ContainsRedactedProviderBlock(payload) {
		t.Fatal("redacted provider-shaped user data was classified as a provider envelope")
	}
}
