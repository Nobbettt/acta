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
	want := `{"wrapper":[{"item":{"parts":[],"redacted":true,"text":"[REDACTED]","type":"reasoning"},"type":"item.completed"},{"message":{"content":[{"redacted":true,"thinking":"[REDACTED]","type":"thinking"}]},"type":"assistant"}]}`
	if string(encoded) != want {
		t.Fatalf("redacted payload = %s\nwant %s", encoded, want)
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
