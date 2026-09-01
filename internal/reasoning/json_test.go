package reasoning

import (
	"errors"
	"testing"
)

func TestUnmarshalProviderLineRequiresObjectEnvelope(t *testing.T) {
	tests := map[string]string{
		"string":  `"private reasoning"`,
		"number":  "42",
		"boolean": "true",
		"array":   `[{"type":"turn.completed"}]`,
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			var value any
			if err := UnmarshalProviderLine([]byte(payload), &value); !errors.Is(err, ErrInvalidProviderEnvelope) {
				t.Fatalf("UnmarshalProviderLine() error = %v, want ErrInvalidProviderEnvelope", err)
			}
		})
	}

	var value any
	if err := UnmarshalProviderLine([]byte(`{"type":"turn.completed"}`), &value); err != nil {
		t.Fatalf("UnmarshalProviderLine() rejected a valid object envelope: %v", err)
	}
}
