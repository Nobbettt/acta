package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactReasoningRawStreamRejectsOversizedLineWithoutMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider.jsonl")
	original := `{"type":"thinking","thinking":"private oversized reasoning"}` + "\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	err := redactReasoningRawStream(path, 16)
	if err == nil || !strings.Contains(err.Error(), "line 1 exceeds maximum") {
		t.Fatalf("redaction error = %v, want explicit oversized-line failure", err)
	}
	payload, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(payload) != original {
		t.Fatalf("oversized redaction changed raw evidence = %q, want %q", payload, original)
	}
}
