package digest

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateRuneSafe(t *testing.T) {
	// A 3-byte rune (€ = E2 82 AC) placed so the byte limit lands mid-rune.
	s := strings.Repeat("a", 8) + "€" // bytes: 8 + 3 = 11
	tests := []struct {
		name  string
		in    string
		limit int
		want  string
	}{
		{"under limit", "hello", 100, "hello"},
		{"exact fit", "hello", 5, "hello"},
		{"ascii cut", "hello", 3, "hel"},
		{"cut before multibyte start", s, 9, strings.Repeat("a", 8)},   // limit 9 lands on € first byte -> drop it
		{"cut mid multibyte backs off", s, 10, strings.Repeat("a", 8)}, // limit 10 lands inside € -> back off to 8
		{"zero limit", "€uro", 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Truncate(tt.in, tt.limit)
			if got != tt.want {
				t.Fatalf("Truncate(%q, %d) = %q, want %q", tt.in, tt.limit, got, tt.want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("Truncate(%q, %d) = %q is not valid UTF-8", tt.in, tt.limit, got)
			}
		})
	}
}

func TestCapOutputCountsRunesNotBytes(t *testing.T) {
	// 5 euro signs = 15 bytes but 5 runes.
	text := strings.Repeat("€", 5)
	out, chars := capOutput(text)
	if out != text {
		t.Fatalf("capOutput altered under-limit text: %q", out)
	}
	if chars != 5 {
		t.Fatalf("capOutput chars = %d, want 5 (runes, not bytes)", chars)
	}
}

func TestCapOutputTruncatesValidUTF8(t *testing.T) {
	// Force truncation with a multibyte rune straddling the cap.
	big := strings.Repeat("a", MaxEventOutputChars-1) + "€€"
	out, chars := capOutput(big)
	if len(out) > MaxEventOutputChars {
		t.Fatalf("capOutput returned %d bytes, over cap %d", len(out), MaxEventOutputChars)
	}
	if !utf8.ValidString(out) {
		t.Fatalf("capOutput produced invalid UTF-8")
	}
	if chars != utf8.RuneCountInString(big) {
		t.Fatalf("capOutput chars = %d, want original rune count %d", chars, utf8.RuneCountInString(big))
	}
}

func TestCapInput(t *testing.T) {
	small := json.RawMessage(`{"file_path":"a.go"}`)
	if got := capInput(small); string(got) != string(small) {
		t.Fatalf("capInput altered small input: %s", got)
	}

	big := json.RawMessage(`{"content":"` + strings.Repeat("x", MaxEventInputChars) + `"}`)
	got := capInput(big)
	if len(got) >= len(big) {
		t.Fatalf("capInput did not shrink oversized input (%d bytes)", len(got))
	}
	if !json.Valid(got) {
		t.Fatalf("capInput produced invalid JSON: %s", got)
	}
	var marker struct {
		TruncatedBytes int `json:"_truncated_bytes"`
	}
	if err := json.Unmarshal(got, &marker); err != nil || marker.TruncatedBytes != len(big) {
		t.Fatalf("capInput marker = %s, want _truncated_bytes=%d", got, len(big))
	}
}
