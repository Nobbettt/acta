package digest

import (
	"strings"
	"testing"
)

func TestNormalizeEventDedupesTargetsAfterTruncation(t *testing.T) {
	prefix := strings.Repeat("x", 4096)
	event := Event{Targets: []CommandTarget{
		{Kind: "url", Value: prefix + "one"},
		{Kind: "url", Value: prefix + "two"},
		{Kind: "host", Value: "example.test"},
	}}

	normalizeEvent(&event)

	if len(event.Targets) != 2 || event.Targets[0].Value != prefix || event.Targets[1].Value != "example.test" {
		t.Fatalf("normalized targets = %+v, want first truncated target and distinct host", event.Targets)
	}
}
