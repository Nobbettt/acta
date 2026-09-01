package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nobbettt/acta/internal/securefile"
)

func TestRedactReasoningRawStreamRejectsOversizedLineWithoutMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider.jsonl")
	original := `{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"private oversized reasoning"}]}}` + "\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := redactReasoningRawStream(path, 16)
	if err == nil || !strings.Contains(err.Error(), "line 1 exceeds maximum") {
		t.Fatalf("redaction error = %v, want explicit oversized-line failure", err)
	}
	if state != "failed" {
		t.Fatalf("redaction state = %q, want failed", state)
	}
	payload, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(payload) != original {
		t.Fatalf("oversized redaction changed raw evidence = %q, want %q", payload, original)
	}
}

func TestRedactReasoningLine(t *testing.T) {
	const providerSecret = "private provider reasoning"
	requireRedactedItem := func(t *testing.T, redacted []byte) {
		t.Helper()
		var event map[string]any
		if err := json.Unmarshal(redacted, &event); err != nil {
			t.Fatal(err)
		}
		item, ok := event["item"].(map[string]any)
		if !ok || item["redacted"] != true {
			t.Fatalf("redacted item = %#v, want typed provenance flag", event["item"])
		}
	}
	tests := []struct {
		name         string
		original     []byte
		wantEqual    bool
		wantError    string
		wantContains []string
		wantAbsent   []string
		semantic     func(*testing.T, []byte)
	}{
		{
			name: "codex provider block", original: []byte(`{"type":"item.completed","item":{"id":"reason-1","type":"reasoning","text":"` + providerSecret + `"}}` + "\n"),
			wantContains: []string{`"type":"reasoning"`}, wantAbsent: []string{providerSecret},
		},
		{
			name: "claude provider block", original: []byte(`{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"` + providerSecret + `"}]}}` + "\n"),
			wantContains: []string{`"type":"thinking"`}, wantAbsent: []string{providerSecret},
		},
		{
			name:       "claimed redacted metadata",
			original:   []byte(`{"type":"item.completed","item":{"type":"reasoning","text":"[REDACTED]","id":{"value":"private-id"},"status":["private-status"],"text_chars":"private-count","text_truncated":"private-truncation","redacted":true}}` + "\n"),
			wantAbsent: []string{"private-"}, semantic: requireRedactedItem,
		},
		{
			name:       "malformed redacted flag",
			original:   []byte(`{"type":"item.completed","item":{"type":"reasoning","text":"","redacted":"private-redacted-flag"}}` + "\n"),
			wantAbsent: []string{"private-"}, semantic: requireRedactedItem,
		},
		{
			name:         "provider-shaped tool result",
			original:     []byte(`{"type":"item.completed","item":{"id":"mcp-1","type":"mcp_tool_call","result":{"type":"item.completed","item":{"type":"reasoning","text":"visible fixture"}}}}` + "\n"),
			wantContains: []string{`"redacted":true`}, wantAbsent: []string{"visible fixture"},
		},
		{
			name:      "lookalike provider discriminator",
			original:  []byte(`{"type":"item.completed","item":{"id":"result-1","type":"reasoning_result","text":"visible output"}}` + "\n"),
			wantEqual: true,
		},
		{
			name:         "generic reasoning field",
			original:     []byte(`{"type":"future.event","thinking":"private future reasoning"}` + "\n"),
			wantContains: []string{`"type":"future.event"`, `"thinking":"[REDACTED]"`}, wantAbsent: []string{"private future reasoning"},
		},
		{
			name:         "bare normalized kind",
			original:     []byte(`{"kind":"tool_call","input":{"thinking":"private-bare-normalized-kind-reasoning-4187"}}` + "\n"),
			wantContains: []string{`"kind":"tool_call"`, `"thinking":"[REDACTED]"`}, wantAbsent: []string{"private-bare-normalized-kind-reasoning-4187"},
		},
		{
			name:         "reasoning kind with future type",
			original:     []byte(`{"type":"future.event","kind":"reasoning","text":"private conflicting-discriminator reasoning"}` + "\n"),
			wantContains: []string{`"type":"future.event"`, `"kind":"reasoning"`, `"redacted":true`}, wantAbsent: []string{"private conflicting-discriminator reasoning"},
		},
		{
			name: "duplicate reasoning key", original: []byte(`{"reasoning":"private","reasoning":0}` + "\n"),
			wantError: `duplicate JSON object key "reasoning"`,
		},
		{
			name:      "duplicate provider discriminator",
			original:  []byte(`{"type":"item.completed","item":{"id":"r","type":"reasoning","type":"agent_message","text":"secret"}}` + "\n"),
			wantError: `duplicate JSON object key "type"`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			redacted, err := redactReasoningLine(test.original)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("duplicate-key redaction = %q, error = %v", redacted, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if test.wantEqual && !bytes.Equal(redacted, test.original) {
				t.Fatalf("redacted line changed:\n got %s\nwant %s", redacted, test.original)
			}
			for _, want := range test.wantContains {
				if !bytes.Contains(redacted, []byte(want)) {
					t.Fatalf("redacted line does not contain %q: %s", want, redacted)
				}
			}
			for _, absent := range test.wantAbsent {
				if bytes.Contains(redacted, []byte(absent)) {
					t.Fatalf("redacted line contains %q: %s", absent, redacted)
				}
			}
			if test.semantic != nil {
				test.semantic(t, redacted)
			}
		})
	}
}

func TestRedactReasoningRawStreamRejectsNonEnvelopeRecordsWithoutMutation(t *testing.T) {
	tests := map[string]string{
		"string":  `"private reasoning"` + "\n",
		"number":  "42\n",
		"boolean": "true\n",
		"array":   `[{"type":"item.completed","item":{"type":"reasoning","text":"private"}}]` + "\n",
	}
	for name, original := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "provider.jsonl")
			if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
				t.Fatal(err)
			}

			state, err := redactReasoningRawStream(path, 1<<20)
			if err == nil || state != "failed" {
				t.Fatalf("redaction state/error = %q/%v, want failed/unverified", state, err)
			}
			payload, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(payload) != original {
				t.Fatalf("failed redaction changed raw evidence = %q, want %q", payload, original)
			}
		})
	}
}

func TestRedactReasoningRawStreamMarksPostRenameCommitFailurePartial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider.jsonl")
	const secret = "private commit-failure reasoning"
	original := `{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"` + secret + `"}]}}` + "\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("sync directory after rename")
	state, err := redactReasoningRawStreamWithWriter(path, 1<<20, failReasoningWriterAfterCommit(t, wantErr))
	if !errors.Is(err, wantErr) || state != "partial" {
		t.Fatalf("redaction state=%q error=%v, want partial commit failure", state, err)
	}
	payload, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if strings.Contains(string(payload), secret) {
		t.Fatalf("post-rename target was not redacted: %s", payload)
	}
}

func TestRedactReasoningRawStreamVerifiesUnchangedPostRenameFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider.jsonl")
	original := `{"type":"turn.completed"}` + "\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("sync directory after rename")
	state, err := redactReasoningRawStreamWithWriter(path, 1<<20, failReasoningWriterAfterCommit(t, wantErr))
	if !errors.Is(err, wantErr) || state != "failed" || !strings.Contains(err.Error(), "hash verified unchanged") {
		t.Fatalf("redaction state=%q error=%v, want verified unchanged failure", state, err)
	}
	if payload, readErr := os.ReadFile(path); readErr != nil || string(payload) != original {
		t.Fatalf("verified target=%q error=%v, want %q", payload, readErr, original)
	}
}

type postCommitFailureWriter struct {
	*securefile.AtomicWriter
	err error
}

func (writer *postCommitFailureWriter) Commit() error {
	if err := writer.AtomicWriter.Commit(); err != nil {
		return err
	}
	return writer.err
}

func failReasoningWriterAfterCommit(t *testing.T, commitErr error) func(string) (reasoningAtomicWriter, error) {
	t.Helper()
	return func(path string) (reasoningAtomicWriter, error) {
		writer, err := securefile.Create(path)
		if err != nil {
			return nil, err
		}
		return &postCommitFailureWriter{AtomicWriter: writer, err: commitErr}, nil
	}
}
