package runner

import (
	"bytes"
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

func TestRedactReasoningLineRedactsExactProviderBlocks(t *testing.T) {
	const secret = "private provider reasoning"
	tests := map[string][]byte{
		"codex":  []byte(`{"type":"item.completed","item":{"id":"reason-1","type":"reasoning","text":"` + secret + `"}}` + "\n"),
		"claude": []byte(`{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"` + secret + `"}]}}` + "\n"),
	}
	for name, original := range tests {
		t.Run(name, func(t *testing.T) {
			redacted, err := redactReasoningLine(original)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(redacted, []byte(secret)) {
				t.Fatalf("provider reasoning was not redacted: %s", redacted)
			}
			if !bytes.Contains(redacted, []byte(`"type":"reasoning"`)) && !bytes.Contains(redacted, []byte(`"type":"thinking"`)) {
				t.Fatalf("provider reasoning block lost its discriminator: %s", redacted)
			}
		})
	}
}

func TestRedactReasoningLinePreservesNestedToolResultLookalike(t *testing.T) {
	original := []byte(`{"type":"item.completed","item":{"id":"mcp-1","type":"mcp_tool_call","result":{"type":"reasoning_result","text":"visible output"}}}` + "\n")
	redacted, err := redactReasoningLine(original)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(redacted, original) {
		t.Fatalf("nested tool result changed:\n got %s\nwant %s", redacted, original)
	}
}

func TestRedactReasoningLineRequiresExactProviderDiscriminator(t *testing.T) {
	original := []byte(`{"type":"item.completed","item":{"id":"result-1","type":"reasoning_result","text":"visible output"}}` + "\n")
	redacted, err := redactReasoningLine(original)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(redacted, original) {
		t.Fatalf("lookalike provider item changed:\n got %s\nwant %s", redacted, original)
	}
}

func TestRedactReasoningLineRequiresProviderEventPosition(t *testing.T) {
	original := []byte(`{"type":"thinking","thinking":"visible non-provider data"}` + "\n")
	redacted, err := redactReasoningLine(original)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(redacted, original) {
		t.Fatalf("non-provider object changed:\n got %s\nwant %s", redacted, original)
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
