package digest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/nobbettt/acta/internal/reasoning"
)

type commandCorpusWant struct {
	Categories []string        `json:"want_categories"`
	Targets    []CommandTarget `json:"want_targets"`
	Mutations  []ShellMutation `json:"want_mutations"`
	// Files is what retrieval published as having been READ. It is optional
	// only because most entries predate it; without it an entry can assert
	// the right categories while the same command quietly publishes a file it
	// never read, which is exactly how a directory operand reached Files.
	Files []string `json:"want_files,omitempty"`
}

type commandCorpusCase struct {
	Command      string `json:"command"`
	WorkspaceDir string `json:"workspace_dir,omitempty"`
	commandCorpusWant
	Source  string             `json:"source"`
	Note    string             `json:"note,omitempty"`
	Output  string             `json:"output,omitempty"`
	Retry   bool               `json:"retry,omitempty"`
	Failure *commandCorpusWant `json:"failure,omitempty"`
}

func TestCommandCorpus(t *testing.T) {
	data, err := os.ReadFile("testdata/command-corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	corpus, err := decodeCommandCorpus(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(corpus) < 200 || len(corpus) > 600 {
		t.Fatalf("corpus has %d entries, want 200-600", len(corpus))
	}
	for i, tc := range corpus {
		name := tc.Source + "/" + strings.ReplaceAll(tc.Command, "/", "_")
		t.Run(name, func(t *testing.T) {
			validateCorpusCase(t, i, tc)
			compareCorpusWant(t, tc.Command, tc.commandCorpusWant, classifyCorpusCommand(tc, true))
			if tc.Failure != nil {
				compareCorpusWant(t, tc.Command+" [exitOK=false]", *tc.Failure, classifyCorpusCommand(tc, false))
			}
		})
	}
}

func TestDecodeCommandCorpusRejectsUnknownFields(t *testing.T) {
	_, err := decodeCommandCorpus([]byte(`[{"command":"echo ok","source":"x","want_category":["fs.delete"]}]`))
	if err == nil || !strings.Contains(err.Error(), `entry 0 ("echo ok"): json: unknown field "want_category"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeCommandCorpusRejectsDuplicateFields(t *testing.T) {
	_, err := decodeCommandCorpus([]byte(`[{"command":"echo ok","source":"x","want_categories":["fs.delete"],"want_categories":[],"want_targets":[],"want_mutations":[]}]`))
	if err == nil || !strings.Contains(err.Error(), `duplicate JSON object key "want_categories"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeCommandCorpusRejectsSkippedEntries(t *testing.T) {
	_, err := decodeCommandCorpus([]byte(`[{"command":"command false && git status","source":"x","want_categories":[],"want_targets":[],"want_mutations":[],"disagrees_with_impl":true,"disagreement":"skip"}]`))
	if err == nil || !strings.Contains(err.Error(), `entry 0 ("command false && git status"): json: unknown field "disagrees_with_impl"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeCommandCorpusRejectsTrailingValue(t *testing.T) {
	_, err := decodeCommandCorpus([]byte(`[] {}`))
	if err == nil || !strings.Contains(err.Error(), "trailing JSON value") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func decodeCommandCorpus(data []byte) ([]commandCorpusCase, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var entries []json.RawMessage
	if err := dec.Decode(&entries); err != nil {
		return nil, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("trailing JSON value")
		}
		return nil, fmt.Errorf("trailing JSON value: %w", err)
	}
	if err := reasoning.ValidateUniqueObjectKeys(data); err != nil {
		return nil, err
	}
	corpus := make([]commandCorpusCase, len(entries))
	for i, entry := range entries {
		dec := json.NewDecoder(bytes.NewReader(entry))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&corpus[i]); err != nil {
			return nil, fmt.Errorf("entry %d (%q): %w", i, corpus[i].Command, err)
		}
	}
	return corpus, nil
}

func TestClassifyCorpusCommandBoundsRetrievalOutput(t *testing.T) {
	got := classifyCorpusCommand(commandCorpusCase{
		Command: "cat README.md",
		Output:  strings.Repeat("x", maxCommandOutputChars+1),
	}, true)
	compareCorpusWant(t, "oversized cat README.md", commandCorpusWant{
		Categories: []string{},
		Targets:    []CommandTarget{},
		Mutations:  []ShellMutation{},
	}, got)
}

func validateCorpusCase(t *testing.T, index int, tc commandCorpusCase) {
	t.Helper()
	if tc.Command == "" || tc.Source == "" {
		t.Fatalf("entry %d must have command and source", index)
	}
	if strings.ContainsAny(tc.Note, "\r\n") {
		t.Fatalf("entry %d note must be one line", index)
	}
	validateCorpusWant(t, index, tc.commandCorpusWant)
	if tc.Failure != nil {
		validateCorpusWant(t, index, *tc.Failure)
	}
}

func validateCorpusWant(t *testing.T, index int, want commandCorpusWant) {
	t.Helper()
	if !slices.IsSorted(want.Categories) {
		t.Fatalf("entry %d want_categories are not sorted: %v", index, want.Categories)
	}
	for i := 1; i < len(want.Categories); i++ {
		if want.Categories[i-1] == want.Categories[i] {
			t.Fatalf("entry %d repeats category %q", index, want.Categories[i])
		}
	}
}

func classifyCorpusCommand(tc commandCorpusCase, exitOK bool) commandCorpusWant {
	ws := testWorkspace().withControlPrefix(".orchestrator-stage-control")
	if tc.WorkspaceDir != "" {
		ws = newWorkspace(tc.WorkspaceDir).withControlPrefix(".orchestrator-stage-control")
	}
	facts := classifyCommand(tc.Command, tc.Output, exitOK, ws)
	if facts == nil {
		facts = &commandFacts{}
	}
	var paths []string
	if exitOK {
		if retrieval := retrievalFromCommand(tc.Command, boundedOutput(tc.Output), ws); retrieval != nil {
			paths = retrieval.files
		}
	}
	classifyPaths(facts, paths, ws)
	e := Event{Kind: KindCommand, Command: tc.Command, Categories: facts.categories, srcLine: 2, IsError: !exitOK}
	d := &Digest{}
	if tc.Retry {
		d.Timeline = append(d.Timeline, Event{Kind: KindCommand, Command: tc.Command, srcLine: 1})
	}
	applyRunState(d, &e, tc.Output)
	facts.categories = e.Categories
	facts.sortCategories()
	return commandCorpusWant{
		Categories: nonNil(facts.categories),
		Targets:    nonNil(facts.targets),
		Mutations:  nonNil(facts.mutations),
		Files:      paths,
	}
}

func nonNil[S ~[]E, E any](s S) S {
	if s == nil {
		return S{}
	}
	return s
}

func compareCorpusWant(t *testing.T, command string, want, got commandCorpusWant) {
	t.Helper()
	// An entry that publishes no files may say so by omitting want_files or by
	// writing an empty list; both mean the same thing, and neither excuses an
	// entry whose command DOES publish a file from naming it.
	if len(want.Files) == 0 {
		want.Files = nil
	}
	if len(got.Files) == 0 {
		got.Files = nil
	}
	if reflect.DeepEqual(want, got) {
		return
	}
	wantJSON, _ := json.MarshalIndent(want, "", "  ")
	gotJSON, _ := json.MarshalIndent(got, "", "  ")
	t.Errorf("classification drift for %q (-want +got):\n-%s\n+%s", command, wantJSON, gotJSON)
}
