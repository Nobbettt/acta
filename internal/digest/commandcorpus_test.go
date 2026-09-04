package digest

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type commandCorpusWant struct {
	Categories []string        `json:"want_categories"`
	Targets    []CommandTarget `json:"want_targets"`
	Mutations  []ShellMutation `json:"want_mutations"`
}

type commandCorpusCase struct {
	Command string `json:"command"`
	commandCorpusWant
	Source            string             `json:"source"`
	Note              string             `json:"note,omitempty"`
	Output            string             `json:"output,omitempty"`
	Retry             bool               `json:"retry,omitempty"`
	Failure           *commandCorpusWant `json:"failure,omitempty"`
	DisagreesWithImpl bool               `json:"disagrees_with_impl,omitempty"`
	Disagreement      string             `json:"disagreement,omitempty"`
}

func TestCommandCorpus(t *testing.T) {
	data, err := os.ReadFile("testdata/command-corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus []commandCorpusCase
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus) < 200 || len(corpus) > 400 {
		t.Fatalf("corpus has %d entries, want 200-400", len(corpus))
	}
	for i, tc := range corpus {
		name := tc.Source + "/" + strings.ReplaceAll(tc.Command, "/", "_")
		t.Run(name, func(t *testing.T) {
			validateCorpusCase(t, i, tc)
			if tc.DisagreesWithImpl {
				t.Skipf("explained implementation disagreement: %s", tc.Note)
			}
			compareCorpusWant(t, tc.Command, tc.commandCorpusWant, classifyCorpusCommand(tc, true))
			if tc.Failure != nil {
				compareCorpusWant(t, tc.Command+" [exitOK=false]", *tc.Failure, classifyCorpusCommand(tc, false))
			}
		})
	}
}

func validateCorpusCase(t *testing.T, index int, tc commandCorpusCase) {
	t.Helper()
	if tc.Command == "" || tc.Source == "" {
		t.Fatalf("entry %d must have command and source", index)
	}
	if strings.ContainsAny(tc.Note, "\r\n") || strings.ContainsAny(tc.Disagreement, "\r\n") {
		t.Fatalf("entry %d note and disagreement must each be one line", index)
	}
	if tc.DisagreesWithImpl != (tc.Disagreement != "") {
		t.Fatalf("entry %d must set disagrees_with_impl and disagreement together", index)
	}
	if tc.DisagreesWithImpl && tc.Note == "" {
		t.Fatalf("entry %d has an unexplained implementation disagreement", index)
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
	ws := testWorkspace().withControlPrefix(".kiwi-stage-control")
	facts := classifyCommand(tc.Command, tc.Output, exitOK, ws)
	if facts == nil {
		facts = &commandFacts{}
	}
	if retrieval := retrievalFromCommand(tc.Command, tc.Output, ws); retrieval != nil {
		classifyPaths(facts, retrieval.files, ws)
	} else {
		classifyPaths(facts, nil, ws)
	}
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
	if reflect.DeepEqual(want, got) {
		return
	}
	wantJSON, _ := json.MarshalIndent(want, "", "  ")
	gotJSON, _ := json.MarshalIndent(got, "", "  ")
	t.Errorf("classification drift for %q (-want +got):\n-%s\n+%s", command, wantJSON, gotJSON)
}
