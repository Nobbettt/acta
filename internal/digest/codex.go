package digest

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/nobbettt/acta/internal/reasoning"
)

// CodexEvent is one line of `codex exec --json` output. Exported so the live
// tracing tee can decode lines with the same shapes.
type CodexEvent struct {
	Type     string          `json:"type"`
	ThreadID string          `json:"thread_id,omitempty"`
	Item     *CodexItem      `json:"item,omitempty"`
	Usage    *CodexUsage     `json:"usage,omitempty"`
	Error    *CodexError     `json:"error,omitempty"`
	Message  string          `json:"message,omitempty"`
	Raw      json.RawMessage `json:"-"`
}

func (e *CodexEvent) UnmarshalJSON(raw []byte) error {
	type wire CodexEvent
	var decoded wire
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*e = CodexEvent(decoded)
	e.Raw = append(e.Raw[:0], raw...)
	return nil
}

type CodexError struct {
	Message string          `json:"message,omitempty"`
	Code    string          `json:"code,omitempty"`
	Info    json.RawMessage `json:"codex_error_info,omitempty"`
}

type CodexItem struct {
	ID                string            `json:"id"`
	Type              string            `json:"type"`
	Command           string            `json:"command,omitempty"`
	AggregatedOutput  string            `json:"aggregated_output,omitempty"`
	ExitCode          *int              `json:"exit_code,omitempty"`
	Status            string            `json:"status,omitempty"`
	Text              string            `json:"text,omitempty"`
	TextChars         int               `json:"text_chars,omitempty"`
	TextTruncated     bool              `json:"text_truncated,omitempty"`
	Redacted          bool              `json:"redacted,omitempty"`
	Message           string            `json:"message,omitempty"`
	Changes           []CodexFileChange `json:"changes,omitempty"`
	Items             []CodexTodoItem   `json:"items,omitempty"`
	Server            string            `json:"server,omitempty"`
	Tool              string            `json:"tool,omitempty"`
	Arguments         json.RawMessage   `json:"arguments,omitempty"`
	Result            json.RawMessage   `json:"result,omitempty"`
	Error             *CodexError       `json:"error,omitempty"`
	Query             string            `json:"query,omitempty"`
	Action            json.RawMessage   `json:"action,omitempty"`
	SenderThreadID    string            `json:"sender_thread_id,omitempty"`
	ReceiverThreadIDs []string          `json:"receiver_thread_ids,omitempty"`
	Prompt            string            `json:"prompt,omitempty"`
	AgentsStates      json.RawMessage   `json:"agents_states,omitempty"`
	Raw               json.RawMessage   `json:"-"`
}

func (i *CodexItem) UnmarshalJSON(raw []byte) error {
	type wire CodexItem
	var decoded wire
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*i = CodexItem(decoded)
	i.Raw = append(i.Raw[:0], raw...)
	return nil
}

// Failed reports whether a terminal codex item represents a failure, so the
// digest and the tracing span agree on error state (a single rule instead of
// four hand-coded copies). A nonzero exit code always means failure; otherwise
// only an explicit non-success status does. The real stream stamps
// "completed"/"failed"; empty and "success" are treated as ok.
func (i *CodexItem) Failed() bool {
	if i.ExitCode != nil && *i.ExitCode != 0 {
		return true
	}
	switch i.Status {
	case "", "completed", "success":
		return false
	default:
		return true
	}
}

type CodexFileChange struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
}

type CodexTodoItem struct {
	Text      string `json:"text"`
	Completed bool   `json:"completed"`
}

type CodexUsage struct {
	InputTokens       int64 `json:"input_tokens"`
	CachedInputTokens int64 `json:"cached_input_tokens"`
	CacheWriteTokens  int64 `json:"cache_write_input_tokens,omitempty"`
	OutputTokens      int64 `json:"output_tokens"`
	ReasoningTokens   int64 `json:"reasoning_output_tokens,omitempty"`
}

// parseCodex normalizes a codex-events.jsonl stream. Completed items carry the
// authoritative action result, while lifecycle/update events are retained as
// diagnostics and started items without a completion become incomplete events.
func parseCodex(r io.Reader, ws *workspace) (*Digest, error) {
	st := newCodexState(ws)
	if err := forEachLine(r, func(n int, line []byte) {
		var event CodexEvent
		if err := reasoning.UnmarshalProviderLine(line, &event); err != nil {
			st.d.countParseError(line)
			return
		}
		st.consume(&event, n, time.Time{})
	}); err != nil {
		return nil, fmt.Errorf("read codex events: %w", err)
	}
	if st.d.Metrics.ParseErrors > 0 {
		return st.finalize(), fmt.Errorf("parse codex events: %d malformed JSONL line(s)", st.d.Metrics.ParseErrors)
	}
	d := st.finalize()
	return d, st.semanticError()
}

type codexParseState struct {
	d            *Digest
	ws           *workspace
	writeTracker *fileWriteTracker
	// item.started line/time per item id, so a completed event's observed_at
	// joins the call's start (matching claude and the span start), not its end
	// startTimes is populated only on the live stream path.
	startLines     map[string]int
	startTimes     map[string]time.Time
	startedItems   map[string]CodexItem
	seenThread     bool
	seenTurn       bool
	seenTerminal   bool
	semanticIssues []string
	finalized      bool
}

func newCodexState(ws *workspace) *codexParseState {
	return &codexParseState{
		d:            &Digest{},
		ws:           ws,
		startLines:   map[string]int{},
		startTimes:   map[string]time.Time{},
		startedItems: map[string]CodexItem{},
	}
}

func (st *codexParseState) consume(event *CodexEvent, lineNo int, at time.Time) {
	switch event.Type {
	case "item.started":
		if event.Item == nil || event.Item.ID == "" || event.Item.Type == "" {
			st.semanticIssues = append(st.semanticIssues, "item.started is missing item id or type")
			st.appendUnsupported(event.Type, event.Raw, lineNo, at)
			return
		}
		if event.Item != nil && event.Item.ID != "" {
			st.startLines[event.Item.ID] = lineNo
			st.startedItems[event.Item.ID] = *event.Item
			if !at.IsZero() {
				st.startTimes[event.Item.ID] = at
			}
			if event.Item.Type == "file_change" {
				st.writeTracker.start(event.Item.ID, codexChangePaths(event.Item, st.ws))
			}
		}
		return
	case "item.updated":
		if event.Item == nil {
			st.semanticIssues = append(st.semanticIssues, "item.updated is missing item")
			st.appendUnsupported(event.Type, event.Raw, lineNo, at)
			return
		}
		if event.Item.ID != "" {
			st.startedItems[event.Item.ID] = *event.Item
			if event.Item.Type == "file_change" {
				st.writeTracker.start(event.Item.ID, codexChangePaths(event.Item, st.ws))
			}
		}
		e := codexUpdateEvent(event.Item, lineNo)
		st.stamp(&e, at, false)
		st.d.appendEvent(e)
		return
	case "thread.started":
		st.seenThread = true
		if event.ThreadID == "" {
			st.semanticIssues = append(st.semanticIssues, "thread.started is missing thread_id")
		}
		st.d.ThreadID = event.ThreadID
		e := Event{
			Kind: KindLifecycle, ProviderEvent: event.Type, ThreadID: event.ThreadID,
			Phase: "started", Status: "running", Visibility: VisibilityDiagnostic,
			srcLine: lineNo, RawEventLines: rawEventLines(lineNo),
		}
		st.stamp(&e, at, false)
		st.d.appendEvent(e)
		return
	case "turn.started":
		st.seenTurn = true
		st.d.Metrics.Turns++
		e := Event{
			Kind: KindLifecycle, ProviderEvent: event.Type, ThreadID: st.d.ThreadID,
			Phase: "started", Status: "running", Visibility: VisibilityDiagnostic,
			srcLine: lineNo, RawEventLines: rawEventLines(lineNo),
		}
		st.stamp(&e, at, false)
		st.d.appendEvent(e)
		return
	case "turn.completed":
		st.seenTerminal = true
		if event.Usage != nil {
			st.d.Metrics.Tokens = codexTokens(event.Usage)
		}
		if st.d.Termination.ProviderReason == "" {
			st.d.Termination.ProviderReason = "turn_completed"
			st.d.Termination.Outcome = "completed"
		}
		e := Event{
			Kind: KindLifecycle, ProviderEvent: event.Type, ThreadID: st.d.ThreadID,
			Phase: "completed", Status: "completed", Visibility: VisibilityDiagnostic,
			srcLine: lineNo, completedLine: lineNo, RawEventLines: rawEventLines(lineNo),
		}
		st.stamp(&e, at, true)
		st.d.appendEvent(e)
		return
	case "turn.failed":
		st.seenTerminal = true
		message, code := codexErrorDetails(event)
		st.d.Termination = Termination{
			Outcome: "failed", ProviderReason: "turn_failed", ErrorCode: code, ErrorMessage: message,
		}
		e := Event{
			Kind: KindError, ProviderEvent: event.Type, ThreadID: st.d.ThreadID,
			Phase: "completed", Status: "failed", IsError: true, ErrorMessage: message, Text: message,
			srcLine: lineNo, completedLine: lineNo, RawEventLines: rawEventLines(lineNo),
		}
		st.stamp(&e, at, true)
		st.d.appendEvent(e)
		return
	case "error":
		st.seenTerminal = true
		message, code := codexErrorDetails(event)
		st.d.Termination = Termination{
			Outcome: "failed", ProviderReason: "error", ErrorCode: code, ErrorMessage: message,
		}
		e := Event{
			Kind: KindError, ProviderEvent: event.Type, ThreadID: st.d.ThreadID,
			Phase: "completed", Status: "failed", IsError: true, ErrorMessage: message, Text: message,
			srcLine: lineNo, completedLine: lineNo, RawEventLines: rawEventLines(lineNo),
		}
		st.stamp(&e, at, true)
		st.d.appendEvent(e)
		return
	case "item.completed":
	default:
		st.appendUnsupported(event.Type, event.Raw, lineNo, at)
		return
	}
	item := event.Item
	if item == nil {
		st.semanticIssues = append(st.semanticIssues, "item.completed is missing item")
		st.appendUnsupported(event.Type, event.Raw, lineNo, at)
		return
	}
	if item.ID == "" || item.Type == "" {
		st.semanticIssues = append(st.semanticIssues, "item.completed is missing item id or type")
		st.appendUnsupported(event.Type, event.Raw, lineNo, at)
		return
	}
	srcLine := lineNo
	if s, ok := st.startLines[item.ID]; ok {
		srcLine = s
	}
	obs := at
	if t, ok := st.startTimes[item.ID]; ok {
		obs = t
	}
	if e, ok := codexItemEvent(st.d, item, srcLine, lineNo, st.ws); ok {
		e.ThreadID = st.d.ThreadID
		if !obs.IsZero() {
			e.ObservedAt = &obs
		}
		if !at.IsZero() {
			completedAt := at
			e.CompletedAt = &completedAt
		}
		if e.Kind == KindFileEdit {
			st.writeTracker.assumeMissing(item.ID, codexAddedPaths(item, st.ws))
			e.fileSnapshots = st.writeTracker.finish(item.ID, e.Files)
		}
		st.d.appendEvent(e)
	}
	delete(st.startedItems, item.ID)
	delete(st.startLines, item.ID)
	delete(st.startTimes, item.ID)
}

func (st *codexParseState) stamp(event *Event, at time.Time, completed bool) {
	if at.IsZero() {
		return
	}
	observed := at
	event.ObservedAt = &observed
	if completed {
		completedAt := at
		event.CompletedAt = &completedAt
	}
}

func (st *codexParseState) appendUnsupported(name string, raw json.RawMessage, lineNo int, at time.Time) {
	st.d.countUnsupported(name)
	e := Event{
		Kind: KindUnsupported, ProviderEvent: name, ThreadID: st.d.ThreadID,
		Phase: "observed", Status: "unsupported", Visibility: VisibilityDiagnostic,
		srcLine: lineNo, RawEventLines: rawEventLines(lineNo), Details: capInput(raw),
	}
	st.stamp(&e, at, false)
	st.d.appendEvent(e)
}

func (st *codexParseState) finalize() *Digest {
	if st.finalized {
		return st.d
	}
	st.finalized = true
	type pending struct {
		id   string
		line int
	}
	pendingItems := make([]pending, 0, len(st.startedItems))
	for id := range st.startedItems {
		pendingItems = append(pendingItems, pending{id: id, line: st.startLines[id]})
	}
	sort.Slice(pendingItems, func(i, j int) bool { return pendingItems[i].line < pendingItems[j].line })
	for _, pending := range pendingItems {
		item := st.startedItems[pending.id]
		e, ok := codexItemEvent(st.d, &item, pending.line, 0, st.ws)
		if !ok {
			continue
		}
		e.ThreadID = st.d.ThreadID
		e.Phase = "incomplete"
		e.Status = "incomplete"
		e.CompletedAt = nil
		e.completedLine = 0
		e.RawEventLines = rawEventLines(pending.line)
		if startedAt, ok := st.startTimes[pending.id]; ok {
			t := startedAt
			e.ObservedAt = &t
		}
		if e.Kind == KindCommand || e.Kind == KindToolCall || e.Kind == KindWebSearch || e.Kind == KindTask {
			st.d.Metrics.IncompleteToolCalls++
		}
		e.IsError = false
		if e.Kind == KindFileEdit {
			st.writeTracker.assumeMissing(item.ID, codexAddedPaths(&item, st.ws))
			e.fileSnapshots = st.writeTracker.finish(item.ID, e.Files)
		}
		st.d.appendEvent(e)
	}
	if !st.seenThread {
		st.semanticIssues = append(st.semanticIssues, "stream has no thread.started event")
	}
	if !st.seenTurn {
		st.semanticIssues = append(st.semanticIssues, "stream has no turn.started event")
	}
	if !st.seenTerminal && st.d.Termination.Outcome == "" {
		st.semanticIssues = append(st.semanticIssues, "stream ended without a terminal turn event")
	}
	if len(st.semanticIssues) > 0 && st.d.Termination.Outcome != OutcomeFailed {
		st.d.Termination.Outcome = OutcomeError
		st.d.Termination.ProviderReason = "provider_stream_degraded"
		st.d.Termination.ErrorMessage = strings.Join(st.semanticIssues, "; ")
	}
	if st.d.Metrics.ProjectionTruncated && st.d.Termination.Outcome != OutcomeFailed {
		st.d.Termination.Outcome = OutcomeError
		st.d.Termination.ProviderReason = "projection_limit_exceeded"
		st.d.Termination.ErrorMessage = fmt.Sprintf("normalized projection exceeded limits; dropped %d event(s)", st.d.Metrics.DroppedEvents)
	}
	return st.d
}

func (st *codexParseState) semanticError() error {
	st.finalize()
	if err := st.writeTracker.evidenceError(st.d); err != nil {
		st.d.Termination.Outcome = OutcomeDegraded
		st.d.Termination.ProviderReason = "write_evidence_incomplete"
		st.d.Termination.ErrorMessage = err.Error()
		return fmt.Errorf("capture write evidence: %w", err)
	}
	if err := unsupportedEventsError(st.d); err != nil {
		if st.d.Termination.Outcome == OutcomeCompleted {
			st.d.Termination.Outcome = OutcomeDegraded
			st.d.Termination.ProviderReason = "unsupported_provider_events"
			st.d.Termination.ErrorMessage = err.Error()
		}
		return err
	}
	if st.d.Termination.Outcome == OutcomeError && st.d.Termination.ProviderReason == "provider_stream_degraded" {
		return fmt.Errorf("validate codex stream: %s", st.d.Termination.ErrorMessage)
	}
	return nil
}

func codexErrorDetails(event *CodexEvent) (string, string) {
	if event.Error != nil {
		return event.Error.Message, event.Error.Code
	}
	return event.Message, ""
}

func codexTokens(usage *CodexUsage) TokenUsage {
	return TokenUsage{
		Input:         usage.InputTokens,
		Output:        usage.OutputTokens,
		CacheRead:     usage.CachedInputTokens,
		CacheCreation: usage.CacheWriteTokens,
		Reasoning:     usage.ReasoningTokens,
		Total:         usage.InputTokens + usage.OutputTokens,
	}
}

// codexItemEvent builds the timeline event for a completed codex item and
// records its metrics. The bool is false for item types not digested yet.
func codexItemEvent(d *Digest, item *CodexItem, srcLine int, completedLine int, ws *workspace) (Event, bool) {
	status := item.Status
	if status == "" {
		status = "completed"
	}
	e := Event{
		ID: item.ID, ProviderEvent: item.Type, Phase: "completed", Status: status,
		srcLine: srcLine, completedLine: completedLine,
		RawEventLines: rawEventLines(srcLine, completedLine),
	}
	switch item.Type {
	case "command_execution":
		e.Kind = KindCommand
		e.Command = unwrapShell(item.Command)
		e.ExitCode = item.ExitCode
		e.IsError = e.IsError || item.Failed()
		setEventOutput(&e, item.AggregatedOutput)
		d.Metrics.Commands++
		if !e.IsError {
			applyStep(&e, retrievalFromCommand(item.Command, boundedOutput(item.AggregatedOutput), ws))
		}
	case "file_change":
		e.Kind = KindFileEdit
		e.Files = codexChangePaths(item, ws)
		for _, change := range item.Changes {
			if rel, ok := normalizeWorkspacePath(change.Path, ws); ok {
				e.Changes = append(e.Changes, FileMutation{Path: rel, Kind: change.Kind})
			}
		}
		e.IsError = item.Failed()
		d.Metrics.Edits++
	case "agent_message":
		e.Kind = KindMessage
		e.Text = item.Text
		d.FinalMessage = item.Text
	case "todo_list":
		e.Kind = KindTodo
		e.Text = renderTodos(item.Items)
	case "reasoning":
		e.Kind = KindReasoning
		if item.Redacted {
			e.Redacted = true
			e.TextChars = item.TextChars
			e.TextTruncated = item.TextTruncated
		} else if strings.TrimSpace(item.Text) == "" {
			// Reasoning redaction deliberately leaves an empty structural item.
			// Match Claude re-digestion by retaining it as explicitly redacted.
			e.Redacted = true
		} else {
			e.localReasoningText = item.Text
		}
	case "mcp_tool_call":
		e.Kind = KindToolCall
		e.Server = item.Server
		e.Tool = item.Tool
		if e.Tool == "" {
			e.Tool = item.Type
		}
		setEventInput(&e, item.Arguments)
		setEventResult(&e, item.Result)
		if len(item.Result) > 0 {
			setEventOutput(&e, string(item.Result))
		}
		if item.Error != nil {
			e.ErrorMessage = item.Error.Message
			e.IsError = true
		}
		e.IsError = e.IsError || item.Failed()
		toolName := item.Tool
		if item.Server != "" {
			toolName = item.Server + "/" + item.Tool
		}
		if toolName == "" {
			toolName = item.Type
		}
		d.Metrics.countTool(toolName)
	case "collab_tool_call":
		e.Kind = KindTask
		e.Tool = item.Tool
		e.ThreadID = item.SenderThreadID
		if len(item.ReceiverThreadIDs) > 0 {
			e.ParentID = item.SenderThreadID
		}
		input, _ := json.Marshal(map[string]any{
			"sender_thread_id":    item.SenderThreadID,
			"receiver_thread_ids": item.ReceiverThreadIDs,
			"prompt":              item.Prompt,
		})
		setEventInput(&e, input)
		setEventResult(&e, item.AgentsStates)
		e.IsError = item.Failed()
		d.Metrics.countTool(item.Tool)
	case "web_search":
		e.Kind = KindWebSearch
		e.Tool = "web_search"
		e.Query = item.Query
		e.Action = capInput(item.Action)
		d.Metrics.countTool("web_search")
	case "error":
		e.Kind = KindError
		e.Text = item.Message
		e.ErrorMessage = item.Message
		e.IsError = true
		e.Status = "failed"
	default:
		e.Kind = KindUnsupported
		e.Status = "unsupported"
		e.Visibility = VisibilityDiagnostic
		e.Details = capInput(item.Raw)
		d.countUnsupported("item." + item.Type)
	}
	return e, true
}

func codexChangePaths(item *CodexItem, ws *workspace) []string {
	var paths []string
	for _, change := range item.Changes {
		if rel, ok := normalizeWorkspacePath(change.Path, ws); ok && !slices.Contains(paths, rel) {
			paths = append(paths, rel)
		}
	}
	return paths
}

func codexAddedPaths(item *CodexItem, ws *workspace) []string {
	var paths []string
	for _, change := range item.Changes {
		if change.Kind != "add" {
			continue
		}
		if rel, ok := normalizeWorkspacePath(change.Path, ws); ok && !slices.Contains(paths, rel) {
			paths = append(paths, rel)
		}
	}
	return paths
}

func codexUpdateEvent(item *CodexItem, lineNo int) Event {
	e := Event{
		ID: item.ID, ProviderEvent: "item.updated." + item.Type,
		Phase: "updated", Status: item.Status, Visibility: VisibilityDiagnostic,
		srcLine: lineNo, RawEventLines: rawEventLines(lineNo),
	}
	if e.Status == "" {
		e.Status = "in_progress"
	}
	if item.Type == "todo_list" {
		e.Kind = KindTodo
		e.Text = renderTodos(item.Items)
		return e
	}
	e.Kind = KindLifecycle
	e.Details = capInput(item.Raw)
	return e
}

func applyStep(e *Event, s *step) {
	if s == nil {
		return
	}
	e.Files = s.files
	if len(s.spans) > 0 {
		e.Spans = s.spans
	}
	if len(s.readRanges) > 0 {
		e.ReadRanges = s.readRanges
	}
}

func renderTodos(items []CodexTodoItem) string {
	return renderChecklist(items,
		func(i CodexTodoItem) string { return i.Text },
		func(i CodexTodoItem) bool { return i.Completed })
}
