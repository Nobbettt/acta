package digest

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nobbettt/acta/internal/reasoning"
)

// ClaudeItem is one line of `claude --print --output-format stream-json`
// output. Exported so the live tracing tee can decode lines with the same
// shapes.
type ClaudeItem struct {
	Type              string                   `json:"type"`
	Subtype           string                   `json:"subtype,omitempty"`
	Model             string                   `json:"model,omitempty"`
	SessionID         string                   `json:"session_id,omitempty"`
	Message           *ClaudeMessage           `json:"message,omitempty"`
	ToolUseResult     json.RawMessage          `json:"tool_use_result,omitempty"`
	Usage             *ClaudeUsage             `json:"usage,omitempty"`
	NumTurns          int                      `json:"num_turns,omitempty"`
	TotalCostUSD      float64                  `json:"total_cost_usd,omitempty"`
	Result            string                   `json:"result,omitempty"`
	IsError           bool                     `json:"is_error,omitempty"`
	StopReason        string                   `json:"stop_reason,omitempty"`
	DurationMillis    int64                    `json:"duration_ms,omitempty"`
	DurationAPIMillis int64                    `json:"duration_api_ms,omitempty"`
	ParentToolUseID   string                   `json:"parent_tool_use_id,omitempty"`
	UUID              string                   `json:"uuid,omitempty"`
	StructuredOutput  json.RawMessage          `json:"structured_output,omitempty"`
	ModelUsage        json.RawMessage          `json:"modelUsage,omitempty"`
	PermissionDenials []ClaudePermissionDenial `json:"permission_denials,omitempty"`
	TaskID            string                   `json:"task_id,omitempty"`
	ToolUseID         string                   `json:"tool_use_id,omitempty"`
	Description       string                   `json:"description,omitempty"`
	TaskType          string                   `json:"task_type,omitempty"`
	Prompt            string                   `json:"prompt,omitempty"`
	Status            string                   `json:"status,omitempty"`
	Summary           string                   `json:"summary,omitempty"`
	OutputFile        string                   `json:"output_file,omitempty"`
	LastToolName      string                   `json:"last_tool_name,omitempty"`
	RateLimitInfo     json.RawMessage          `json:"rate_limit_info,omitempty"`
	Tools             []string                 `json:"tools,omitempty"`
	MCPServers        json.RawMessage          `json:"mcp_servers,omitempty"`
	PermissionMode    string                   `json:"permissionMode,omitempty"`
	ClaudeCodeVersion string                   `json:"claude_code_version,omitempty"`
	Agents            []string                 `json:"agents,omitempty"`
	Skills            []string                 `json:"skills,omitempty"`
	SlashCommands     []string                 `json:"slash_commands,omitempty"`
	Plugins           json.RawMessage          `json:"plugins,omitempty"`
	Raw               json.RawMessage          `json:"-"`
}

func (i *ClaudeItem) UnmarshalJSON(raw []byte) error {
	type wire ClaudeItem
	var decoded wire
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*i = ClaudeItem(decoded)
	i.Raw = append(i.Raw[:0], raw...)
	return nil
}

type ClaudePermissionDenial struct {
	ToolName  string          `json:"tool_name"`
	ToolUseID string          `json:"tool_use_id"`
	ToolInput json.RawMessage `json:"tool_input"`
}

type ClaudeMessage struct {
	ID         string          `json:"id,omitempty"`
	Model      string          `json:"model,omitempty"`
	Role       string          `json:"role,omitempty"`
	Content    []ClaudeContent `json:"content"`
	Usage      *ClaudeUsage    `json:"usage,omitempty"`
	StopReason string          `json:"stop_reason,omitempty"`
}

type ClaudeContent struct {
	Type          string          `json:"type"`
	Text          string          `json:"text,omitempty"`
	Thinking      string          `json:"thinking,omitempty"`
	TextChars     int             `json:"text_chars,omitempty"`
	TextTruncated bool            `json:"text_truncated,omitempty"`
	Redacted      bool            `json:"redacted,omitempty"`
	ID            string          `json:"id,omitempty"`
	Name          string          `json:"name,omitempty"`
	Input         json.RawMessage `json:"input,omitempty"`
	ToolUseID     string          `json:"tool_use_id,omitempty"`
	IsError       bool            `json:"is_error,omitempty"`
	Content       json.RawMessage `json:"content,omitempty"`
	Raw           json.RawMessage `json:"-"`
}

func (c *ClaudeContent) UnmarshalJSON(raw []byte) error {
	type wire ClaudeContent
	var decoded wire
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*c = ClaudeContent(decoded)
	c.Raw = append(c.Raw[:0], raw...)
	return nil
}

type ClaudeUsage struct {
	InputTokens              int64 `json:"input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
}

var claudeEditTools = map[string]bool{
	"Edit": true, "MultiEdit": true, "Write": true, "NotebookEdit": true,
}

type claudeTodo struct {
	Content string `json:"content"`
	Status  string `json:"status"`
}

// claudeParseState pairs tool_use content blocks with their later
// tool_result by id, pointing back into the timeline being built.
type claudeParseState struct {
	d              *Digest
	ws             *workspace
	writeTracker   *fileWriteTracker
	pending        map[string]int // tool_use_id → timeline index
	lastText       string
	haveResult     bool
	validResult    bool
	seenLifecycle  bool
	semanticIssues []string
	// Usage summed across distinct assistant messages, for the no-result
	// fallback. Deduped by message id because a message's content blocks can
	// arrive on separate stream lines that repeat the same usage.
	// commandObservations holds the filesystem fingerprint taken when a shell
	// command STARTED, keyed by tool_use id. The before-state exists only while
	// the run is live, so it has to be captured here and compared when the
	// result arrives.
	commandObservations map[string]map[string]pathState
	usageSeen           map[string]bool
	haveUsage           bool
	summedUsage         TokenUsage
	finalized           bool
}

func (s *claudeParseState) addUsage(msgID string, u *ClaudeUsage) {
	if s.usageSeen[msgID] {
		return
	}
	s.usageSeen[msgID] = true
	s.haveUsage = true
	s.summedUsage.Input += u.InputTokens
	s.summedUsage.Output += u.OutputTokens
	s.summedUsage.CacheRead += u.CacheReadInputTokens
	s.summedUsage.CacheCreation += u.CacheCreationInputTokens
	s.summedUsage.Total = s.summedUsage.Input + s.summedUsage.Output
}

func parseClaude(r io.Reader, ws *workspace) (*Digest, error) {
	state := &claudeParseState{
		d:         &Digest{},
		ws:        ws,
		pending:   map[string]int{},
		usageSeen: map[string]bool{},
	}
	if err := forEachLine(r, func(n int, line []byte) {
		var item ClaudeItem
		if err := reasoning.UnmarshalProviderLine(line, &item); err != nil {
			state.d.countParseError(line)
			return
		}
		state.consume(&item, n, time.Time{})
	}); err != nil {
		return nil, fmt.Errorf("read claude output: %w", err)
	}
	if state.d.Metrics.ParseErrors > 0 {
		return state.finalize(), fmt.Errorf("parse claude output: %d malformed JSONL line(s)", state.d.Metrics.ParseErrors)
	}
	d := state.finalize()
	return d, state.semanticError()
}

// finalize applies the post-loop fallbacks (final message, killed-run token
// sum). Shared by the pull parser and the live StreamDigester.
func (s *claudeParseState) finalize() *Digest {
	if s.finalized {
		return s.d
	}
	s.finalized = true
	d := s.d
	if d.FinalMessage == "" {
		d.FinalMessage = s.lastText
	}
	if !s.haveResult && s.haveUsage {
		d.Metrics.Tokens = s.summedUsage
	}
	if !s.haveResult && d.Termination.ProviderReason == "" {
		d.Termination.Outcome = OutcomeError
		d.Termination.ProviderReason = "stream_ended_without_result"
		d.Termination.ErrorMessage = "stream ended without a result event"
	}
	if s.haveResult && !s.validResult {
		d.Termination.Outcome = OutcomeError
		d.Termination.ProviderReason = "invalid_result"
		d.Termination.ErrorMessage = strings.Join(s.semanticIssues, "; ")
	}
	if !s.seenLifecycle && d.Termination.Outcome == "" {
		d.Termination.Outcome = OutcomeError
		d.Termination.ProviderReason = "provider_stream_degraded"
		d.Termination.ErrorMessage = "stream has no recognizable lifecycle events"
	}
	pending := make([]int, 0, len(s.pending))
	for _, idx := range s.pending {
		pending = append(pending, idx)
	}
	sort.Ints(pending)
	// Work backward so dropping an event cannot invalidate an index still to do.
	for i := len(pending) - 1; i >= 0; i-- {
		idx := pending[i]
		if idx < 0 || idx >= len(d.Timeline) {
			continue
		}
		e := &d.Timeline[idx]
		if e.Status == "completed" || e.Status == "failed" || e.Status == "denied" {
			continue
		}
		before := *e
		e.Phase = "incomplete"
		e.Status = "incomplete"
		e.CompletedAt = nil
		if e.Kind == KindFileEdit {
			e.fileSnapshots = s.writeTracker.finish(e.ID, e.Files)
		}
		if e.Kind == KindCommand {
			// Mirrors codex.go's finalize path (codexItemEvent called with
			// completedLine 0): a command that never got a tool_result still
			// gets classified, with no trusted output and exitOK false so only
			// its read-only categories, never a state-changing one, can be
			// credited.
			classifyEventCommand(e, "", false, s.ws)
			applyRunState(d, e, "")
		}
		s.finishAppendedEvent(idx, before)
		d.Metrics.IncompleteToolCalls++
	}
	if d.Metrics.ProjectionTruncated && d.Termination.Outcome != OutcomeFailed {
		d.Termination.Outcome = OutcomeError
		d.Termination.ProviderReason = "projection_limit_exceeded"
		d.Termination.ErrorMessage = fmt.Sprintf("normalized projection exceeded limits; dropped %d event(s)", d.Metrics.DroppedEvents)
	}
	return d
}

func (s *claudeParseState) consume(item *ClaudeItem, lineNo int, at time.Time) {
	if item.SessionID != "" {
		s.d.SessionID = item.SessionID
	}
	switch item.Type {
	case "system":
		s.seenLifecycle = true
		s.consumeSystem(item, lineNo, at)
	case "assistant":
		if item.Message == nil {
			s.semanticIssues = append(s.semanticIssues, "assistant event is missing message")
			return
		}
		s.seenLifecycle = true
		if item.Message.Usage != nil {
			s.addUsage(item.Message.ID, item.Message.Usage)
		}
		if item.Message.Model != "" && s.d.Model == "" {
			s.d.Model = item.Message.Model
		}
		for _, content := range item.Message.Content {
			s.consumeAssistantContent(&content, item, lineNo, at)
		}
	case "user":
		if item.Message == nil {
			s.semanticIssues = append(s.semanticIssues, "user event is missing message")
			return
		}
		s.seenLifecycle = true
		for _, content := range item.Message.Content {
			switch content.Type {
			case "tool_result":
				s.consumeToolResult(&content, item.ToolUseResult, lineNo, at)
			case "text":
				s.appendUserInput(&content, item, lineNo, at)
			default:
				s.appendUnsupported("user."+content.Type, content.Raw, item, lineNo, at)
			}
		}
	case "result":
		s.consumeResult(item, lineNo, at)
	case "rate_limit_event":
		e := Event{
			Kind: KindRateLimit, ProviderEvent: item.Type, SessionID: item.SessionID,
			Phase: "observed", Status: "observed", Visibility: VisibilityDiagnostic,
			Details: capInput(item.RateLimitInfo), srcLine: lineNo, RawEventLines: rawEventLines(lineNo),
		}
		s.stamp(&e, at, false)
		s.d.appendEvent(e)
	default:
		s.appendUnsupported(item.Type, item.Raw, item, lineNo, at)
	}
}

func (s *claudeParseState) consumeAssistantContent(content *ClaudeContent, item *ClaudeItem, lineNo int, at time.Time) {
	e := Event{
		ID: content.ID, ParentID: item.ParentToolUseID, SessionID: item.SessionID,
		srcLine: lineNo, RawEventLines: rawEventLines(lineNo),
	}
	switch content.Type {
	case "text":
		if strings.TrimSpace(content.Text) == "" {
			return
		}
		e.Kind = KindMessage
		e.ProviderEvent = "assistant.text"
		e.Status = "completed"
		e.Text = content.Text
		s.lastText = content.Text
	case "thinking":
		if content.Redacted {
			e.Redacted = true
			e.TextChars = content.TextChars
			e.TextTruncated = content.TextTruncated
		} else if strings.TrimSpace(content.Thinking) == "" {
			// Reasoning redaction deliberately leaves an empty structural content
			// block. Retain its event and raw-line reference on re-digestion.
			e.Redacted = true
		} else {
			e.localReasoningText = content.Thinking
		}
		e.Kind = KindReasoning
		e.ProviderEvent = "assistant.thinking"
		e.Status = "completed"
	case "redacted_thinking":
		e.Kind = KindReasoning
		e.ProviderEvent = "assistant.redacted_thinking"
		e.Status = "completed"
		e.Redacted = true
	case "tool_use":
		e.ProviderEvent = "assistant.tool_use"
		e.Phase = "started"
		e.Status = "running"
		s.consumeToolUse(&e, content)
		if e.Kind == KindFileEdit {
			s.writeTracker.start(e.ID, e.Files)
		}
	default:
		s.appendUnsupported("assistant."+content.Type, content.Raw, item, lineNo, at)
		return
	}
	// Live stream: stamp observed_at directly (call start). The pull parser
	// passes a zero time and joins from the sidecar afterward instead.
	if !at.IsZero() {
		e.ObservedAt = &at
	}
	if !s.d.appendEvent(e) && e.ID != "" {
		delete(s.pending, e.ID)
	}
}

// consumeToolUse fills e from a claude tool_use content block and records its
// metrics, pairing it with a later tool_result via the pending map.
func (s *claudeParseState) consumeToolUse(e *Event, content *ClaudeContent) {
	var input struct {
		Command      string       `json:"command"`
		FilePath     string       `json:"file_path"`
		NotebookPath string       `json:"notebook_path"`
		Path         string       `json:"path"`
		Query        string       `json:"query"`
		URL          string       `json:"url"`
		Prompt       string       `json:"prompt"`
		Todos        []claudeTodo `json:"todos"`
	}
	// encoding/json fills the fields it managed to decode before it reports a
	// type error, so discarding the error leaves a struct that is part real
	// input and part zero value. A Bash command taken from such a struct is a
	// fragment of a payload this parser did not understand, and crediting a
	// delete from it invents the very act the malformed field should have made
	// us doubt.
	inputDecoded := json.Unmarshal(content.Input, &input) == nil
	if fields, ok := decoderMatchedJSONFieldValues(content.Input, "command"); ok && len(fields) > 1 {
		inputDecoded = false
	}

	e.Tool = content.Name
	setEventInput(e, content.Input)
	e.inputFilePath = input.FilePath
	if e.inputFilePath == "" {
		e.inputFilePath = input.NotebookPath
	}
	e.inputPath = input.Path
	s.d.Metrics.countTool(content.Name)
	switch {
	case content.Name == "Bash":
		e.Kind = KindCommand
		if inputDecoded {
			e.Command = strings.Trim(input.Command, " \t\n")
		}
		s.observeCommandStart(content.ID, e.Command)
		s.d.Metrics.Commands++
	case claudeEditTools[content.Name]:
		e.Kind = KindFileEdit
		// NotebookEdit reports notebook_path, not file_path. Only credit a
		// path the workspace can relativize, so an out-of-workspace edit
		// never keys the files summary by an absolute path.
		if e.inputFilePath != "" {
			if rel, ok := normalizeWorkspacePath(e.inputFilePath, s.ws); ok {
				e.Files = []string{rel}
			}
		}
		s.d.Metrics.Edits++
	case content.Name == "TodoWrite":
		e.Kind = KindTodo
		e.Text = renderChecklist(input.Todos,
			func(t claudeTodo) string { return t.Content },
			func(t claudeTodo) bool { return t.Status == "completed" })
	case content.Name == "WebSearch" || content.Name == "WebFetch":
		e.Kind = KindWebSearch
		e.Query = input.Query
		if e.Query == "" {
			e.Query = input.URL
		}
		if e.Query == "" {
			e.Query = input.Prompt
		}
	case content.Name == "Agent" || content.Name == "Task":
		e.Kind = KindTask
	default:
		e.Kind = KindToolCall
	}
	if content.ID != "" {
		s.pending[content.ID] = len(s.d.Timeline)
	}
}

// observeCommandStart fingerprints the paths a command names, before it runs.
func (s *claudeParseState) observeCommandStart(id, command string) {
	if s == nil || id == "" || command == "" {
		return
	}
	before := observePathStates(s.ws, commandObservationCandidates(command))
	if len(before) == 0 {
		return
	}
	if s.commandObservations == nil {
		s.commandObservations = map[string]map[string]pathState{}
	}
	s.commandObservations[id] = before
}

// observeCommandEnd re-fingerprints those paths and records what actually
// changed. The result is evidence rather than prediction, so an event carrying
// it can say what the command did instead of what its text suggested.
func (s *claudeParseState) observeCommandEnd(id string, e *Event) {
	if s == nil || id == "" || e == nil {
		return
	}
	before, ok := s.commandObservations[id]
	if !ok {
		return
	}
	delete(s.commandObservations, id)
	e.ObservationStatus = observationStatusObserved
	after := observePathStates(s.ws, sortedObservedPaths(before))
	for _, effect := range diffPathStates(before, after) {
		e.ObservedEffects = append(e.ObservedEffects, ObservedEffect{Path: effect.path, Kind: effect.kind})
	}
}

func (s *claudeParseState) consumeToolResult(content *ClaudeContent, toolUseResult json.RawMessage, lineNo int, at time.Time) {
	idx, ok := s.pending[content.ToolUseID]
	if !ok {
		s.d.Metrics.OrphanedToolResults++
		e := Event{
			Kind: KindToolResult, ProviderEvent: "user.tool_result", ID: content.ToolUseID,
			Phase: "completed", Status: "orphaned", IsError: content.IsError,
			srcLine: lineNo, completedLine: lineNo, RawEventLines: rawEventLines(lineNo),
		}
		outputText := ToolResultText(content.Content)
		setEventOutput(&e, outputText)
		if len(toolUseResult) > 0 {
			setEventResult(&e, toolUseResult)
		} else {
			setEventResult(&e, content.Content)
		}
		s.stamp(&e, at, true)
		s.d.appendEvent(e)
		return
	}
	delete(s.pending, content.ToolUseID)
	e := &s.d.Timeline[idx]
	before := *e
	e.completedLine = lineNo
	e.RawEventLines = rawEventLines(e.srcLine, lineNo)
	e.Phase = "completed"
	e.Status = "completed"
	if !at.IsZero() {
		completedAt := at
		e.CompletedAt = &completedAt
	}

	e.IsError = content.IsError
	outputText := ToolResultText(content.Content)
	setEventOutput(e, outputText)
	if len(toolUseResult) > 0 {
		setEventResult(e, toolUseResult)
	} else {
		setEventResult(e, content.Content)
	}
	if e.IsError {
		e.Status = "failed"
		e.ErrorMessage = outputText
	}

	if e.Kind == KindCommand {
		if code, ok := ExitCodeFromToolUseResult(toolUseResult); ok {
			e.ExitCode = &code
		}
		// Look before classifying: what the filesystem shows outranks what the
		// command text suggests.
		s.observeCommandEnd(content.ToolUseID, e)
	}
	if e.Kind == KindFileEdit {
		e.fileSnapshots = s.writeTracker.finish(e.ID, e.Files)
	}

	bounded := boundedOutput(outputText)
	if e.Kind == KindCommand {
		// is_error is optional in the stream and defaults to false, so a tool
		// result can carry a nonzero exit_code without ever setting it. The
		// exit code, when present, is the more direct proof.
		//
		// A result that carries an outcome this parser cannot read is a third
		// case, and it must not collapse into either of the other two. Absent
		// is not the same as unreadable: plenty of results legitimately carry
		// no exit code at all, and treating those as failures would silently
		// drop every state-changing fact from an ordinary successful command.
		// An outcome that IS present but malformed proves nothing, so it fails
		// closed rather than being read as the zero it never decoded to.
		exitOK := !e.IsError && (e.ExitCode == nil || *e.ExitCode == 0) &&
			!toolUseResultOutcomeUnreadable(toolUseResult)
		// Retrieval inference stays success-only, but a command is classified
		// whether or not it succeeded: the per-category gates decide what a
		// failed command may still be credited with.
		if exitOK {
			applyStep(e, retrievalFromCommand(e.Command, bounded, s.ws))
		}
		classifyEventCommand(e, bounded, exitOK, s.ws)
		applyRunState(s.d, e, bounded)
		// e was appended before its completion and classification existed.
		// Replace its original projection charge with the normalized completed
		// event, applying the same admission limit appendEvent uses.
		s.finishAppendedEvent(idx, before)
		return
	}
	if e.IsError {
		return
	}
	switch {
	case e.Tool == "Read" && e.inputFilePath != "":
		applyStep(e, inferReadStep(e.inputFilePath, bounded, s.ws))
	case e.Tool == "Grep":
		applyStep(e, inferSearchFileStepFromPath(e.inputPath, bounded, s.ws))
	}
}

// finishAppendedEvent accounts for a Claude event that was admitted when its
// tool_use started and then replaced in place. If the normalized
// replacement no longer fits, remove it exactly as appendEvent would have
// rejected an event that arrived fully formed; retaining an over-budget
// classification would make the final digest impossible to marshal.
func (s *claudeParseState) finishAppendedEvent(index int, before Event) {
	event := &s.d.Timeline[index]
	normalizeEvent(event)
	beforeBytes, beforeErr := eventProjectionBytes(before)
	afterBytes, afterErr := eventProjectionBytes(*event)
	base := s.d.projectionBytes - beforeBytes
	if beforeErr == nil && afterErr == nil && base >= 0 && afterBytes <= s.d.projectionLimit()-base {
		s.d.projectionBytes = base + afterBytes
		return
	}

	copy(s.d.Timeline[index:], s.d.Timeline[index+1:])
	s.d.Timeline[len(s.d.Timeline)-1] = Event{}
	s.d.Timeline = s.d.Timeline[:len(s.d.Timeline)-1]
	if beforeErr == nil && beforeBytes <= s.d.projectionBytes {
		s.d.projectionBytes -= beforeBytes
	} else {
		s.d.projectionBytes = 0
	}
	for id, pendingIndex := range s.pending {
		if pendingIndex > index {
			s.pending[id] = pendingIndex - 1
		}
	}
	s.d.Metrics.DroppedEvents++
	s.d.Metrics.ProjectionTruncated = true
}

func (s *claudeParseState) stamp(event *Event, at time.Time, completed bool) {
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

func (s *claudeParseState) consumeSystem(item *ClaudeItem, lineNo int, at time.Time) {
	switch item.Subtype {
	case "init":
		if item.Model != "" {
			s.d.Model = item.Model
		}
		s.d.Runtime = RuntimeInfo{
			Version: item.ClaudeCodeVersion, PermissionMode: item.PermissionMode,
			Tools: item.Tools, Agents: item.Agents, Skills: item.Skills,
			Commands: item.SlashCommands, MCPServers: capInput(item.MCPServers), Plugins: capInput(item.Plugins),
		}
		details, _ := json.Marshal(s.d.Runtime)
		e := Event{
			Kind: KindRuntime, ProviderEvent: "system.init", SessionID: item.SessionID,
			Phase: "configured", Status: "completed", Visibility: VisibilityDiagnostic,
			Details: capInput(details), srcLine: lineNo, RawEventLines: rawEventLines(lineNo),
		}
		s.stamp(&e, at, false)
		s.d.appendEvent(e)
	case "task_started", "task_progress", "task_notification":
		phase := strings.TrimPrefix(item.Subtype, "task_")
		status := item.Status
		if status == "" {
			if phase == "notification" {
				status = "completed"
			} else {
				status = "running"
			}
		}
		e := Event{
			Kind: KindTask, ProviderEvent: "system." + item.Subtype,
			ID: firstNonEmpty(item.TaskID, item.ToolUseID), ParentID: item.ToolUseID,
			TaskID: item.TaskID, SessionID: item.SessionID,
			Phase: phase, Status: status, Visibility: VisibilityDiagnostic,
			Tool: item.LastToolName, Text: firstNonEmpty(item.Description, item.Summary),
			srcLine: lineNo, RawEventLines: rawEventLines(lineNo), Details: capInput(item.Raw),
		}
		e.IsError = status == "failed" || status == "denied"
		if item.Prompt != "" {
			setEventInput(&e, json.RawMessage(strconv.Quote(item.Prompt)))
		}
		s.stamp(&e, at, status == "completed" || status == "failed")
		s.d.appendEvent(e)
	default:
		s.appendUnsupported("system."+item.Subtype, item.Raw, item, lineNo, at)
	}
}

func (s *claudeParseState) consumeResult(item *ClaudeItem, lineNo int, at time.Time) {
	s.haveResult = true
	s.seenLifecycle = true
	if item.Usage != nil {
		s.d.Metrics.Tokens = claudeTokens(item.Usage)
	}
	s.d.Metrics.Turns = item.NumTurns
	s.d.Metrics.CostUSD = item.TotalCostUSD
	if strings.TrimSpace(item.Result) != "" {
		s.d.FinalMessage = item.Result
	}
	providerReason := item.StopReason
	if providerReason == "" {
		providerReason = item.Subtype
	}
	outcome := OutcomeCompleted
	switch {
	case item.IsError || (item.Subtype != "" && item.Subtype != "success"):
		outcome = OutcomeFailed
		s.validResult = true
	case item.Subtype == "success":
		s.validResult = true
	default:
		outcome = OutcomeError
		s.semanticIssues = append(s.semanticIssues, "result event is missing a recognized subtype")
	}
	s.d.Termination = Termination{
		Outcome: outcome, ProviderReason: providerReason, ProviderSubtype: item.Subtype,
	}
	if item.IsError {
		s.d.Termination.ErrorMessage = item.Result
	}
	if len(item.StructuredOutput) > 0 && string(item.StructuredOutput) != "null" {
		s.d.StructuredOutput = capInput(item.StructuredOutput)
		e := Event{
			Kind: KindStructuredOutput, ProviderEvent: "result.structured_output",
			SessionID: item.SessionID, Phase: "completed", Status: outcome,
			Visibility: VisibilityDiagnostic, Details: capInput(item.StructuredOutput),
			srcLine: lineNo, completedLine: lineNo, RawEventLines: rawEventLines(lineNo),
		}
		s.stamp(&e, at, true)
		s.d.appendEvent(e)
	}
	if len(item.ModelUsage) > 0 && string(item.ModelUsage) != "null" {
		s.d.ModelUsage = capInput(item.ModelUsage)
	}
	for _, denial := range item.PermissionDenials {
		e := Event{
			Kind: KindPermission, ProviderEvent: "result.permission_denial",
			ID: denial.ToolUseID, SessionID: item.SessionID, Tool: denial.ToolName,
			Phase: "completed", Status: "denied", IsError: true,
			srcLine: lineNo, completedLine: lineNo, RawEventLines: rawEventLines(lineNo),
		}
		setEventInput(&e, denial.ToolInput)
		s.stamp(&e, at, true)
		s.d.appendEvent(e)
	}
}

func (s *claudeParseState) semanticError() error {
	s.finalize()
	if err := s.writeTracker.evidenceError(s.d); err != nil {
		s.d.Termination.Outcome = OutcomeDegraded
		s.d.Termination.ProviderReason = "write_evidence_incomplete"
		s.d.Termination.ErrorMessage = err.Error()
		return fmt.Errorf("capture write evidence: %w", err)
	}
	if err := unsupportedEventsError(s.d); err != nil {
		if s.d.Termination.Outcome == OutcomeCompleted {
			s.d.Termination.Outcome = OutcomeDegraded
			s.d.Termination.ProviderReason = "unsupported_provider_events"
			s.d.Termination.ErrorMessage = err.Error()
		}
		return err
	}
	if s.d.Termination.Outcome == OutcomeError {
		return fmt.Errorf("validate claude stream: %s", firstNonEmpty(s.d.Termination.ErrorMessage, s.d.Termination.ProviderReason))
	}
	return nil
}

func (s *claudeParseState) appendUserInput(content *ClaudeContent, item *ClaudeItem, lineNo int, at time.Time) {
	if strings.TrimSpace(content.Text) == "" {
		return
	}
	e := Event{
		Kind: KindUserInput, ProviderEvent: "user.text", ParentID: item.ParentToolUseID,
		SessionID: item.SessionID, Phase: "observed", Status: "completed", Text: content.Text,
		srcLine: lineNo, RawEventLines: rawEventLines(lineNo),
	}
	s.stamp(&e, at, false)
	s.d.appendEvent(e)
}

func (s *claudeParseState) appendUnsupported(name string, raw json.RawMessage, item *ClaudeItem, lineNo int, at time.Time) {
	s.d.countUnsupported(name)
	e := Event{
		Kind: KindUnsupported, ProviderEvent: name, ParentID: item.ParentToolUseID,
		SessionID: item.SessionID, Phase: "observed", Status: "unsupported",
		Visibility: VisibilityDiagnostic, Details: capInput(raw),
		srcLine: lineNo, RawEventLines: rawEventLines(lineNo),
	}
	s.stamp(&e, at, false)
	s.d.appendEvent(e)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func claudeTokens(usage *ClaudeUsage) TokenUsage {
	return TokenUsage{
		Input:         usage.InputTokens,
		Output:        usage.OutputTokens,
		CacheRead:     usage.CacheReadInputTokens,
		CacheCreation: usage.CacheCreationInputTokens,
		Total:         usage.InputTokens + usage.OutputTokens,
	}
}

// decoderMatchedJSONFieldValues returns every object key encoding/json can
// bind to name. Raw validation must use the decoder's case-insensitive fallback
// too, or a differently cased key can overwrite the field that was checked.
func decoderMatchedJSONFieldValues(raw json.RawMessage, name string) ([]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, false
	}
	var values []json.RawMessage
	for key, value := range fields {
		if strings.EqualFold(key, name) {
			values = append(values, value)
		}
	}
	return values, true
}

// ExitCodeFromToolUseResult pulls the bash exit code out of a claude
// tool_use_result payload. Shared with the live tracing mapper.
// toolUseResultOutcomeUnreadable reports whether a tool result claims to carry
// an outcome that this parser could not decode. ExitCodeFromToolUseResult
// answers "no usable exit code" for both a missing field and a malformed one,
// and those two mean opposite things to a caller deciding whether a command
// succeeded, so the distinction is drawn here instead.
func toolUseResultOutcomeUnreadable(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	decoded := 0
	first := 0
	for _, name := range []string{"exit_code", "exitCode"} {
		values, ok := decoderMatchedJSONFieldValues(raw, name)
		if !ok {
			// The payload is not even an object, so whatever outcome it meant to
			// report is unreadable rather than absent.
			return true
		}
		for _, value := range values {
			var code *int
			// A JSON null unmarshals into *int without error and leaves the
			// pointer nil. The field is present and claims to report an outcome,
			// so a null is a value this parser could not read - not an absent one.
			if json.Unmarshal(value, &code) != nil || code == nil {
				return true
			}
			if decoded > 0 && *code != first {
				// The two spellings of the same field contradict each other, and
				// nothing in the stream says which one to believe.
				return true
			}
			decoded++
			first = *code
		}
	}
	return false
}

func ExitCodeFromToolUseResult(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var payload struct {
		ExitCode  *int `json:"exit_code"`
		ExitCode2 *int `json:"exitCode"`
	}
	if json.Unmarshal(raw, &payload) != nil {
		return 0, false
	}
	if payload.ExitCode != nil {
		return *payload.ExitCode, true
	}
	if payload.ExitCode2 != nil {
		return *payload.ExitCode2, true
	}
	return 0, false
}

// ToolResultText extracts human-readable text from polymorphic tool_result
// content shapes such as strings, blocks, and nested dictionaries. It is
// shared with the live tracing mapper.
func ToolResultText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return ""
	}
	return textFromValue(value, 0)
}

var textKeys = []string{"content", "text", "result", "output", "stdout", "stderr", "message"}

func textFromValue(value any, depth int) string {
	if value == nil || depth > 8 {
		return ""
	}
	switch v := value.(type) {
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case []any:
		var parts []string
		for _, item := range v {
			if part := strings.TrimSpace(textFromValue(item, depth+1)); part != "" {
				parts = append(parts, part)
			}
		}
		return strings.Join(parts, "\n")
	case map[string]any:
		var parts []string
		for _, key := range textKeys {
			if item, ok := v[key]; ok {
				if part := strings.TrimSpace(textFromValue(item, depth+1)); part != "" {
					parts = append(parts, part)
				}
			}
		}
		return strings.Join(parts, "\n")
	default:
		return ""
	}
}
