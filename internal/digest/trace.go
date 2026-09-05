package digest

// This file conservatively infers which files and line spans an agent looked
// at, grounded in tool inputs and command output. When unsure, it claims
// nothing.

import (
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

// These limits bound the amount of command output examined for retrieval
// evidence and keep tokenization work predictable.
const (
	maxCommandOutputChars       = 120_000
	maxCommandTokenizationChars = 4_096
	maxPlainPathLineChars       = 2_048
)

var (
	lineArrowRe           = regexp.MustCompile(`(?m)^\s*(\d+)\s*→`)
	numberedLineRe        = regexp.MustCompile(`(?m)^\s*(\d+)(?:\t| {2,})`)
	lineArrowContentRe    = regexp.MustCompile(`^\s*(\d+)\s*→(.*)$`)
	numberedLineContentRe = regexp.MustCompile(`^\s*(\d+)(?:\t| {2,})(.*)$`)
	sedRangeRe            = regexp.MustCompile(`^(\d+)\s*,\s*(\d+)\s*p$`)
	pathWithLineRe        = regexp.MustCompile(`^(.+?):(\d+)(?::.*)?$`)
	pathLikeRe            = regexp.MustCompile(`(?:/|\.{0,2}/)?[A-Za-z0-9_.@%+=~:/-]+\.[A-Za-z0-9_+-]+`)
)

var knownRootFilenames = map[string]bool{
	"BUILD": true, "BUILD.bazel": true, "Brewfile": true, "CMakeLists.txt": true,
	"CONTRIBUTING": true, "Dockerfile": true, "Gemfile": true, "Jenkinsfile": true, "LICENSE": true,
	"Makefile": true, "NOTICE": true, "Procfile": true, "README": true,
	"Rakefile": true, "Vagrantfile": true, "WORKSPACE": true, "WORKSPACE.bazel": true,
}

var knownRootPrefixes = []string{"Dockerfile.", "README."}

// step is one inferred retrieval: files looked at, with optional line spans.
type step struct {
	files      []string
	spans      map[string][]Span
	readRanges map[string][]ReadRange
}

// workspace resolves agent-reported paths to repo-relative ones using only
// recorded path spellings. The macOS /private variants cover the stable alias
// reported by different providers without consulting the live filesystem.
type workspace struct {
	variants []string
	root     string
	// controlPrefix is the caller-declared control-plane directory, relative to
	// the root. Empty — the default — means control.access is never credited.
	controlPrefix string
}

func newWorkspace(dir string) *workspace {
	w := &workspace{}
	if strings.TrimSpace(dir) == "" {
		return w
	}
	logical := canonicalWorkspacePath(dir)
	root := filepath.Clean(dir)
	if isPortableAbsolute(logical) && !filepath.IsAbs(dir) {
		// Preserve a recorded path from another OS for offline re-digestion.
		root = filepath.Clean(filepath.FromSlash(logical))
	}
	w.root = root
	seen := map[string]bool{}
	add := func(p string) {
		p = canonicalWorkspacePath(p)
		if p != "" && p != "/" && p != "." && !seen[p] {
			seen[p] = true
			w.variants = append(w.variants, p)
		}
	}
	add(root)
	add(logical)
	for _, v := range append([]string(nil), w.variants...) {
		add(togglePrivatePrefix(v))
	}
	return w
}

func togglePrivatePrefix(p string) string {
	if rest, ok := strings.CutPrefix(p, "/private/"); ok {
		return "/" + rest
	}
	if strings.HasPrefix(p, "/") {
		return "/private" + p
	}
	return p
}

func canonicalWorkspacePath(value string) string {
	return path.Clean(strings.ReplaceAll(filepath.ToSlash(value), `\`, "/"))
}

func isPortableAbsolute(value string) bool {
	if strings.HasPrefix(value, "/") {
		return true
	}
	return len(value) >= 3 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) && value[1] == ':' && value[2] == '/'
}

// rel converts p to a workspace-relative posix path. The second return is
// false when p is absolute but outside the workspace (p returned unchanged).
func (w *workspace) rel(p string) (string, bool) {
	if hasParentPathComponent(p) {
		return p, false
	}
	canonical := canonicalWorkspacePath(p)
	if !filepath.IsAbs(p) && !isPortableAbsolute(canonical) {
		return path.Clean(canonical), true
	}
	// newWorkspace already stores the /private-toggled form of every variant,
	// so matching clean against the variants suffices — no candidate-side
	// toggle needed.
	clean := canonical
	for _, v := range w.variants {
		prefix := v + "/"
		matched := strings.HasPrefix(clean, prefix)
		if runtime.GOOS == "windows" {
			matched = strings.HasPrefix(strings.ToLower(clean), strings.ToLower(prefix))
		}
		if matched {
			return clean[len(prefix):], true
		}
	}
	return p, false
}

func hasParentPathComponent(value string) bool {
	for _, component := range strings.Split(strings.ReplaceAll(value, `\`, "/"), "/") {
		if component == ".." {
			return true
		}
	}
	return false
}

// normalizeWorkspacePath admits only paths inside the recorded workspace. It
// accepts ordinary relative tool paths, but rejects traversal such as ../x and
// absolute paths that workspace.rel could not relativize.
func normalizeWorkspacePath(value string, ws *workspace) (string, bool) {
	if value == "" {
		return "", false
	}
	normalized, ok := ws.rel(value)
	if !ok {
		return "", false
	}
	normalized = path.Clean(filepath.ToSlash(normalized))
	if normalized == "" || normalized == "." || normalized == ".." || strings.HasPrefix(normalized, "/") {
		return "", false
	}
	if strings.HasPrefix(normalized, "../") || strings.Contains(normalized, "/../") {
		return "", false
	}
	return normalized, true
}

// inferReadSpan extracts the line range covered by Read-style output: `N→...`
// arrow markers, or numeric prefixes that form a strict +1 line counter
// (rejecting timestamped logs and data tables).
func inferReadSpan(text string) (Span, bool) {
	nums := captureInts(lineArrowRe, text)
	if len(nums) == 0 {
		nums = numberedLinePrefixes(text)
		if !looksLikeLineNumbering(nums) {
			return Span{}, false
		}
	}
	if len(nums) == 0 {
		return Span{}, false
	}
	lo, hi := nums[0], nums[0]
	for _, n := range nums[1:] {
		if n < lo {
			lo = n
		}
		if n > hi {
			hi = n
		}
	}
	return Span{Start: lo, End: hi}, true
}

func captureInts(re *regexp.Regexp, text string) []int {
	var nums []int
	for _, m := range re.FindAllStringSubmatch(text, -1) {
		if n, err := strconv.Atoi(m[1]); err == nil {
			nums = append(nums, n)
		}
	}
	return nums
}

// numberedLinePrefixes finds `N<tab-or-spaces>content` line-number prefixes.
// RE2 has no lookahead, so the "content follows" check is done on match
// indices without swallowing the next line's number.
func numberedLinePrefixes(text string) []int {
	var nums []int
	for _, loc := range numberedLineRe.FindAllStringSubmatchIndex(text, -1) {
		if strings.TrimSpace(text[loc[1]:]) == "" {
			continue // nothing but whitespace to end of text
		}
		if n, err := strconv.Atoi(text[loc[2]:loc[3]]); err == nil {
			nums = append(nums, n)
		}
	}
	return nums
}

func looksLikeLineNumbering(nums []int) bool {
	if len(nums) == 0 {
		return false
	}
	if len(nums) == 1 {
		return nums[0] == 1
	}
	for i := 1; i < len(nums); i++ {
		if nums[i]-nums[i-1] != 1 {
			return false
		}
	}
	return true
}

func looksLikeRepoFilename(name string) bool {
	if name == "" {
		return false
	}
	if knownRootFilenames[name] {
		return true
	}
	for _, prefix := range knownRootPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	dot := strings.LastIndexByte(name, '.')
	if dot < 0 {
		return false
	}
	ext := strings.NewReplacer("_", "", "-", "", "+", "").Replace(name[dot+1:])
	if ext == "" || !isAlnum(ext) {
		return false
	}
	return strings.ContainsFunc(name, isAlphaRune)
}

func isAlnum(s string) bool {
	for _, r := range s {
		if !isAlphaRune(r) && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func isAlphaRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

func looksLikePathHead(value string) bool {
	if value == "" || strings.Contains(value, "=") {
		return false
	}
	name := value
	if idx := strings.LastIndexByte(value, '/'); idx >= 0 {
		name = value[idx+1:]
	}
	return looksLikeRepoFilename(name)
}

func looksLikePlainPath(value string) bool {
	if value == "" || len(value) > maxPlainPathLineChars {
		return false
	}
	if strings.ContainsAny(value, " \t\n\v\f\r") || strings.Contains(value, "=") {
		return false
	}
	return looksLikePathHead(value)
}

func findPathLikeToken(command string) string {
	for _, m := range pathLikeRe.FindAllString(command, -1) {
		candidate := strings.Trim(m, `'"`)
		if strings.Contains(candidate, "=") || strings.HasSuffix(candidate, ".exe") {
			continue
		}
		return candidate
	}
	return ""
}

// stripPathDecoration removes quotes, file:// prefixes, and :line / #L
// suffixes, returning the bare path and any line number found.
func stripPathDecoration(value string) (string, int) {
	candidate := strings.Trim(strings.TrimSpace(value), "'\"`")
	candidate = strings.TrimPrefix(candidate, "file://")
	line := 0
	if m := pathWithLineRe.FindStringSubmatch(candidate); m != nil && looksLikePathHead(strings.TrimSpace(m[1])) {
		candidate = strings.TrimSpace(m[1])
		line, _ = strconv.Atoi(m[2])
	}
	if before, after, found := strings.Cut(candidate, "#L"); found {
		numPart, _, _ := strings.Cut(after, "-")
		if n, err := strconv.Atoi(strings.TrimSpace(numPart)); err == nil && n > 0 {
			candidate = before
			line = n
		}
	}
	return candidate, line
}

// normalizeInferredFilePath validates and workspace-relativizes a path-ish
// token. Returns "" when the token should not be credited as a file.
func normalizeInferredFilePath(value string, ws *workspace) string {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return ""
	}
	candidate, _ := stripPathDecoration(raw)
	normalized, ok := normalizeWorkspacePath(candidate, ws)
	if !ok {
		return ""
	}
	if !looksLikePlainPath(normalized) && !looksLikePathHead(normalized) {
		return ""
	}
	return normalized
}

func normalizeCommandPathToken(token string, ws *workspace) string {
	if token == "" || strings.HasPrefix(token, "-") {
		return ""
	}
	switch token {
	case "|", "&&", "||", ";", "<", ">", ">>":
		return ""
	}
	if strings.ContainsAny(token, `*?[]{}\|`) {
		return ""
	}
	if strings.HasPrefix(token, "http://") || strings.HasPrefix(token, "https://") {
		return ""
	}
	if strings.HasSuffix(token, "p") && strings.Contains(token, ",") {
		return "" // sed range like 10,20p
	}
	return normalizeInferredFilePath(token, ws)
}

func pathTokenFromTokens(tokens []string, ws *workspace, reverse bool) string {
	for i := range tokens {
		idx := i
		if reverse {
			idx = len(tokens) - 1 - i
		}
		if normalized := normalizeCommandPathToken(tokens[idx], ws); normalized != "" {
			return normalized
		}
	}
	return ""
}

func sedRangeFromTokens(tokens []string) (Span, bool) {
	for _, token := range tokens {
		m := sedRangeRe.FindStringSubmatch(strings.Trim(token, "'\""))
		if m == nil {
			continue
		}
		start, _ := strconv.Atoi(m[1])
		end, _ := strconv.Atoi(m[2])
		if start <= 0 || end <= 0 {
			return Span{}, false
		}
		return Span{Start: min(start, end), End: max(start, end)}, true
	}
	return Span{}, false
}

func headCountFromTokens(tokens []string) int {
	for i, token := range tokens {
		if token == "-n" && i+1 < len(tokens) {
			if n, err := strconv.Atoi(strings.TrimSpace(tokens[i+1])); err == nil {
				return n
			}
			return 0
		}
		if rest, ok := strings.CutPrefix(token, "--lines="); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(rest)); err == nil {
				return n
			}
			return 0
		}
		if strings.HasPrefix(token, "-") && len(token) > 1 {
			if n, err := strconv.Atoi(token[1:]); err == nil {
				return n
			}
		}
	}
	return 0
}

func firstPipeIndexAfter(tokens []string, start int) int {
	if i := slices.Index(tokens[start:], "|"); i >= 0 {
		return start + i
	}
	return len(tokens)
}

func hasRedirectionToken(tokens []string) bool {
	for _, token := range tokens {
		if strings.Contains(token, ">") || strings.HasPrefix(token, "<") {
			return true
		}
	}
	return false
}

func fileBeforePipe(tokens []string, ws *workspace) string {
	beforePipe := tokens
	if idx := firstPipeIndexAfter(tokens, 0); idx < len(tokens) {
		beforePipe = tokens[:idx]
	}
	return pathTokenFromTokens(beforePipe, ws, true)
}

func fileAfterCommand(tokens []string, commandWord string, ws *workspace) string {
	start := -1
	for i, token := range tokens {
		if token == commandWord {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return ""
	}
	stop := firstPipeIndexAfter(tokens, start)
	return pathTokenFromTokens(tokens[start:stop], ws, true)
}

var readLikeWords = []string{"sed", "cat", "head", "tail", "nl"}

func hasGrepLikeCommand(rawCommand string, tokens []string) bool {
	return slices.Contains(tokens, "rg") || slices.Contains(tokens, "grep") ||
		commandHasWord(rawCommand, "rg") || commandHasWord(rawCommand, "grep")
}

// readSegmentStep infers file+span retrieval from one read-like command
// segment (sed -n 'A,Bp' file, head -n N file, cat/tail/nl file).
func readSegmentStep(segment, outputText string, ws *workspace) *step {
	if strings.TrimSpace(outputText) == "" {
		return nil
	}
	tokens := tokensForSegment(segment)
	if len(tokens) == 0 {
		return untokenizedReadStep(segment, outputText, ws)
	}
	if readSegmentIsInformational(tokens) {
		return nil
	}
	if s := sedReadStep(tokens, ws); s != nil {
		return s
	}
	if s := headReadStep(tokens, ws); s != nil {
		return s
	}
	return catLikeReadStep(tokens, outputText, ws)
}

func readSegmentIsInformational(tokens []string) bool {
	for len(tokens) > 0 {
		end := firstPipeIndexAfter(tokens, 0)
		stage := tokens[:end]
		for _, word := range readLikeWords {
			if shellStageStartsWith(stage, word) {
				index := slices.IndexFunc(stage, func(token string) bool {
					return path.Base(strings.Trim(token, "()")) == word
				})
				if index >= 0 && execCommandAssertsNoChange(execCommand{word: word, args: fsOwnArgs(stage[index+1:])}) {
					return true
				}
			}
		}
		if end == len(tokens) {
			break
		}
		tokens = tokens[end+1:]
	}
	return false
}

// untokenizedReadStep handles a segment the tokenizer couldn't parse.
// tokensForSegment yields nothing both when the segment is too long to
// tokenize and when a quote is unbalanced; only the former warrants the cheap
// path-like scan — guessing on an unbalanced-quote fragment (e.g. `sys.exit(0)"`
// from split quoted code) credits phantom reads.
func untokenizedReadStep(segment, outputText string, ws *workspace) *step {
	if len(segment) <= maxCommandTokenizationChars {
		return nil
	}
	pathToken := findPathLikeToken(segment)
	if pathToken == "" {
		return nil
	}
	filePath := normalizeInferredFilePath(pathToken, ws)
	if filePath == "" {
		return nil
	}
	return fileSpanStep(filePath, outputText)
}

func sedReadStep(tokens []string, ws *workspace) *step {
	if !shellStageStartsWith(tokens, "sed") {
		return nil
	}
	sedRange, haveRange := sedRangeFromTokens(tokens)
	var filePath string
	if pipeIdx := firstPipeIndexAfter(tokens, 0); pipeIdx < len(tokens) {
		// Only credit the file left of the pipe when a read-like command
		// produced the piped text; `python x.py | sed -n '1,50p'` filters
		// program output, not file content.
		readLike := false
		for _, token := range tokens[:pipeIdx] {
			if slices.Contains(readLikeWords, token) {
				readLike = true
				break
			}
		}
		if readLike {
			filePath = fileBeforePipe(tokens, ws)
		}
	} else {
		filePath = fileAfterCommand(tokens, "sed", ws)
	}
	if haveRange && filePath != "" {
		return &step{files: []string{filePath}, spans: map[string][]Span{filePath: {sedRange}}}
	}
	return nil
}

func headReadStep(tokens []string, ws *workspace) *step {
	if !shellStageStartsWith(tokens, "head") {
		return nil
	}
	count := headCountFromTokens(tokens)
	filePath := fileAfterCommand(tokens, "head", ws)
	if count > 0 && filePath != "" {
		return &step{files: []string{filePath}, spans: map[string][]Span{filePath: {{Start: 1, End: count}}}}
	}
	return nil
}

func catLikeReadStep(tokens []string, outputText string, ws *workspace) *step {
	for _, commandWord := range []string{"nl", "cat", "tail"} {
		if !shellStageStartsWith(tokens, commandWord) || hasRedirectionToken(tokens) {
			continue
		}
		filePath := fileAfterCommand(tokens, commandWord, ws)
		if filePath == "" {
			continue
		}
		return fileSpanStep(filePath, outputText)
	}
	return nil
}

// fileSpanStep credits a file plus, when detectable, the line span its output
// covers.
func fileSpanStep(filePath, outputText string) *step {
	s := &step{files: []string{filePath}}
	if span, ok := inferReadSpan(outputText); ok {
		s.spans = map[string][]Span{filePath: {span}}
	}
	return s
}

func readLikeStep(chain []chainSegment, outputText string, ws *workspace) *step {
	merged := &step{}
	for _, segment := range chain {
		if !segment.cwdUncertain && !segment.orGated {
			mergeStep(merged, readSegmentStep(segment.raw, outputText, ws))
		}
	}
	if len(merged.files) == 0 && len(merged.spans) == 0 {
		return nil
	}
	if len(chain) == 1 {
		attachReadRange(merged, outputText, !strings.Contains(chain[0].raw, "|"))
	}
	return merged
}

func mergeStep(target *step, s *step) {
	if s == nil {
		return
	}
	for _, f := range s.files {
		if !slices.Contains(target.files, f) {
			target.files = append(target.files, f)
		}
	}
	for filePath, spans := range s.spans {
		if target.spans == nil {
			target.spans = map[string][]Span{}
		}
		if !slices.Contains(target.files, filePath) {
			target.files = append(target.files, filePath)
		}
		target.spans[filePath] = append(target.spans[filePath], spans...)
	}
	for filePath, ranges := range s.readRanges {
		if target.readRanges == nil {
			target.readRanges = map[string][]ReadRange{}
		}
		target.readRanges[filePath] = append(target.readRanges[filePath], ranges...)
	}
}

var contentSuppressingFlags = map[string]bool{
	"-q": true, "--quiet": true,
	"-l": true, "--files-with-matches": true,
	"-L": true, "--files-without-match": true,
	"-c": true, "--count": true,
	"--files": true,
}

func searchCommandCanExposeFileContent(tokens []string, outputText string) bool {
	if strings.TrimSpace(outputText) == "" || hasRedirectionToken(tokens) {
		return false
	}
	for _, token := range tokens {
		if contentSuppressingFlags[token] {
			return false
		}
	}
	return true
}

func explicitSingleSearchFile(tokens []string, ws *workspace) string {
	start := -1
	word := ""
	for i, token := range tokens {
		if token == "grep" || token == "rg" {
			start = i + 1
			word = token
			break
		}
	}
	if start < 0 {
		return ""
	}
	stop := firstPipeIndexAfter(tokens, start)
	args := tokens[start:stop]
	if execSearchPattern(word, args) == "" {
		return ""
	}
	scan := scanCommandArgs(args, execSearchFlagModelFor(word))
	if scan.unknownFlag {
		return ""
	}
	if _, ok := scan.flagValue("-f", "--file"); ok {
		return "" // the pattern file is a second input, not search result content
	}
	operands := scan.operands
	if _, explicit := scan.flagValue("-e", "--regexp"); !explicit {
		if len(operands) == 0 {
			return ""
		}
		operands = operands[1:] // the first operand is the pattern, never a file
	}
	var candidates []string
	for _, token := range operands {
		// A directory operand is a repository search, not a file read, and it
		// must not be published as a file that was read. Nothing here may touch
		// the filesystem to tell the two apart, so the same shape rule the
		// claude Grep path already applies decides it: `.github` and
		// `jquery-3.6` look like filenames but are rejected as directories.
		normalized := normalizeCommandPathToken(token, ws)
		if normalized == "" || !looksLikeSingleSearchFile(path.Base(normalized)) {
			continue
		}
		if !slices.Contains(candidates, normalized) {
			candidates = append(candidates, normalized)
		}
	}
	if len(candidates) == 1 {
		return candidates[0]
	}
	return ""
}

// searchFileStepFromCommand credits a file-only retrieval when a grep/rg
// command was explicitly scoped to exactly one file and produced output.
func searchFileStepFromCommand(chain []chainSegment, outputText string, ws *workspace) *step {
	var files []string
	for _, segment := range chain {
		tokens := tokensForSegment(segment.raw)
		if segment.cwdUncertain || segment.orGated || len(tokens) == 0 || !hasGrepLikeCommand(segment.raw, tokens) {
			continue
		}
		if !searchCommandCanExposeFileContent(tokens, outputText) {
			continue
		}
		if filePath := explicitSingleSearchFile(tokens, ws); filePath != "" && !slices.Contains(files, filePath) {
			files = append(files, filePath)
		}
	}
	if len(files) == 0 {
		return nil
	}
	return &step{files: files}
}

var grepNoMatchMarkers = []string{"no matches found", "no files found"}

func grepOutputIndicatesMatch(outputText string) bool {
	text := strings.TrimSpace(outputText)
	if text == "" {
		return false
	}
	lower := strings.ToLower(text)
	for _, marker := range grepNoMatchMarkers {
		if strings.HasPrefix(lower, marker) {
			return false
		}
	}
	return true
}

func looksLikeSingleSearchFile(name string) bool {
	if !looksLikeRepoFilename(name) {
		return false
	}
	// Hidden directories ('.github') and version-suffixed directories
	// ('jquery-3.6') pass the filename heuristic but are not files.
	if strings.HasPrefix(name, ".") && !strings.Contains(name[1:], ".") {
		return false
	}
	if dot := strings.LastIndexByte(name, '.'); dot >= 0 {
		if ext := name[dot+1:]; ext != "" && isDigits(ext) {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

// inferSearchFileStepFromPath credits file-only context when a search tool
// (claude Grep) was explicitly scoped to one file and found matches.
func inferSearchFileStepFromPath(pathValue, outputText string, ws *workspace) *step {
	if !grepOutputIndicatesMatch(outputText) {
		return nil
	}
	normalized := normalizeInferredFilePath(pathValue, ws)
	if normalized == "" {
		return nil
	}
	name := normalized
	if idx := strings.LastIndexByte(normalized, '/'); idx >= 0 {
		name = normalized[idx+1:]
	}
	if !looksLikeSingleSearchFile(name) {
		return nil
	}
	return &step{files: []string{normalized}}
}

// inferReadStep credits a Read tool call: the file, plus the line span
// grounded in the tool output when detectable.
func inferReadStep(filePath, outputText string, ws *workspace) *step {
	normalized, ok := normalizeWorkspacePath(filePath, ws)
	if !ok {
		return nil // outside the workspace: don't credit it
	}
	s := &step{files: []string{normalized}}
	if span, ok := inferReadSpan(outputText); ok {
		s.spans = map[string][]Span{normalized: {span}}
	}
	attachReadRange(s, outputText, false)
	return s
}

func capturedOutputLines(text string) []string {
	normalized := strings.ReplaceAll(text, "\r\n", "\n")
	normalized = strings.TrimSuffix(normalized, "\n")
	if normalized == "" {
		return nil
	}
	return strings.Split(normalized, "\n")
}

func numberedReadRange(lines []string, span Span) (ReadRange, bool) {
	if len(lines) == 0 {
		return ReadRange{}, false
	}
	patterns := []*regexp.Regexp{lineArrowContentRe, numberedLineContentRe}
	for _, pattern := range patterns {
		content := make([]string, 0, len(lines))
		start, previous := 0, 0
		matched := true
		for index, line := range lines {
			parts := pattern.FindStringSubmatch(line)
			if len(parts) != 3 {
				matched = false
				break
			}
			number, err := strconv.Atoi(parts[1])
			if err != nil || (index > 0 && number != previous+1) {
				matched = false
				break
			}
			if index == 0 {
				start = number
			}
			previous = number
			content = append(content, parts[2])
		}
		if matched && start >= span.Start && previous <= span.End {
			return ReadRange{Start: start, End: previous, Content: strings.Join(content, "\n")}, true
		}
	}
	return ReadRange{}, false
}

func readRangeFromOutput(text string, span Span, allowPlain bool) (ReadRange, bool) {
	lines := capturedOutputLines(text)
	if span.Start < 1 || span.End < span.Start || len(lines) == 0 {
		return ReadRange{}, false
	}
	if captured, ok := numberedReadRange(lines, span); ok {
		return captured, true
	}
	if !allowPlain || len(lines) > span.End-span.Start+1 {
		return ReadRange{}, false
	}
	return ReadRange{
		Start:   span.Start,
		End:     span.Start + len(lines) - 1,
		Content: strings.Join(lines, "\n"),
	}, true
}

func attachReadRange(s *step, outputText string, allowPlain bool) {
	if s == nil || len(s.files) != 1 || len(s.spans[s.files[0]]) != 1 {
		return
	}
	rangeContent, ok := readRangeFromOutput(outputText, s.spans[s.files[0]][0], allowPlain)
	if !ok {
		return
	}
	s.readRanges = map[string][]ReadRange{s.files[0]: {rangeContent}}
}

// retrievalFromCommand infers retrieval context from a shell command and its
// output: read-like commands (sed/head/cat/tail/nl) yield file+span, a
// single-file grep/rg yields file-only, everything else yields nothing.
func retrievalFromCommand(command, outputText string, ws *workspace) *step {
	rawCommand := unwrapShell(command)
	chain := splitCommandChain(rawCommand)
	if len(chain) == 0 {
		return nil
	}
	for _, segment := range chain {
		tokens := tokensForSegment(segment.raw)
		if slices.Contains(tokens, "Read") || commandHasWord(segment.raw, "Read") {
			return nil
		}
	}
	if s := readLikeStep(chain, outputText, ws); s != nil {
		return s
	}
	return searchFileStepFromCommand(chain, outputText, ws)
}

// boundedOutput excludes very large outputs from retrieval inference because
// grounding in megabytes of output adds noise rather than useful signal.
func boundedOutput(text string) string {
	if len(text) > maxCommandOutputChars {
		return ""
	}
	return text
}
