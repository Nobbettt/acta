package digest

import (
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// fsInspectFlags turn a patch command into an inspection or an unwind: with any
// of these the command applied nothing, so it is credited with nothing.
var fsInspectFlags = []string{"--check", "--dry-run", "--stat", "--numstat", "--summary", "--abort", "--quit"}

// classifyFS owns the filesystem slice of the category table: fs.delete,
// fs.move, fs.create and fs.patch, plus the ShellMutations that back the
// file.deleted / file.moved events. Every category here asserts
// a state change, so a failed command is credited with nothing — an `rm` that
// exited non-zero deleted no file — and so is a segment that would not
// tokenize.
func classifyFS(segment commandSegment) *commandFacts {
	var ok bool
	segment, ok = parsedCommandSegment(segment)
	if !ok {
		return nil
	}
	if !segment.exitOK || len(segment.tokens) == 0 {
		return nil
	}
	verb, args := fsVerb(segment.tokens)
	repoRedirected := strings.HasPrefix(verb, "git ") && gitEnvironmentRedirectsRepository(segment.tokens)
	if verb == "" {
		gitVerb, gitArgs, redirected, informational, ok := gitInvocation(segment.tokens)
		if !ok || informational {
			return nil
		}
		switch gitVerb {
		case "rm", "apply", "cherry-pick", "revert":
		default:
			return nil
		}
		verb, args, repoRedirected = "git "+gitVerb, gitArgs, redirected
	}
	ownArgs := fsOwnArgs(args)
	scan := scanCommandArgs(ownArgs, fsFlagModels[verb])
	if commandAssertsNoChange(ownArgs, fsFlagModels[verb]) {
		return nil
	}
	switch verb {
	case "git rm":
		if gitAssertsNoChange("rm", ownArgs) {
			return nil
		}
	case "touch":
		if scan.hasFlag("-c", "--no-create") {
			return nil
		}
	case "patch", "git apply", "git cherry-pick", "git revert":
		if scan.hasFlag(fsInspectFlags...) || verb == "patch" && scan.hasFlag("-C", "-v") {
			return nil
		}
		if verb == "patch" && fsPatchInputIsEmpty(args, segment.shell) {
			return nil
		}
		if verb == "git apply" && fsGitApplyInputIsEmpty(args, segment.shell) {
			return nil
		}
	}
	if fsRuntimeOutcomeUnproven(verb, scan) {
		return nil
	}
	if verb == "patch" || verb == "git apply" || verb == "git cherry-pick" || verb == "git revert" {
		if strings.HasPrefix(verb, "git ") && repoRedirected {
			if workTree, ok := gitWorkTree(segment.tokens); ok && fsEscapes([]string{workTree}, segment.ws, segment.cwdUncertain) {
				return &commandFacts{categories: []string{"workspace.escape"}}
			}
			return nil
		}
		return &commandFacts{categories: []string{"fs.patch"}}
	}
	if verb == "git rm" && repoRedirected {
		if workTree, ok := gitWorkTree(segment.tokens); ok && fsEscapes([]string{workTree}, segment.ws, segment.cwdUncertain) {
			return &commandFacts{categories: []string{"workspace.escape"}}
		}
		if dir, ok := gitCommandDirectory(segment.tokens, segment.cwd, segment.cwdKnown && !segment.cwdUncertain); ok {
			operands, _ := fsOperands(verb, args)
			for i, operand := range operands {
				if !fsOperandAbsolute(operand) {
					operands[i] = literalPathJoin(dir, operand)
				}
			}
			return fsDelete(operands, segment.ws, false)
		}
		return nil
	}
	if scan.unknownFlag {
		var category string
		switch verb {
		case "rm", "git rm":
			category = "fs.delete"
		case "mv":
			category = "fs.move"
		case "cp", "touch", "mkdir":
			category = "fs.create"
		case "patch", "git apply", "git cherry-pick", "git revert":
			category = "fs.patch"
		default:
			return nil
		}
		return &commandFacts{categories: []string{category}}
	}
	operands, _ := fsOperands(verb, args)
	var facts *commandFacts
	switch verb {
	case "rm":
		facts = fsDelete(operands, segment.ws, segment.cwdUncertain)
		if facts == nil && fsHasExpandedOperand(segment.shell, operands) {
			facts = &commandFacts{categories: []string{"fs.delete"}}
		}
	case "git rm":
		// A dry run, or `--cached`/`--staged` (which only untracks the path —
		// the file is still on disk), all assert a deletion that did not happen.
		if scan.hasFlag("--pathspec-from-file") {
			return &commandFacts{categories: []string{"fs.delete"}}
		}
		facts = fsDelete(operands, segment.ws, segment.cwdUncertain)
		if facts == nil && fsHasExpandedOperand(segment.shell, operands) {
			facts = &commandFacts{categories: []string{"fs.delete"}}
		}
	case "mv":
		facts = fsMove(ownArgs, operands, segment.ws, segment.cwdUncertain)
	case "cp":
		facts = fsCopy(ownArgs, operands, segment.ws, segment.cwdUncertain)
	case "touch":
		facts = fsCreate(operands, segment.ws, segment.cwdUncertain)
	case "mkdir":
		facts = fsCreate(operands, segment.ws, segment.cwdUncertain)
	}
	return facts
}

// fsRuntimeOutcomeUnproven is the single gate for filesystem operations whose
// successful exit still does not prove a particular path changed. Conditional
// modes can decline or skip an operation, so neither a state-change category
// nor its path targets and derived file events are proven.
//
// This is deliberately stricter than the cwd-uncertainty rule, and the two are
// easy to confuse. An unresolved `cd` means the act happened somewhere this
// classifier cannot name, so the category survives and only the path is
// withheld. A conditional mode means the act may not have happened AT ALL —
// `rm -f missing` exits zero having deleted nothing, `cp -n` skips an existing
// destination, `mv -i` waits for an answer that may be no — so there is no
// category to credit either. A test that means to exercise cwd taint must
// therefore avoid `-f`, or it will be measuring this gate instead.
func fsRuntimeOutcomeUnproven(verb string, scan commandArgScan) bool {
	switch verb {
	case "rm":
		if scan.hasFlag("-f", "--force", "-i", "-I") {
			return true
		}
		for _, flag := range scan.flags {
			if flag.name == "--interactive" && !strings.EqualFold(flag.value, "never") {
				return true
			}
		}
	case "mv", "cp":
		return scan.hasFlag("-i", "--interactive", "-n", "--no-clobber", "-u", "--update")
	case "mkdir":
		return scan.hasFlag("-p", "--parents")
	}
	return false
}

// fsVerb reduces a segment's tokens to the filesystem verb it invokes plus that
// verb's arguments. A leading `sudo` or `NAME=value` prefix is skipped first —
// the same prefixes execLeadingTokens already strips for the exec classifier —
// so `sudo rm -rf x` still resolves to `rm`. Only the leading token after that
// counts, so `echo rm -rf /` and a quoted `rm` inside another command's
// argument are not verbs. A `git` verb counts only when its subcommand follows
// immediately: `git -C other/repo rm x` resolves its paths against a directory
// this classifier cannot see.
func fsVerb(tokens []string) (string, []string) {
	tokens = execLeadingTokens(tokens)
	if len(tokens) == 0 {
		return "", nil
	}
	name := path.Base(tokens[0])
	if name != "git" {
		return name, tokens[1:]
	}
	if len(tokens) < 2 || strings.HasPrefix(tokens[1], "-") {
		return "", nil
	}
	return "git " + tokens[1], tokens[2:]
}

// gitWorkTree returns the effective explicit work-tree selection. Command-line
// flags override environment assignments, matching Git's precedence.
func gitWorkTree(tokens []string) (value string, ok bool) {
	for _, token := range tokens {
		name, assignmentValue, assignment := strings.Cut(token, "=")
		if assignment {
			if name == "GIT_WORK_TREE" {
				value, ok = assignmentValue, true
			}
			continue
		}
		if token == "sudo" || token == "env" {
			continue
		}
		break
	}
	tokens = execLeadingTokens(tokens)
	if len(tokens) == 0 || path.Base(tokens[0]) != "git" {
		return value, ok
	}
	scan := scanCommandArgs(tokens[1:], gitGlobalFlagModel)
	if len(scan.operandIndexes) == 0 {
		return value, ok
	}
	verbIndex := scan.operandIndexes[0]
	configuredValue, configured := "", false
	explicitValue, explicit := "", false
	for _, flag := range scan.flags {
		if flag.index >= verbIndex {
			continue
		}
		if flag.name == "-c" {
			key, configValue, hasValue := strings.Cut(flag.value, "=")
			if hasValue && strings.EqualFold(strings.TrimSpace(key), "core.worktree") {
				configuredValue, configured = configValue, true
			}
		}
		if flag.name == "--work-tree" {
			explicitValue, explicit = flag.value, true
		}
	}
	if explicit {
		return explicitValue, true
	}
	if ok {
		return value, true
	}
	return configuredValue, configured
}

// gitCommandDirectory returns the literal directory selected by git's -C
// flags. Each relative occurrence is resolved against the preceding one, as
// Git does; an absolute occurrence restores certainty after an unknown cwd.
func gitCommandDirectory(tokens []string, cwd string, cwdKnown bool) (string, bool) {
	tokens = execLeadingTokens(tokens)
	if len(tokens) == 0 || path.Base(tokens[0]) != "git" {
		return "", false
	}
	scan := scanCommandArgs(tokens[1:], gitGlobalFlagModel)
	if len(scan.operandIndexes) == 0 {
		return "", false
	}
	verbIndex := scan.operandIndexes[0]
	found := false
	for _, flag := range scan.flags {
		if flag.index >= verbIndex || flag.name != "-C" {
			continue
		}
		found = true
		if flag.value == "" || strings.ContainsAny(flag.value, fsShellMetacharacters) {
			cwd, cwdKnown = "", false
		} else if fsOperandAbsolute(flag.value) {
			cwd, cwdKnown = literalPath(flag.value), true
		} else if cwdKnown {
			cwd = literalPathJoin(cwd, flag.value)
		}
	}
	return cwd, found && cwdKnown
}

type commandFlagArity uint8

const (
	flagBoolean commandFlagArity = iota + 1
	flagBooleanValue
	flagValue
	flagAttachedValue
)

// commandFlagModel declares the arity of every flag a classifier interprets.
// Unknown flags are still flags, but consume nothing and are never split into
// letters. flagAttachedValue covers optional values accepted only when joined
// to the flag, such as git's --force-with-lease=<ref>.
type commandFlagModel map[string]commandFlagArity

// fsFlagModels keep each filesystem command's option grammar separate. The
// parser consumes only declared values, so a mode, timestamp, suffix or strip
// count can never fall through as a path.
var fsFlagModels = map[string]commandFlagModel{
	"rm": {
		"-d": flagBoolean, "-f": flagBoolean, "-i": flagBoolean,
		"-I": flagBoolean, "-r": flagBoolean, "-R": flagBoolean, "-v": flagBoolean,
		"--force": flagBoolean, "--interactive": flagAttachedValue,
	},
	"git rm": {
		"-f": flagBoolean, "-n": flagBoolean, "-q": flagBoolean, "-r": flagBoolean,
		"--cached": flagBoolean, "--dry-run": flagBoolean, "--staged": flagBoolean,
		"--ignore-unmatch":     flagBoolean,
		"--pathspec-from-file": flagValue, "--pathspec-file-nul": flagBoolean,
	},
	"mkdir": {
		"-p": flagBoolean, "-v": flagBoolean, "-Z": flagBoolean,
		"--parents": flagBoolean,
		"-m":        flagValue, "--mode": flagValue, "--context": flagValue,
	},
	"touch": {
		"-a": flagBoolean, "-c": flagBoolean, "-f": flagBoolean,
		"-h": flagBoolean, "-m": flagBoolean,
		"--no-create": flagBoolean,
		"-A":          flagValue, "-d": flagValue, "--date": flagValue, "-t": flagValue,
		"-r": flagValue, "--reference": flagValue, "--time": flagValue,
	},
	"mv": {
		"-b": flagBoolean, "-f": flagBoolean, "-i": flagBoolean,
		"-n": flagBoolean, "-T": flagBoolean, "-u": flagBoolean, "-v": flagBoolean,
		"--interactive": flagBoolean, "--no-clobber": flagBoolean,
		"--no-target-directory": flagBoolean, "--update": flagAttachedValue,
		"-t": flagValue, "--target-directory": flagValue,
		"-S": flagValue, "--suffix": flagValue,
	},
	"cp": {
		"-a": flagBoolean, "-b": flagBoolean, "-f": flagBoolean,
		"-H": flagBoolean, "-i": flagBoolean, "-L": flagBoolean,
		"-n": flagBoolean, "-p": flagBoolean, "-P": flagBoolean,
		"-R": flagBoolean, "-r": flagBoolean, "-T": flagBoolean,
		"-u": flagBoolean, "-v": flagBoolean, "--no-clobber": flagBoolean,
		"--interactive": flagBoolean, "--no-target-directory": flagBoolean,
		"--parents": flagBoolean, "--update": flagAttachedValue,
		"-t": flagValue, "--target-directory": flagValue,
		"-S": flagValue, "--suffix": flagValue,
	},
	"patch": {
		"-b": flagBoolean, "-C": flagBoolean, "-E": flagBoolean, "-f": flagBoolean,
		"-F": flagValue, "--fuzz": flagValue, "-N": flagBoolean, "-R": flagBoolean,
		"-d": flagValue, "--directory": flagValue, "-i": flagValue, "--input": flagValue,
		"-o": flagValue, "--output": flagValue, "-r": flagValue, "--reject-file": flagValue,
		"-B": flagValue, "--prefix": flagValue, "-D": flagValue, "--ifdef": flagValue,
		"-g": flagValue, "--get": flagValue, "-p": flagValue, "--strip": flagValue,
		"-V": flagValue, "--version-control": flagValue, "-x": flagValue, "--debug": flagValue,
		"-Y": flagValue, "--basename-prefix": flagValue, "-z": flagValue, "--suffix": flagValue,
		"--quoting-style": flagValue, "-v": flagBoolean,
	},
}

// fsOperands returns the non-flag arguments of a filesystem command. `--` ends
// the flags, so `rm -- -oddly-named` still credits the file. The shell parser
// has already removed redirections; verb's entry in fsFlagModels skips values
// belonging to flags so they never become operands.
func fsOperands(verb string, args []string) ([]string, bool) {
	ownArgs := fsOwnArgs(args)
	return scanCommandArgs(ownArgs, fsFlagModels[verb]).operands, false
}

// fsOwnArgs returns the prefix of args that belongs to this verb's own
// invocation, up to a pipe/control operator that hands the rest of the line to
// a different command. A flag scan that skipped this truncation would read a
// downstream stage's own flag as this verb's own —
// `cp a.txt b.txt | xargs -t rm` names xargs's -t, not cp's, so
// fsCopyTargetFlag, classifyFS's patch inspect-flag scan and the git-rm
// `--cached`/`--staged` check must all see this slice, never the raw one.
func fsOwnArgs(args []string) []string {
	for i, arg := range args {
		if arg == "|" || arg == "|&" || arg == "&" {
			return args[:i]
		}
	}
	return args
}

// patchInputIsEmpty reports whether the final stdin source is known empty. A
// later redirect wins, so its parser-provided position is the only source that
// may suppress a patch.
func patchInputIsEmpty(command shellSimpleCommand) bool {
	redirect, ok := command.inputRedirect()
	if !ok {
		return false
	}
	if redirect.heredoc {
		return redirect.word.text == ""
	}
	file, ok := command.inputFile()
	return ok && file == "/dev/null"
}

// fsPatchInputIsEmpty reports whether patch's effective input is empty. Its
// native input option overrides stdin, and '-' is an explicit stdin alias.
func fsPatchInputIsEmpty(args []string, command shellSimpleCommand) bool {
	input, explicit := "", false
	for _, flag := range scanCommandArgs(args, fsFlagModels["patch"]).flags {
		if flag.name == "-i" || flag.name == "--input" {
			input, explicit = flag.value, true
		}
	}
	if !explicit {
		return patchInputIsEmpty(command)
	}
	return input == "/dev/null" || input == "-" && patchInputIsEmpty(command)
}

// fsGitApplyInputIsEmpty reports git apply's --allow-empty forms that prove
// no patch was supplied. A dash operand reads stdin, while named files override
// it; classifying either the heredoc delimiter or dash itself as a patch file
// would invent an application that did not happen.
func fsGitApplyInputIsEmpty(args []string, command shellSimpleCommand) bool {
	scan := scanCommandArgs(args, nil)
	if !scan.hasFlag("--allow-empty") {
		return false
	}
	stdin := false
	for _, operand := range scan.operands {
		switch operand {
		case "/dev/null":
		case "-":
			stdin = true
		default:
			return false
		}
	}
	return !stdin && len(scan.operands) != 0 || (stdin || len(scan.operands) == 0) && patchInputIsEmpty(command)
}

// fsHasExpandedOperand distinguishes an expanded operand from an ordinary
// glob: both lack a publishable path, but a successful rm still proves the
// former performed a deletion somewhere.
func fsHasExpandedOperand(command shellSimpleCommand, operands []string) bool {
	for _, operand := range operands {
		for _, word := range command.words {
			if word.text == operand && !word.literal {
				return true
			}
		}
	}
	return false
}

type commandFlag struct {
	name  string
	value string
	arity commandFlagArity
	index int
}

type commandArgScan struct {
	operands       []string
	operandIndexes []int
	flags          []commandFlag
	unknownFlag    bool
}

// scanCommandArgs is the classifiers' authoritative operand/flag scanner. It
// handles separate and attached long values, attached short values, and known
// short clusters. A value-taking short option ends a cluster: the remainder is
// its value, never more option letters. An unknown option is kept opaque and
// marks the scan uncertain, so target extractors can fail closed rather than
// guess whether the following token was its value.
func scanCommandArgs(args []string, model commandFlagModel) commandArgScan {
	var scan commandArgScan
	for i := 0; i < len(args); i++ {
		argIndex := i
		arg := args[i]
		switch {
		case arg == "--":
			for j := i + 1; j < len(args); j++ {
				scan.operands = append(scan.operands, args[j])
				scan.operandIndexes = append(scan.operandIndexes, j)
			}
			return scan
		case arg == "-" || !strings.HasPrefix(arg, "-"):
			scan.operands = append(scan.operands, arg)
			scan.operandIndexes = append(scan.operandIndexes, i)
		case strings.HasPrefix(arg, "--"):
			name, value, attached := strings.Cut(arg, "=")
			arity := model[name]
			if arity == flagBoolean && attached && commandBooleanValue(model, name) {
				arity = flagBooleanValue
			}
			if arity == 0 {
				scan.unknownFlag = true
			}
			if arity == flagValue && !attached && i+1 < len(args) {
				i++
				value = args[i]
			}
			scan.flags = append(scan.flags, commandFlag{name: name, value: value, arity: arity, index: argIndex})
		case len(arg) >= 3 && arg[2] == '=' && model[arg[:2]] == flagBoolean:
			arity := flagBoolean
			if commandBooleanValue(model, arg[:2]) {
				arity = flagBooleanValue
			}
			scan.flags = append(scan.flags, commandFlag{name: arg[:2], value: arg[3:], arity: arity, index: argIndex})
		case model[arg] != 0:
			arity := model[arg]
			value := ""
			if arity == flagValue && i+1 < len(args) {
				i++
				value = args[i]
			}
			scan.flags = append(scan.flags, commandFlag{name: arg, value: value, arity: arity, index: argIndex})
		default:
			flags := make([]commandFlag, 0, len(arg)-1)
			known := true
			for j := 1; j < len(arg); j++ {
				name := "-" + string(arg[j])
				arity := model[name]
				if arity == 0 {
					known = false
					break
				}
				value := ""
				if arity == flagValue || arity == flagAttachedValue {
					if j+1 < len(arg) {
						value = arg[j+1:]
					} else if arity == flagValue && i+1 < len(args) {
						i++
						value = args[i]
					}
					flags = append(flags, commandFlag{name: name, value: value, arity: arity, index: argIndex})
					break
				}
				flags = append(flags, commandFlag{name: name, arity: arity, index: argIndex})
			}
			if known {
				scan.flags = append(scan.flags, flags...)
			} else {
				scan.unknownFlag = true
				// Boolean flags decoded before the unknown suffix are still
				// certain. Preserve them so a leading help/dry-run mode cannot be
				// erased by an option this model does not know.
				scan.flags = append(scan.flags, flags...)
				scan.flags = append(scan.flags, commandFlag{name: arg, index: argIndex})
			}
		}
	}
	return scan
}

func commandBooleanValue(model commandFlagModel, name string) bool {
	return (name == "-g" || name == "--global") && model["--package-lock-only"] != 0 ||
		(name == "--package-lock-only" || name == "--dry-run") && model["--package-lock-only"] != 0 ||
		(name == "-d" || name == "--detach") && model["--project-name"] != 0
}

func (scan commandArgScan) hasFlag(names ...string) bool {
	found, enabled := false, false
	for _, flag := range scan.flags {
		for _, name := range names {
			if flag.name == name {
				found, enabled = true, flag.enabled()
			}
		}
	}
	return found && enabled
}

func (scan commandArgScan) hasModeFlag(names ...string) bool {
	for _, flag := range scan.flags {
		if flag.arity == flagValue || flag.arity == flagAttachedValue {
			continue
		}
		for _, name := range names {
			if flag.name == name && flag.enabled() {
				return true
			}
		}
	}
	return false
}

// enabled reports whether a flag activates its boolean mode. Only flags marked
// flagBooleanValue accept =false; other tools reject that spelling, so it
// cannot disable an informational or no-op flag in the classifier.
func (flag commandFlag) enabled() bool {
	return flag.arity != flagBooleanValue || !strings.EqualFold(flag.value, "false")
}

func (scan commandArgScan) flagValue(names ...string) (string, bool) {
	for _, flag := range scan.flags {
		for _, name := range names {
			if flag.name == name {
				return flag.value, true
			}
		}
	}
	return "", false
}

// commandAssertsNoChange reports an informational or dry-run invocation. The
// arity model prevents a spelling such as gem's `--version 7` from being
// mistaken for the command-level `--version` probe.
func commandAssertsNoChange(args []string, model commandFlagModel) bool {
	return scanCommandArgs(args, model).hasModeFlag(
		"--help", "-h", "--version", "-V", "--usage", "--dry-run",
	)
}

// fsShellMetacharacters is the set of characters that prove an operand carries
// unexpanded shell syntax rather than a literal path. shellTokens has no
// $()/backtick awareness (see shelltok.go), so a command substitution such as
// `$(cat list.txt)` or a backtick-quoted one tokenizes into plain words, e.g.
// `$(cat` and `list.txt)`, with only the `$`-prefixed half distinguishable
// without this set. Without parens and a backtick here, the other half reads
// as an ordinary path and gets credited as one that never existed.
const fsShellMetacharacters = "*?[{$~()`"

// fsOperandAbsolute reports whether operand names an absolute path outright —
// the one shape immune to an unknown working directory, since
// normalizeWorkspacePath resolves it against the workspace root no matter what
// an earlier `cd` changed the shell's cwd to.
func fsOperandAbsolute(operand string) bool {
	return strings.HasPrefix(operand, "/") || filepath.IsAbs(operand) || isPortableAbsolute(canonicalWorkspacePath(operand))
}

// literalPath preserves a raw parent component until workspace normalization
// rejects it. Cleaning first would erase the only spelling that reveals a
// symlink traversal may have left the recorded workspace.
func literalPath(value string) string {
	value = strings.ReplaceAll(value, `\`, "/")
	if hasParentPathComponent(value) {
		return value
	}
	return path.Clean(value)
}

func literalPathJoin(base, value string) string {
	base, value = literalPath(base), literalPath(value)
	if hasParentPathComponent(base) || hasParentPathComponent(value) {
		return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(value, "/")
	}
	return path.Join(base, value)
}

// fsSourceBasenameIsDotOrDotDot reports whether the raw source operand's last
// path element is "." or "..". fsPaths cleans an operand before this
// classifier ever sees it, so `src/.` normalises to `src`, but `cp -a src/.
// backup/` copies the CONTENTS of src into backup/ and creates no backup/src
// at all — the raw operand, checked here before that clean, is the only place
// this shape is still visible.
func fsSourceBasenameIsDotOrDotDot(src string) bool {
	clean := filepath.ToSlash(src)
	return path.Base(clean) == "." || path.Base(clean) == ".."
}

// fsDestinationNamesDirectory reports the operand spellings that prove the
// destination is a directory before path cleaning discards that syntax.
func fsDestinationNamesDirectory(dest string) bool {
	dest = strings.TrimRight(filepath.ToSlash(dest), "/")
	return dest != "" && (path.Base(dest) == "." || path.Base(dest) == "..")
}

// fsIsWorkspaceRoot reports whether operand names the workspace root itself.
// normalizeWorkspacePath deliberately rejects "." along with every other
// unresolvable shape, so fsEscapes needs its own check here — otherwise a
// write into the root (`cp src/a.go .`) looks identical to one that left the
// workspace entirely.
func fsIsWorkspaceRoot(operand string, ws *workspace) bool {
	if hasParentPathComponent(operand) {
		return false
	}
	rel, ok := ws.rel(operand)
	if ok && path.Clean(filepath.ToSlash(rel)) == "." {
		return true
	}
	canonical := canonicalWorkspacePath(operand)
	for _, root := range ws.variants {
		if canonical == root || runtime.GOOS == "windows" && strings.EqualFold(canonical, root) {
			return true
		}
	}
	return false
}

// fsDirectoryPath resolves a destination directory, including the workspace
// root itself. normalizeWorkspacePath excludes the root because it is not a
// file target, but cp/mv can prove a child destination beneath it from the
// source basename.
func fsDirectoryPath(operand string, ws *workspace, cwdUncertain bool) (string, bool) {
	if strings.ContainsAny(operand, fsShellMetacharacters) || cwdUncertain && !fsOperandAbsolute(operand) {
		return "", false
	}
	if fsIsWorkspaceRoot(operand, ws) {
		return ".", true
	}
	return normalizeWorkspacePath(operand, ws)
}

// fsPaths keeps the operands that resolve to a file inside the workspace. An
// operand that escapes the workspace is skipped here and credited by fsEscapes
// instead, and so is one carrying shell metacharacters, which names an
// unexpanded pattern rather than a path. Once cwdUncertain is set, a relative
// operand is skipped too: an earlier `cd`/`pushd` in this command means this
// classifier no longer knows what directory it would resolve against, and
// guessing "the workspace root" would be a fabricated cwd, not a proven one.
func fsPaths(operands []string, ws *workspace, cwdUncertain bool) []string {
	var paths []string
	for _, operand := range operands {
		if strings.ContainsAny(operand, fsShellMetacharacters) {
			continue
		}
		if cwdUncertain && !fsOperandAbsolute(operand) {
			continue
		}
		if p, ok := normalizeWorkspacePath(operand, ws); ok {
			paths = append(paths, p)
		}
	}
	return paths
}

// fsEscapes reports an operand that names a write target the workspace does not
// contain — the path-shaped half of workspace.escape, the one case where a path
// that will not resolve is itself the finding. An unexpanded pattern is not one:
// that is an operand this classifier could not read at all, and guessing where
// it pointed would be an invention. Nor is the workspace root itself, or — once
// cwdUncertain is set — a relative operand: without a known cwd, "did not
// resolve" no longer proves "escaped", only "unprovable". The flag-shaped
// escapes (`npm install -g` and friends) belong to the exec classifier.
func fsEscapes(operands []string, ws *workspace, cwdUncertain bool) bool {
	for _, operand := range operands {
		if strings.ContainsAny(operand, fsShellMetacharacters) {
			continue
		}
		if cwdUncertain && !fsOperandAbsolute(operand) {
			continue
		}
		if fsIsWorkspaceRoot(operand, ws) {
			continue
		}
		if _, ok := normalizeWorkspacePath(operand, ws); !ok {
			return true
		}
	}
	return false
}

// fsPathFacts credits category for every resolvable operand, with the paths as
// targets, plus workspace.escape for any operand that landed outside. Nothing
// resolvable and nothing escaping means nothing proven, so nothing is credited.
func fsPathFacts(category string, operands []string, ws *workspace, cwdUncertain bool) *commandFacts {
	facts := &commandFacts{}
	for _, p := range fsPaths(operands, ws, cwdUncertain) {
		facts.categories = []string{category}
		appendCommandTarget(facts, CommandTarget{Kind: "path", Value: p})
	}
	if fsEscapes(operands, ws, cwdUncertain) {
		facts.categories = append(facts.categories, "workspace.escape")
	}
	if facts.empty() {
		return nil
	}
	return facts
}

// fsDelete credits every deleted path, each with the mutation that backs a
// file.deleted event.
func fsDelete(operands []string, ws *workspace, cwdUncertain bool) *commandFacts {
	facts := fsPathFacts("fs.delete", operands, ws, cwdUncertain)
	if facts == nil {
		return nil
	}
	// If one successful rm also names an ancestor, command text cannot prove
	// where an earlier descendant resolved through that possibly-symlinked path.
	targets := facts.targets[:0]
	for _, target := range facts.targets {
		descendant := false
		for _, other := range facts.targets {
			if target.Value != other.Value && strings.HasPrefix(target.Value, other.Value+"/") {
				descendant = true
				break
			}
		}
		if !descendant {
			targets = append(targets, target)
		}
	}
	facts.targets = targets
	// Only the in-workspace targets back a file.deleted event; an escape has no
	// path the file timeline could name.
	for _, target := range facts.targets {
		facts.mutations = append(facts.mutations, ShellMutation{Kind: "delete", Path: target.Value})
	}
	return facts
}

// fsMove derives the candidate paths for a move. classifyFS removes them when
// fsRuntimeOutcomeUnproven finds a conditional mode; otherwise the plain
// two-operand form uses the accepted assumption documented by that gate.
// Multi-source moves are deliberately uncredited: command text alone does not
// prove each source/destination pair.
func fsMove(args, operands []string, ws *workspace, cwdUncertain bool) *commandFacts {
	if dest, ok := fsCopyTargetFlag("mv", args); ok {
		if dest == "" || len(operands) != 1 {
			return nil
		}
		return fsMoveIntoDir(operands[0], dest, ws, cwdUncertain)
	}
	if len(operands) != 2 {
		return nil
	}
	src, dest := operands[0], operands[1]
	if !scanCommandArgs(args, fsFlagModels["mv"]).hasFlag("-T", "--no-target-directory") &&
		(strings.HasSuffix(dest, "/") || fsDestinationNamesDirectory(dest) || fsIsWorkspaceRoot(dest, ws)) {
		return fsMoveIntoDir(src, dest, ws, cwdUncertain)
	}
	paths := fsPaths(operands, ws, cwdUncertain)
	if len(paths) != 2 {
		if fsEscapes(operands, ws, cwdUncertain) {
			return &commandFacts{categories: []string{"workspace.escape"}}
		}
		return nil
	}
	if paths[0] == paths[1] {
		return nil
	}
	facts := &commandFacts{
		categories: []string{"fs.move"},
		mutations:  []ShellMutation{{Kind: "move", From: paths[0], To: paths[1]}},
	}
	appendCommandTarget(facts, CommandTarget{Kind: "path", Value: paths[0]})
	appendCommandTarget(facts, CommandTarget{Kind: "path", Value: paths[1]})
	return facts
}

// fsMoveIntoDir credits a move whose destination operand ends in `/`. The
// trailing slash is mv's own proof that the destination is a directory: mv
// refuses a trailing-slash destination that does not already exist as one, so
// a successful exit means it did. The file's real destination is therefore
// dir/basename(src) — never the directory path itself, which is what the
// two-operand rename form below would otherwise report.
func fsMoveIntoDir(src, dest string, ws *workspace, cwdUncertain bool) *commandFacts {
	srcPaths := fsPaths([]string{src}, ws, cwdUncertain)
	destDir, destOK := fsDirectoryPath(dest, ws, cwdUncertain)
	if len(srcPaths) != 1 || !destOK {
		if fsEscapes([]string{src, dest}, ws, cwdUncertain) {
			return &commandFacts{categories: []string{"workspace.escape"}}
		}
		return nil
	}
	if fsSourceBasenameIsDotOrDotDot(src) {
		// dir/basename(src) would name a path this command never wrote; the
		// category is credited alone, with no synthesised target.
		return &commandFacts{categories: []string{"fs.move"}}
	}
	to := path.Join(destDir, path.Base(srcPaths[0]))
	if srcPaths[0] == to {
		return nil
	}
	facts := &commandFacts{
		categories: []string{"fs.move"},
		mutations:  []ShellMutation{{Kind: "move", From: srcPaths[0], To: to}},
	}
	appendCommandTarget(facts, CommandTarget{Kind: "path", Value: srcPaths[0]})
	appendCommandTarget(facts, CommandTarget{Kind: "path", Value: to})
	return facts
}

// fsCopyTargetFlag returns the destination named by GNU cp/mv's
// -t/--target-directory form, and whether that form was used at all. The final
// occurrence wins, matching GNU option parsing while preserving alias order.
func fsCopyTargetFlag(verb string, args []string) (string, bool) {
	var value string
	found := false
	for _, flag := range scanCommandArgs(args, fsFlagModels[verb]).flags {
		if flag.name == "-t" || flag.name == "--target-directory" {
			value, found = flag.value, true
		}
	}
	return value, found
}

// fsCopy derives the candidate destination of a copy. A plain two-operand form
// uses the accepted assumption documented by fsRuntimeOutcomeUnproven, while
// two directory shapes name their destinations directly: `-t`/`--target-directory`
// names it explicitly instead — cp refuses that form unless the named
// directory already exists, so the real destination of each source is
// dir/basename(src), never the directory path itself, exactly as
// fsCopyIntoDir already computes for the trailing-slash form below: `cp -t
// backup a.txt b.txt` writes backup/a.txt and backup/b.txt, never a path
// named "backup". A trailing slash on the destination operand is the same
// proof for the other shape, exactly as fsMoveIntoDir already treats it for
// mv, no matter how many sources precede it: `cp a.txt b.txt dest/` writes
// dest/a.txt and dest/b.txt, never a path named "dest" itself. Without a
// trailing slash and more than one source, cp still requires dest to already
// exist as a directory, but nothing in the command text proves that shape, so
// only the category is credited rather than guessing a path.
func fsCopy(args, operands []string, ws *workspace, cwdUncertain bool) *commandFacts {
	scan := scanCommandArgs(args, fsFlagModels["cp"])
	if scan.hasFlag("--parents") {
		var dest string
		if target, ok := fsCopyTargetFlag("cp", args); ok {
			if target == "" || len(operands) == 0 {
				return nil
			}
			dest = target
		} else {
			if len(operands) < 2 {
				return nil
			}
			dest = operands[len(operands)-1]
		}
		if len(fsPaths([]string{dest}, ws, cwdUncertain)) == 1 {
			return &commandFacts{categories: []string{"fs.create"}}
		}
		if fsEscapes([]string{dest}, ws, cwdUncertain) {
			return &commandFacts{categories: []string{"workspace.escape"}}
		}
		return nil
	}
	if dest, ok := fsCopyTargetFlag("cp", args); ok {
		if dest == "" || len(operands) == 0 {
			return nil
		}
		facts := &commandFacts{}
		for _, src := range operands {
			facts.merge(fsCopyIntoDir(src, dest, ws, cwdUncertain))
		}
		if facts.empty() {
			return nil
		}
		return facts
	}
	if len(operands) < 2 {
		return nil
	}
	dest := operands[len(operands)-1]
	if scan.hasFlag("-T", "--no-target-directory") && scan.hasFlag("-R", "--recursive") && fsIsWorkspaceRoot(dest, ws) {
		// Recursive -T copies a source directory's contents into the existing
		// workspace root. The command proves creation but not one child path.
		return &commandFacts{categories: []string{"fs.create"}}
	}
	if !scan.hasFlag("-T", "--no-target-directory") &&
		(strings.HasSuffix(dest, "/") || fsDestinationNamesDirectory(dest) || fsIsWorkspaceRoot(dest, ws)) {
		facts := &commandFacts{}
		for _, src := range operands[:len(operands)-1] {
			facts.merge(fsCopyIntoDir(src, dest, ws, cwdUncertain))
		}
		if facts.empty() {
			return nil
		}
		return facts
	}
	if len(operands) == 2 {
		return fsCreate(operands[len(operands)-1:], ws, cwdUncertain)
	}
	return fsDestinationOnly("fs.create", dest, ws, cwdUncertain)
}

// fsDestinationOnly credits an attempted operation whose destination is
// provably inside or outside the workspace but whose exact resulting file path
// is not. It deliberately publishes no path target.
func fsDestinationOnly(category, dest string, ws *workspace, cwdUncertain bool) *commandFacts {
	if _, ok := fsDirectoryPath(dest, ws, cwdUncertain); ok {
		return &commandFacts{categories: []string{category}}
	}
	if fsEscapes([]string{dest}, ws, cwdUncertain) {
		return &commandFacts{categories: []string{"workspace.escape"}}
	}
	return nil
}

// fsCopyIntoDir credits the real destination of a copy whose sole destination
// operand ends in `/`. cp refuses that form unless the directory already
// exists, so a successful exit proves it did, and the file cp actually wrote
// is dir/basename(src) — never the pre-existing directory path itself, which
// is what crediting the raw operand would otherwise report. Only the
// destination is checked for an escape: the source is read, not written, so it
// is never the write that left the workspace.
func fsCopyIntoDir(src, dest string, ws *workspace, cwdUncertain bool) *commandFacts {
	destDir, destOK := fsDirectoryPath(dest, ws, cwdUncertain)
	if src == "" || strings.ContainsAny(src, fsShellMetacharacters) || !destOK {
		if fsEscapes([]string{dest}, ws, cwdUncertain) {
			return &commandFacts{categories: []string{"workspace.escape"}}
		}
		return nil
	}
	if fsSourceBasenameIsDotOrDotDot(src) {
		// dir/basename(src) would name a path this command never wrote; the
		// category is credited alone, with no synthesised target.
		return &commandFacts{categories: []string{"fs.create"}}
	}
	basename := path.Base(canonicalWorkspacePath(src))
	if basename == "/" || basename == "." {
		return &commandFacts{categories: []string{"fs.create"}}
	}
	to := path.Join(destDir, basename)
	facts := &commandFacts{categories: []string{"fs.create"}}
	appendCommandTarget(facts, CommandTarget{Kind: "path", Value: to})
	return facts
}

// fsCreate credits the paths a command brought into existence.
func fsCreate(operands []string, ws *workspace, cwdUncertain bool) *commandFacts {
	return fsPathFacts("fs.create", operands, ws, cwdUncertain)
}
