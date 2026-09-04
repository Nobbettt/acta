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
// file.deleted / file.moved / file.patched events. Every category here asserts
// a state change, so a failed command is credited with nothing — an `rm` that
// exited non-zero deleted no file — and so is a segment that would not
// tokenize.
func classifyFS(segment commandSegment) *commandFacts {
	if !segment.exitOK || len(segment.tokens) == 0 {
		return nil
	}
	verb, args := fsVerb(segment.tokens)
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
	}
	if fsRuntimeOutcomeUnproven(verb, scan) {
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
	operands, redirected := fsOperands(verb, args)
	var facts *commandFacts
	switch verb {
	case "rm":
		facts = fsDelete(operands, segment.ws, segment.cwdUncertain)
	case "git rm":
		// A dry run, or `--cached`/`--staged` (which only untracks the path —
		// the file is still on disk), all assert a deletion that did not happen.
		if scan.hasFlag("--pathspec-from-file") {
			return &commandFacts{categories: []string{"fs.delete"}}
		}
		facts = fsDelete(operands, segment.ws, segment.cwdUncertain)
	case "mv":
		facts = fsMove(ownArgs, operands, segment.ws, segment.cwdUncertain)
	case "cp":
		facts = fsCopy(ownArgs, operands, segment.ws, segment.cwdUncertain)
	case "touch":
		facts = fsCreate(operands, segment.ws, segment.cwdUncertain)
	case "mkdir":
		facts = fsCreate(operands, segment.ws, segment.cwdUncertain)
	case "patch":
		facts = fsPatch(ownArgs, operands, redirected, segment.ws, segment.cwdUncertain)
	case "git apply", "git cherry-pick", "git revert":
		// The operands name a patch file or a commit, never the files rewritten.
		facts = fsPatch(ownArgs, nil, false, segment.ws, segment.cwdUncertain)
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
		return scan.hasFlag("-f", "-i", "-I")
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

type commandFlagArity uint8

const (
	flagBoolean commandFlagArity = iota + 1
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
	},
	"git rm": {
		"-f": flagBoolean, "-n": flagBoolean, "-q": flagBoolean, "-r": flagBoolean,
		"--cached": flagBoolean, "--dry-run": flagBoolean, "--staged": flagBoolean,
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
		"-i": flagBoolean, "-n": flagBoolean, "-p": flagBoolean,
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

// fsOperands returns the non-flag arguments of a filesystem command and reports
// whether it redirected a stream. `--` ends the flags, so `rm -- -oddly-named`
// still credits the file; from the first redirection operator or control
// operator on, an argument names a stream, a downstream command or the
// background rather than this command's own operand. verb's entry in
// fsFlagModels, if any, is consulted to skip the value of a flag that takes
// one, so that value is never credited as an operand either.
func fsOperands(verb string, args []string) ([]string, bool) {
	ownArgs := fsOwnArgs(args)
	redirected := len(ownArgs) < len(args) && isRedirection(args[len(ownArgs)])
	return scanCommandArgs(ownArgs, fsFlagModels[verb]).operands, redirected
}

// fsOwnArgs returns the prefix of args that belongs to this verb's own
// invocation, up to the same stopping points fsOperands already applies when
// collecting operands: a redirection, or a pipe/control operator that hands
// the rest of the line to a different command. A flag scan that skipped this
// truncation would read a downstream stage's own flag as this verb's own —
// `cp a.txt b.txt | xargs -t rm` names xargs's -t, not cp's, so
// fsCopyTargetFlag, fsPatch's inspect-flag scan and the git-rm
// `--cached`/`--staged` check must all see this slice, never the raw one.
func fsOwnArgs(args []string) []string {
	for i, arg := range args {
		if isRedirection(arg) || arg == "|" || arg == "|&" || arg == "&" {
			return args[:i]
		}
	}
	return args
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
			if arity == 0 {
				scan.unknownFlag = true
			}
			if arity == flagValue && !attached && i+1 < len(args) {
				i++
				value = args[i]
			}
			scan.flags = append(scan.flags, commandFlag{name: name, value: value, arity: arity, index: argIndex})
		case len(arg) >= 3 && arg[2] == '=' && model[arg[:2]] == flagBoolean:
			scan.flags = append(scan.flags, commandFlag{name: arg[:2], value: arg[3:], arity: flagBoolean, index: argIndex})
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

func (scan commandArgScan) hasFlag(names ...string) bool {
	for _, flag := range scan.flags {
		for _, name := range names {
			if flag.name == name && flag.enabled() {
				return true
			}
		}
	}
	return false
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

// enabled reports whether a flag activates its boolean mode. Some CLIs accept
// --flag=false; the scanner preserves that attached value so mode classifiers
// do not mistake an explicitly disabled option for an enabled one.
func (flag commandFlag) enabled() bool {
	return flag.arity != flagBoolean || !strings.EqualFold(flag.value, "false")
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

// isRedirection reports whether tok opens a redirection (`<`, `>`, `2>`, `&>`,
// `<<EOF`), including the attached form where the stream name follows in the
// same token.
func isRedirection(tok string) bool {
	rest := strings.TrimLeft(tok, "0123456789&")
	return strings.HasPrefix(rest, "<") || strings.HasPrefix(rest, ">")
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
	return strings.HasPrefix(operand, "/") || filepath.IsAbs(operand)
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
// `mv a b c` moves each source into a directory, but this classifier does not
// derive that multi-source shape, so guessing wrong cannot report files at
// paths that never existed.
func fsMove(args, operands []string, ws *workspace, cwdUncertain bool) *commandFacts {
	if dest, ok := fsCopyTargetFlag("mv", args); ok {
		if dest == "" || len(operands) == 0 {
			return nil
		}
		facts := &commandFacts{}
		for _, src := range operands {
			facts.merge(fsMoveIntoDir(src, dest, ws, cwdUncertain))
		}
		if facts.empty() {
			return nil
		}
		return facts
	}
	if len(operands) < 2 {
		return nil
	}
	if len(operands) > 2 {
		return fsDestinationOnly("fs.move", operands[len(operands)-1], ws, cwdUncertain)
	}
	src, dest := operands[0], operands[1]
	if strings.HasSuffix(dest, "/") || fsDestinationNamesDirectory(dest) || fsIsWorkspaceRoot(dest, ws) {
		return fsMoveIntoDir(src, dest, ws, cwdUncertain)
	}
	paths := fsPaths(operands, ws, cwdUncertain)
	if len(paths) != 2 {
		if fsEscapes(operands, ws, cwdUncertain) {
			return &commandFacts{categories: []string{"workspace.escape"}}
		}
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
	facts := &commandFacts{
		categories: []string{"fs.move"},
		mutations:  []ShellMutation{{Kind: "move", From: srcPaths[0], To: to}},
	}
	appendCommandTarget(facts, CommandTarget{Kind: "path", Value: srcPaths[0]})
	appendCommandTarget(facts, CommandTarget{Kind: "path", Value: to})
	return facts
}

// commandFlagValue returns the value of flag short/long in whichever spelling args
// uses, and whether the flag was present at all: a separate token (`-t
// backup`), an attached short value (`-tbackup`), a `--long=value` form, or
// the flag packed after boolean short flags (`-rt backup`, `-Nfo new.txt`).
// `-T` (cp's "treat DEST as a normal file", a different, uppercase letter)
// never matches a lowercase short flag here.
//
// value is "" when the flag was present but no value could be read — a bare
// `-t` at the end of the line, or a cluster's last letter with nothing after
// it — and the caller must not treat that the same as "flag absent": e.g.
// fsCopy relies on telling "no destination named" apart from "-t not given".
func commandFlagValue(args []string, model commandFlagModel, short, long string) (value string, ok bool) {
	return scanCommandArgs(args, model).flagValue(short, long)
}

// fsCopyTargetFlag returns the destination named by GNU cp/mv's
// -t/--target-directory form, and whether that form was used at all.
func fsCopyTargetFlag(verb string, args []string) (string, bool) {
	return commandFlagValue(args, fsFlagModels[verb], "-t", "--target-directory")
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
	if strings.HasSuffix(dest, "/") || fsDestinationNamesDirectory(dest) || fsIsWorkspaceRoot(dest, ws) {
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
	srcPaths := fsPaths([]string{src}, ws, cwdUncertain)
	destDir, destOK := fsDirectoryPath(dest, ws, cwdUncertain)
	if len(srcPaths) != 1 || !destOK {
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
	to := path.Join(destDir, path.Base(srcPaths[0]))
	facts := &commandFacts{categories: []string{"fs.create"}}
	appendCommandTarget(facts, CommandTarget{Kind: "path", Value: to})
	return facts
}

// fsCreate credits the paths a command brought into existence.
func fsCreate(operands []string, ws *workspace, cwdUncertain bool) *commandFacts {
	return fsPathFacts("fs.create", operands, ws, cwdUncertain)
}

// fsPatchOutput returns patch's -o/--output value in any accepted spelling.
// A named output leaves the input operand untouched; stdout and /dev/null also
// prove that the command changed no filesystem path.
func fsPatchOutput(args []string) (string, bool) {
	return commandFlagValue(args, fsFlagModels["patch"], "-o", "--output")
}

// outputTargetsWorkspaceFile reports whether an explicit output destination
// resolves to a file inside the recorded workspace. Device paths, stdout,
// outside absolute paths, shell expressions, and relative paths after an
// uncertain cwd all fail closed through the workspace resolver.
func outputTargetsWorkspaceFile(destination string, ws *workspace, cwdUncertain bool) bool {
	destination = strings.TrimSpace(destination)
	if destination == "-" || strings.ContainsAny(destination, fsShellMetacharacters) ||
		cwdUncertain && !fsOperandAbsolute(destination) {
		return false
	}
	_, ok := normalizeWorkspacePath(destination, ws)
	return ok
}

// fsPatchDirectory returns patch's -d/--directory value in any accepted
// spelling. patch chdirs there before applying a relative file operand.
func fsPatchDirectory(args []string) (string, bool) {
	return commandFlagValue(args, fsFlagModels["patch"], "-d", "--directory")
}

// fsPatch credits the patch itself, and a path only where the command proves
// one. `git apply f.diff`, `git cherry-pick <sha>` and `patch -p1 < f.diff` all
// name the patch or the commit, never the files rewritten: those live in the
// patch body, which the digest never sees. The one provable shape is
// `patch <file> < f.diff` — with the diff arriving on stdin, the single
// remaining operand is the file that was rewritten. -o/--output names the
// effective output directly, while -d/--directory relocates a relative
// operand beneath its resolved directory.
func fsPatch(args, operands []string, redirected bool, ws *workspace, cwdUncertain bool) *commandFacts {
	scan := scanCommandArgs(args, fsFlagModels["patch"])
	output, redirectsOutput := fsPatchOutput(args)
	if scan.hasFlag(fsInspectFlags...) {
		return nil
	}
	facts := &commandFacts{categories: []string{"fs.patch"}}
	if scan.unknownFlag {
		return facts
	}
	if !redirected {
		return facts
	}
	var destination string
	if redirectsOutput {
		cleanOutput := canonicalWorkspacePath(output)
		if output == "" || output == "-" || cleanOutput == "/dev/null" || cleanOutput == "/dev/zero" ||
			cleanOutput == "/dev/stdout" || cleanOutput == "/dev/stderr" || strings.HasPrefix(cleanOutput, "/dev/fd/") {
			return nil
		}
		if !outputTargetsWorkspaceFile(output, ws, cwdUncertain) {
			if fsEscapes([]string{output}, ws, cwdUncertain) {
				return &commandFacts{categories: []string{"workspace.escape"}}
			}
			return nil
		}
		destination = output
	} else {
		if len(operands) != 1 {
			return facts
		}
		destination = operands[0]
		if directory, hasDirectory := fsPatchDirectory(args); hasDirectory && !fsOperandAbsolute(destination) {
			dir, ok := fsDirectoryPath(directory, ws, cwdUncertain)
			if !ok {
				if fsEscapes([]string{directory}, ws, cwdUncertain) {
					return &commandFacts{categories: []string{"workspace.escape"}}
				}
				return facts
			}
			destination = path.Join(dir, filepath.ToSlash(destination))
		}
	}
	paths := fsPaths([]string{destination}, ws, cwdUncertain)
	if len(paths) != 1 {
		if fsEscapes([]string{destination}, ws, cwdUncertain) {
			return &commandFacts{categories: []string{"workspace.escape"}}
		}
		return facts
	}
	appendCommandTarget(facts, CommandTarget{Kind: "path", Value: paths[0]})
	facts.mutations = append(facts.mutations, ShellMutation{Kind: "patch", Path: paths[0]})
	return facts
}
