package digest

import (
	neturl "net/url"
	"path"
	"regexp"
	"slices"
	"strings"
)

// classifyVCS owns the version-control and forge slice of the category table:
// vcs.read, vcs.mutate, vcs.rewrite, vcs.provenance and forge.mutate. It only
// looks at segments that actually invoke git, so a `git` word buried in a
// pipeline or an echo argument is never credited.

// gitObjectNameRe matches a full 40-hex object name, the only sha shape
// `git rev-parse HEAD` proves. Abbreviated output stays uncredited.
var gitObjectNameRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// gitGlobalFlagModel keeps global option values out of the subcommand scan, so
// `git -C path status` still finds status while an unknown option fails closed.
var gitGlobalFlagModel = commandFlagModel{
	"--bare": flagBoolean, "--no-pager": flagBoolean, "--paginate": flagBoolean,
	"--literal-pathspecs": flagBoolean, "--glob-pathspecs": flagBoolean,
	"--noglob-pathspecs": flagBoolean, "--icase-pathspecs": flagBoolean,
	"-C": flagValue, "-c": flagValue, "--git-dir": flagValue,
	"--work-tree": flagValue, "--namespace": flagValue, "--super-prefix": flagValue,
	"--exec-path": flagAttachedValue,
	"--help":      flagBoolean, "-h": flagBoolean, "--version": flagBoolean,
	"--html-path": flagBoolean, "--man-path": flagBoolean, "--info-path": flagBoolean,
	"--list-cmds": flagAttachedValue,
}

// gitGlobalInformationalFlags print documentation instead of running the verb
// that follows them: `git --help commit` documents commit, `git --version
// commit` prints the version and never reaches commit at all.
// A bare `--exec-path` (no attached value) is in the same family: git prints
// the path and exits instead of running the verb. With a value it is a real
// prefix, so only the valueless spelling terminates.
var gitGlobalInformationalFlags = []string{
	"--help", "-h", "--version", "--html-path", "--man-path", "--info-path",
	"--list-cmds",
}

// gitRepoRedirectFlags point git at a repository or working tree other than
// the one the classifier assumes it runs in. There is no cwd tracking here,
// so a command using one of these cannot be proven to have changed the
// workspace this run is about — crediting a state change would be a guess,
// not a fact the command text proves.
var gitRepoRedirectFlags = []string{"-C", "--git-dir", "--work-tree"}

var (
	gitReadVerbs   = []string{"status", "diff", "log", "show", "blame", "ls-files"}
	gitMutateVerbs = []string{"add", "commit", "checkout", "switch", "merge", "restore", "reset"}
)

// gitBranchTagReadOnlyFlags select a listing/query form of `branch` or `tag`
// rather than a change to it. Their presence disqualifies vcs.mutate even if a
// non-flag argument (e.g. a ref to filter by) is also present.
var gitBranchTagReadOnlyFlags = map[string][]string{
	"branch": {
		"-a", "-r", "-l", "--list", "-v", "--verbose", "--show-current",
		"--contains", "--no-contains", "--merged", "--no-merged", "--points-at", "--format", "--sort",
	},
	"tag": {
		"-l", "--list", "-n", "-v", "--verify",
		"--contains", "--no-contains", "--merged", "--no-merged", "--points-at", "--format", "--sort",
	},
}

// gitBranchTagMutateFlags change a branch or tag even with no positional
// argument, e.g. `git branch -d` reads the name to delete from its own -d/-D
// operand handling, but the flag alone already proves a mutation is intended.
var gitBranchTagMutateFlags = []string{"-d", "-D", "-m", "-M", "-c", "-C", "-f", "--force", "--delete", "--move", "--copy"}

// gitStashReadOnlyVerbs are the `git stash` sub-verbs that only inspect the
// stash. Every other sub-verb, including the bare form, changes it.
var gitStashReadOnlyVerbs = []string{"list", "show"}

// gitNoOpFlags maps a git verb to the flags that prove THIS invocation made
// none of the changes its name would otherwise imply: `--dry-run`/`-n`
// simulate the mutation, and rm/add's own `--cached`/`--staged` only change
// the index, never the working tree — the same "asserted a change it did
// not make" fact under a different name. Every verb below is credited a
// state change elsewhere in this package (gitVerbMutates, gitRewrites, or
// classifyFS's `git rm` case), so a hit here must veto that credit rather
// than add a new one. A verb absent from this table has no no-op spelling
// this package knows to check; where a flag means something else for a verb
// it is deliberately excluded rather than guessed at — mv/cp's own `-n` is
// `--no-clobber`, not a dry run, and this table is git-only.
var gitNoOpFlags = map[string][]string{
	"rm":     {"--dry-run", "-n", "--cached", "--staged"},
	"add":    {"--dry-run", "-n"},
	"commit": {"--dry-run"},
	"push":   {"--dry-run", "-n"},
}

var gitFlagModels = map[string]commandFlagModel{
	"rm": {
		"-f": flagBoolean, "-n": flagBoolean, "-q": flagBoolean, "-r": flagBoolean,
		"--cached": flagBoolean, "--dry-run": flagBoolean, "--staged": flagBoolean,
		"--pathspec-from-file": flagValue, "--pathspec-file-nul": flagBoolean,
	},
	"add": {
		"-f": flagBoolean, "-n": flagBoolean, "-v": flagBoolean, "-A": flagBoolean,
		"-i": flagBoolean, "--interactive": flagBoolean,
	},
	"commit": {
		"-m": flagValue, "--message": flagValue, "-F": flagValue, "--file": flagValue,
		"--author": flagValue, "--date": flagValue,
		"--amend": flagBoolean, "--dry-run": flagBoolean, "--no-edit": flagBoolean,
	},
	"push": {
		"-f": flagBoolean, "--force": flagBoolean, "-q": flagBoolean, "--quiet": flagBoolean, "-v": flagBoolean,
		"-u": flagBoolean, "--set-upstream": flagBoolean,
		"-n": flagBoolean, "--dry-run": flagBoolean,
		"-o": flagValue, "--push-option": flagValue,
		"--force-with-lease": flagAttachedValue,
	},
	"stash": {
		"-m": flagValue, "--message": flagValue,
	},
	"branch": {
		"-a": flagBoolean, "-r": flagBoolean, "-l": flagBoolean,
		"-v": flagBoolean, "-d": flagBoolean, "-D": flagBoolean,
		"-m": flagBoolean, "-M": flagBoolean, "-c": flagBoolean,
		"-C": flagBoolean, "-f": flagBoolean,
		"--contains": flagValue, "--no-contains": flagValue,
		"--merged": flagValue, "--no-merged": flagValue,
		"--points-at": flagValue, "--format": flagValue, "--sort": flagValue,
	},
	"tag": {
		"-a": flagBoolean, "-l": flagBoolean, "-v": flagBoolean,
		"-d": flagBoolean, "-f": flagBoolean, "-n": flagAttachedValue,
		"-m": flagValue, "-F": flagValue,
		"--contains": flagValue, "--no-contains": flagValue,
		"--merged": flagValue, "--no-merged": flagValue,
		"--points-at": flagValue, "--format": flagValue, "--sort": flagValue,
	},
	"reset": {
		"--hard": flagBoolean,
	},
	"rebase": {
		"-i": flagBoolean, "--interactive": flagBoolean,
	},
	"rev-parse": {
		"--path-format": flagValue, "--default": flagValue, "--prefix": flagValue,
		"--resolve-git-dir": flagValue, "--disambiguate": flagValue, "--exclude": flagValue,
		"--short": flagAttachedValue, "--verify": flagBoolean,
	},
	"remote": {
		"-v": flagBoolean, "--verbose": flagBoolean,
	},
}

// gitAssertsNoChange reports whether ownArgs prove verb made none of the
// changes it would otherwise be credited with, checking every spelling
// gitNoOpFlags[verb] lists: a bare token, or, for a single-letter flag,
// packed into a short-option cluster the way git's own parser accepts
// (`git rm -rn` alongside `git rm -r -n`).
// One predicate serves classifyFS's `git rm` case and classifyVCS's
// add/commit/push handling alike, so a fix to this rule is a fix for every
// verb at once rather than one sibling at a time.
func gitAssertsNoChange(verb string, ownArgs []string) bool {
	model := gitFlagModels[verb]
	if commandAssertsNoChange(ownArgs, model) {
		return true
	}
	scan := scanCommandArgs(ownArgs, model)
	for _, flag := range gitNoOpFlags[verb] {
		if scan.hasFlag(flag) {
			return true
		}
	}
	return false
}

// gitVerbMutates reports whether a git verb's arguments prove a change to the
// repository, as opposed to a same-named listing form. `branch` and `tag`
// list by default and only mutate given a mutating flag or a name to act on;
// `stash list`/`stash show` are read-only while every other stash sub-verb
// changes the stash. Every other verb in gitMutateVerbs always mutates.
func gitVerbMutates(verb string, args []string) bool {
	switch verb {
	case "branch", "tag":
		scan := scanCommandArgs(args, gitFlagModels[verb])
		if scan.unknownFlag {
			return false
		}
		if scan.hasFlag(gitBranchTagReadOnlyFlags[verb]...) {
			return false
		}
		if scan.hasFlag(gitBranchTagMutateFlags...) {
			return true
		}
		return len(scan.operands) != 0
	case "stash":
		return !slices.Contains(gitStashReadOnlyVerbs, gitFirstArg(verb, args))
	default:
		return slices.Contains(gitMutateVerbs, verb)
	}
}

func classifyVCS(segment commandSegment) *commandFacts {
	if !vcsExecutionProven(segment) {
		return nil
	}
	verb, args, redirected, informational, ok := gitInvocation(segment.tokens)
	if !ok {
		return nil
	}
	if informational {
		return nil
	}
	// An informational invocation (`git status --help`, `git log --version`)
	// prints documentation and performs no work at all, so it is not even an
	// observed read. classifyExec applies the same gate to its own verbs; this
	// keeps the two classifiers from disagreeing about the same shape.
	if commandAssertsNoChange(args, gitFlagModels[verb]) {
		return nil
	}
	facts := &commandFacts{}
	if slices.Contains(gitReadVerbs, verb) {
		facts.categories = append(facts.categories, "vcs.read")
	}
	// A provenance read is observational: the command ran, so the category is
	// true even when this classifier cannot tell which repository answered it.
	// The identifying VALUE is the unprovable part, so a redirect or an earlier
	// `cd`/`pushd` withholds the target while keeping the category.
	gitProvenance(facts, verb, args, segment.output, !redirected && !segment.cwdUncertain)
	// Everything below asserts a change to the repository, so it needs the
	// command to have succeeded, and to have run against this repository:
	// redirected means -C/--git-dir/--work-tree sent it somewhere this
	// classifier cannot see, and cwdUncertain means an earlier `cd`/`pushd` in
	// the same command may have sent it somewhere this classifier cannot see
	// either — a `cd ../other && git commit` is the same act as
	// `git -C ../other commit`, and must be denied the same way. A rewrite
	// outranks the plain mutation it is a variant of — `git commit --amend` is
	// a rewrite, not also a mutate — but it does not outrank forge.mutate,
	// which is a different fact about a different place: a force push both
	// rewrote history and changed the forge.
	// Verbs with a dry-run spelling need a complete flag parse before a state
	// change is provable. An opaque cluster may hide that spelling, so fail
	// closed while retaining any observational facts already established above.
	flagsCertain := true
	if _, hasNoOpFlags := gitNoOpFlags[verb]; hasNoOpFlags {
		flagsCertain = !scanCommandArgs(args, gitFlagModels[verb]).unknownFlag
	}
	if segment.exitOK && !redirected && !segment.cwdUncertain && flagsCertain {
		noOp := gitAssertsNoChange(verb, args)
		rewrite := gitRewrites(verb, args) && !noOp
		if rewrite {
			facts.categories = append(facts.categories, "vcs.rewrite")
		}
		switch {
		case verb == "push" && !noOp:
			facts.categories = append(facts.categories, "forge.mutate")
		case !rewrite && !noOp && gitVerbMutates(verb, args):
			facts.categories = append(facts.categories, "vcs.mutate")
		}
	}
	if facts.empty() {
		return nil
	}
	return facts
}

// vcsExecutionProven extends the shared execution gate for a branch that the
// central pruner retained after carrying a known literal outcome across skipped
// terms. The older gate rejects every later conditional segment; consulting the
// pruned chain admits only the cases whose preceding executed outcome proves
// this segment ran.
func vcsExecutionProven(segment commandSegment) bool {
	if execExecutionProven(segment) {
		return true
	}
	raw, valid := splitRawChain(segment.command)
	if !valid {
		return false
	}
	raw, valid = stripHeredocBodies(raw)
	if !valid {
		return false
	}
	for _, part := range pruneUnexecuted(raw) {
		if part.raw == segment.raw && part.executed {
			return true
		}
	}
	return false
}

// gitInvocation returns the subcommand of a segment that runs git, plus the
// tokens after it. Leading env assignments, `sudo`, and `env` used as an
// assignment runner are allowed — the same prefixes classifyExec strips, via
// the shared execLeadingTokens, so the two classifiers agree on what counts as
// a git invocation. git's own global flags are skipped, and anything else —
// including an empty token slice from the tokenizer refusing the segment —
// reports false. redirected reports whether one of gitRepoRedirectFlags was
// among the skipped flags, in either its separate-token (`-C path`) or
// attached (`--git-dir=path`) spelling. args is truncated at the first
// redirection or control token via fsOwnArgs, the same truncation classifyFS
// and classifyExec already apply to their own verbs' arguments — without it,
// `git tag > tags.txt` reads the redirection's target filename as the tag name
// to create, crediting vcs.mutate for a command that listed and changed
// nothing.
// It also reports whether a global informational flag appeared before the verb,
// which makes the whole invocation documentation rather than work.
func gitInvocation(tokens []string) (verb string, args []string, redirected, informational, ok bool) {
	redirected = gitEnvironmentRedirectsRepository(tokens)
	tokens = execLeadingTokens(tokens)
	if len(tokens) == 0 || path.Base(tokens[0]) != "git" {
		return "", nil, false, false, false
	}
	scan := scanCommandArgs(tokens[1:], gitGlobalFlagModel)
	if len(scan.operands) == 0 {
		return "", nil, false, false, false
	}
	verbIndex := scan.operandIndexes[0]
	for _, flag := range scan.flags {
		if flag.index >= verbIndex {
			continue
		}
		if slices.Contains(gitRepoRedirectFlags, flag.name) {
			redirected = true
		}
		if slices.Contains(gitGlobalInformationalFlags, flag.name) {
			informational = true
		}
		if flag.name == "--exec-path" && flag.value == "" {
			informational = true
		}
	}
	verbIndex++ // scan indexes tokens[1:]
	return tokens[verbIndex], fsOwnArgs(tokens[verbIndex+1:]), redirected, informational, true
}

var gitRepoRedirectEnvironment = []string{"GIT_DIR", "GIT_WORK_TREE"}

// gitEnvironmentRedirectsRepository reports a leading Git environment
// assignment that selects a repository or work tree. execLeadingTokens removes
// these prefixes before the Git parser runs, so this check must happen first;
// both `GIT_DIR=... git` and `env GIT_DIR=... git` are covered.
func gitEnvironmentRedirectsRepository(tokens []string) bool {
	for _, token := range tokens {
		name, _, assignment := strings.Cut(token, "=")
		if assignment {
			if slices.Contains(gitRepoRedirectEnvironment, name) {
				return true
			}
			continue
		}
		if token == "sudo" || token == "env" {
			continue
		}
		return false // the first non-prefix token is the command word
	}
	return false
}

// gitRewrites reports whether the invocation rewrites history that already
// existed, as opposed to adding to it.
func gitRewrites(verb string, args []string) bool {
	scan := scanCommandArgs(args, gitFlagModels[verb])
	switch verb {
	case "rebase", "filter-branch":
		return true
	case "commit":
		return scan.hasFlag("--amend")
	case "reset":
		return scan.hasFlag("--hard")
	case "stash":
		return gitFirstArg(verb, args) == "drop"
	case "push":
		return scan.hasFlag("-f", "--force", "--force-with-lease")
	}
	return false
}

// gitProvenance credits the two commands that pin what the work was done
// against, and lifts the sha or remote out of the bounded output when it is
// there. Empty or oversized output proves nothing, so the category is still
// credited but no target is.
func gitProvenance(facts *commandFacts, verb string, args []string, output string, trustTargets bool) {
	scan := scanCommandArgs(args, gitFlagModels[verb])
	if scan.unknownFlag {
		return
	}
	switch {
	case verb == "rev-parse" && slices.Equal(scan.operands, []string{"HEAD"}):
		facts.categories = append(facts.categories, "vcs.provenance")
		sha := strings.TrimSpace(output)
		if trustTargets && gitObjectNameRe.MatchString(sha) {
			appendCommandTarget(facts, CommandTarget{Kind: "ref", Value: sha})
		}
	case verb == "remote" && len(scan.operands) == 0 && scan.hasFlag("-v", "--verbose"):
		facts.categories = append(facts.categories, "vcs.provenance")
		if !trustTargets {
			return
		}
		for _, remoteURL := range gitRemoteURLs(output) {
			appendCommandTarget(facts, CommandTarget{Kind: "url", Value: remoteURL})
		}
	}
}

// gitRemoteURLs reads the `name<tab>url (fetch)` lines `git remote -v` prints.
// The trailing `(fetch)`/`(push)` marker is required: it is what proves the
// line came from that command and not from something else in the output.
// Every producer of a url target shares the same sanitizing pair —
// stripURLCredentials then execStripURLQuery, as execFirstURL and execPackage
// in commandclass_exec.go both apply to an argument — so a query string or
// fragment is cut here too. This one is the higher-risk of the three: its
// input is command OUTPUT rather than the agent's own argv, so a
// credential-bearing query string (`?private_token=...`) reaches this
// classifier via whatever the remote happened to be configured with.
// gitRemoteOrigin reduces a remote URL to scheme://host, or to the bare host
// for the scp-like `git@host:path` spelling git also prints. Anything it cannot
// reduce to a host is dropped: a target it cannot prove is safe is not worth
// publishing.
func gitRemoteOrigin(raw string) string {
	sanitized := stripURLCredentials(raw)
	if sanitized == "" {
		return ""
	}
	if u, err := neturl.Parse(sanitized); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	// scp-like: [user@]host:path. Only this exact shape is accepted — a
	// `user@host` prefix followed by a colon before the path — because the
	// sanitizer already refuses anything more ambiguous. The host must look
	// like a host (a dotted name or a bracketed address); otherwise this is
	// some opaque spelling and no target is published at all.
	at := strings.LastIndex(sanitized, "@")
	if at < 0 {
		return ""
	}
	rest := sanitized[at+1:]
	colon := strings.Index(rest, ":")
	if colon <= 0 {
		return ""
	}
	host := rest[:colon]
	if !strings.Contains(host, ".") || strings.ContainsAny(host, " /") {
		return ""
	}
	return host
}

func gitRemoteURLs(output string) []string {
	var urls []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || (fields[2] != "(fetch)" && fields[2] != "(push)") {
			continue
		}
		// Only the origin — scheme and host — is published. A remote's PATH can
		// itself carry a secret (a token-in-path clone URL), and the path adds
		// nothing to the provenance fact that this run talked to that host, so
		// it is dropped rather than sanitized shape by shape.
		if origin := gitRemoteOrigin(fields[1]); origin != "" && !slices.Contains(urls, origin) {
			urls = append(urls, origin)
		}
	}
	return urls
}

// stripURLCredentials drops any userinfo (`user:token@`) from a URL before it
// is published as a CommandTarget. A target is provenance about where a
// command reached, not a place to publish whatever credential happened to be
// embedded in the argument. The scp-like `git@host:path` shape git prints has
// no "://" for net/url to find a scheme in, so it parses with no userinfo and
// passes through unchanged — which is correct, since that leading name is a
// fixed transport user, not a secret. Shared with commandclass_exec.go, which
// has the same class of URL argument to sanitize.
//
// net/url.Parse rejects a userinfo containing characters like `|`, `^`, or an
// invalid `%` escape — exactly the shape a raw secret is likely to have. On
// that error this falls back to a textual scan rather than publishing raw
// unchanged, so a credential a strict parser objects to does not leak for
// that reason alone.
func stripURLCredentials(raw string) string {
	u, err := neturl.Parse(raw)
	if err != nil {
		return stripURLCredentialsTextual(raw)
	}
	if u.User == nil {
		return stripURLCredentialsTextual(raw)
	}
	u.User = nil
	if u.Host == "" {
		return ""
	}
	return u.String()
}

// stripURLCredentialsTextual removes userinfo from a standard authority or an
// opaque `user:password@host/path` spelling. The scp-like `git@host:path` form
// remains: its colon follows the @ and therefore proves there is no password.
func stripURLCredentialsTextual(raw string) string {
	schemeEnd := strings.Index(raw, "://")
	if schemeEnd >= 0 {
		authorityStart := schemeEnd + len("://")
		rest := raw[authorityStart:]
		end := len(rest)
		if i := strings.IndexAny(rest, "/?#"); i >= 0 {
			end = i
		}
		authority := rest[:end]
		at := strings.LastIndexByte(authority, '@')
		if at < 0 {
			return raw
		}
		authority = authority[at+1:]
		if authority == "" || strings.HasPrefix(authority, ":") {
			return ""
		}
		return raw[:authorityStart] + authority + rest[end:]
	}
	end := len(raw)
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		end = i
	}
	prefix := raw[:end]
	at := strings.LastIndexByte(prefix, '@')
	colon := strings.IndexByte(prefix, ':')
	if at < 0 || at == 0 || colon > at {
		return raw
	}
	if colon < 0 {
		return ""
	}
	if at+1 == end {
		return ""
	}
	return raw[at+1:]
}

// gitFirstArg is the first non-flag token after the verb, i.e. the sub-verb of
// commands like `git stash drop`.
func gitFirstArg(verb string, args []string) string {
	operands := scanCommandArgs(args, gitFlagModels[verb]).operands
	if len(operands) != 0 {
		return operands[0]
	}
	return ""
}
