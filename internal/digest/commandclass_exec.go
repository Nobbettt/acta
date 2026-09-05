package digest

// classifyExec owns the execution slice of the category table: network.egress,
// forge.mutate, package.install, verify.run, search.query, container.run,
// process.background, archive.extract, permission.changed, env.inspect,
// command.interactive, and the three flag forms of workspace.escape that are
// properties of an exec command rather than of a path.
//
// Every rule keys off the segment's leading command word, so a command word
// that merely appears as an argument (`echo curl https://x`) is never credited.

import (
	"net"
	neturl "net/url"
	"path"
	"slices"
	"strconv"
	"strings"
)

// execCommand is one segment reduced to its leading command word and that
// word's own arguments — the arguments stop at the first pipe or redirection so
// a downstream command's operands are never mistaken for this one's.
type execCommand struct {
	word string
	args []string
	seg  commandSegment
}

func classifyExec(seg commandSegment) *commandFacts {
	tokens := execLeadingTokens(seg.tokens)
	if len(tokens) == 0 {
		return nil
	}
	cmd := execCommand{word: path.Base(tokens[0]), args: fsOwnArgs(tokens[1:]), seg: seg}
	if !execExecutionProven(seg) {
		if execTrailingAmpersand(seg) && execBackgroundLaunchProven(seg) {
			return execBackground(cmd)
		}
		return nil
	}
	if execCommandAssertsNoChange(cmd) {
		return execNoChangeWrites(cmd)
	}
	facts := &commandFacts{}
	for _, rule := range execRules {
		facts.merge(rule(cmd))
	}
	if facts.empty() {
		return nil
	}
	return facts
}

// execExecutionProven rejects a conditional branch or post-loader command that
// may not have run. A proven successful status is sufficient; observational
// rules on failed commands additionally require pruneUnexecuted to prove that
// an equal segment started. Equal segments are harmless because the facts were
// then proved by at least one identical invocation.
func execExecutionProven(seg commandSegment) bool {
	if seg.exitOK {
		return true
	}
	raw, valid := splitRawChain(seg.command)
	if !valid {
		return false
	}
	raw, valid = stripHeredocBodies(raw)
	if !valid {
		return false
	}
	for _, part := range pruneUnexecuted(raw) {
		if part.executed && part.raw == seg.raw {
			return true
		}
	}
	return false
}

// execBackgroundLaunchProven allows an uncertain command inside a launched
// background AND-list, but not one after a parent-shell loader or terminator
// that may have ended the list before the job was launched.
func execBackgroundLaunchProven(seg commandSegment) bool {
	raw, valid := splitRawChain(seg.command)
	if !valid {
		return false
	}
	raw, valid = stripHeredocBodies(raw)
	if !valid {
		return false
	}
	for _, part := range pruneUnexecuted(raw) {
		if part.raw == seg.raw {
			return true
		}
		if containsShellControlCommand(tokensForSegment(part.raw), "eval", "source", ".", "exit", "exec") {
			return false
		}
	}
	return false
}

var execRules = []func(execCommand) *commandFacts{
	execNetwork,
	execForge,
	execPackage,
	execVerify,
	execSearch,
	execContainer,
	execBackground,
	execArchive,
	execPermission,
	execEnvInspect,
	execInteractive,
	execEscapeFlags,
}

// execLeadingTokens drops the prefixes that stand in front of the real command
// word — environment assignments, `sudo`, and `env` used as an assignment
// runner — so `FOO=1 sudo chmod +x x` still classifies as a chmod. A bare `env`
// is left alone: that one is an inspection, not a prefix.
func execLeadingTokens(tokens []string) []string {
	for i, token := range tokens {
		switch {
		case execIsAssignment(token):
		case token == "sudo":
		case token == "env" && i+1 < len(tokens) && execIsAssignment(tokens[i+1]):
		default:
			return tokens[i:]
		}
	}
	return nil
}

func execIsAssignment(token string) bool {
	eq := strings.IndexByte(token, '=')
	if eq <= 0 {
		return false
	}
	for i, r := range token[:eq] {
		if r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
			continue
		}
		if i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

func execFacts(category string, targets ...CommandTarget) *commandFacts {
	facts := &commandFacts{categories: []string{category}}
	for _, target := range targets {
		appendCommandTarget(facts, target)
	}
	return facts
}

// appendCommandTarget is the only route from a classifier into the published
// target set. Every wire kind is handled explicitly; free-form patterns and
// unknown kinds fail closed, URL targets are reduced to an origin, and shell
// expressions that this package never expands are rejected.
func appendCommandTarget(facts *commandFacts, target CommandTarget) {
	if target.Kind != "path" {
		target.Value = strings.TrimSpace(target.Value)
	}
	if target.Value == "" {
		return
	}
	switch target.Kind {
	case "url":
		target.Value = commandTargetOrigin(target.Value)
	case "host":
		target.Value = commandTargetHost(target.Value)
	case "package":
		if !execPackageName("", target.Value) {
			return
		}
	case "path":
		if path.Clean(target.Value) != target.Value || strings.HasPrefix(target.Value, "/") ||
			target.Value == "." || target.Value == ".." || strings.HasPrefix(target.Value, "../") {
			return
		}
	case "tool":
		if strings.ContainsFunc(target.Value, func(r rune) bool {
			return r != '-' && r != '_' && r != '.' && (r < '0' || r > '9') &&
				(r < 'A' || r > 'Z') && (r < 'a' || r > 'z')
		}) {
			return
		}
	case "ref":
		if !gitObjectNameRe.MatchString(target.Value) {
			return
		}
	case "pattern":
		return // a search pattern is arbitrary user text, never audit metadata
	default:
		return
	}
	if target.Value == "" || target.Kind != "package" && strings.ContainsAny(target.Value, fsShellMetacharacters) ||
		slices.Contains(facts.targets, target) {
		return
	}
	facts.targets = append(facts.targets, target)
}

func commandTargetOrigin(value string) string {
	if origin := gitRemoteOrigin(value); origin != "" {
		if u, err := neturl.Parse(origin); err == nil && u.Scheme != "" && validCommandHost(u.Hostname()) {
			return origin
		}
		if validCommandHost(origin) {
			return origin
		}
	}
	return execHostName(value)
}

func commandTargetHost(value string) string {
	return commandTargetOrigin(value)
}

func execCredentialPackage(value string) bool {
	at := strings.IndexByte(value, '@')
	colon := strings.IndexByte(value, ':')
	return colon >= 0 && at > colon
}

func execSub(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

// network.egress -------------------------------------------------------------

var execNetworkCommands = map[string]bool{
	"curl": true, "wget": true, "ssh": true, "scp": true, "nc": true, "rsync": true,
}

// execNetwork credits a command that reaches off this machine. rsync only
// counts in its remote form: a local `rsync -a src dst` never leaves the box.
func execNetwork(cmd execCommand) *commandFacts {
	if !execNetworkCommands[cmd.word] {
		return nil
	}
	scan := scanCommandArgs(cmd.args, execHostFlagModelFor(cmd.word))
	if scan.unknownFlag {
		return nil
	}
	if cmd.word == "nc" && scan.hasFlag("-l") {
		return nil
	}
	operands := scan.operands
	if cmd.word == "rsync" {
		remoteOperands := 0
		for _, operand := range operands {
			if execHostFromSpec(operand) != "" || strings.HasPrefix(operand, "rsync://") {
				remoteOperands++
			}
		}
		if remoteOperands > 1 {
			return nil
		}
	}
	if cmd.word != "ssh" {
		if url := execFirstURL(cmd.word, operands); url != "" {
			return execFacts("network.egress", CommandTarget{Kind: "url", Value: url})
		}
	}
	if host := execRemoteHost(cmd.word, operands); host != "" {
		return execFacts("network.egress", CommandTarget{Kind: "host", Value: host})
	}
	if cmd.word == "ssh" && len(operands) != 0 {
		return execFacts("network.egress")
	}
	if cmd.word != "curl" && cmd.word != "wget" {
		return nil // no operand proves a remote peer
	}
	if len(operands) == 0 {
		return nil // flags-only probe (`curl --version`) reaches nowhere
	}
	if !slices.ContainsFunc(operands, func(operand string) bool {
		return !strings.HasPrefix(strings.ToLower(operand), "file:")
	}) {
		return nil
	}
	return execFacts("network.egress")
}

// execFirstURL returns the safe origin of the first URL argument. URL paths can
// carry credentials just as readily as userinfo and query strings, so network
// and VCS targets share gitRemoteOrigin and never publish them.
func execFirstURL(word string, args []string) string {
	for _, arg := range args {
		if (word == "curl" || word == "wget") &&
			(strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://")) ||
			word == "rsync" && strings.HasPrefix(arg, "rsync://") {
			return gitRemoteOrigin(arg)
		}
	}
	return ""
}

var execSSHFlagModel = commandFlagModel{
	"-4": flagBoolean, "-6": flagBoolean, "-A": flagBoolean, "-a": flagBoolean,
	"-C": flagBoolean, "-f": flagBoolean, "-G": flagBoolean, "-g": flagBoolean,
	"-K": flagBoolean, "-k": flagBoolean, "-M": flagBoolean, "-N": flagBoolean,
	"-n": flagBoolean, "-q": flagBoolean, "-s": flagBoolean, "-T": flagBoolean,
	"-t": flagBoolean, "-V": flagBoolean, "-v": flagBoolean, "-X": flagBoolean,
	"-x": flagBoolean, "-Y": flagBoolean, "-y": flagBoolean,
	"-B": flagValue, "-b": flagValue, "-c": flagValue, "-D": flagValue,
	"-E": flagValue, "-e": flagValue, "-F": flagValue, "-I": flagValue,
	"-i": flagValue, "-J": flagValue, "-L": flagValue, "-l": flagValue,
	"-m": flagValue, "-O": flagValue, "-o": flagValue, "-P": flagValue,
	"-p": flagValue, "-Q": flagValue, "-R": flagValue, "-S": flagValue,
	"-W": flagValue, "-w": flagValue,
}

var execSCPFlagModel = commandFlagModel{
	"-3": flagBoolean, "-4": flagBoolean, "-6": flagBoolean, "-A": flagBoolean,
	"-B": flagBoolean, "-C": flagBoolean, "-O": flagBoolean, "-p": flagBoolean,
	"-q": flagBoolean, "-R": flagBoolean, "-r": flagBoolean, "-s": flagBoolean,
	"-T": flagBoolean, "-v": flagBoolean,
	"-c": flagValue, "-D": flagValue, "-F": flagValue, "-i": flagValue,
	"-J": flagValue, "-l": flagValue, "-o": flagValue, "-P": flagValue,
	"-S": flagValue, "-X": flagValue,
}

var execRsyncFlagModel = commandFlagModel{
	"-a": flagBoolean, "-n": flagBoolean, "-q": flagBoolean, "-r": flagBoolean,
	"-v": flagBoolean, "-z": flagBoolean,
	"-e": flagValue, "-f": flagValue,
	"--address": flagValue, "--backup-dir": flagValue, "--bwlimit": flagValue,
	"--checksum-seed": flagValue, "--chmod": flagValue, "--compare-dest": flagValue,
	"--compress-level": flagValue, "--copy-dest": flagValue, "--exclude": flagValue,
	"--exclude-from": flagValue, "--files-from": flagValue, "--filter": flagValue,
	"--include": flagValue, "--include-from": flagValue, "--link-dest": flagValue,
	"--max-delete": flagValue, "--max-size": flagValue, "--min-size": flagValue,
	"--modify-window": flagValue, "--out-format": flagValue, "--partial-dir": flagValue,
	"--password-file": flagValue, "--port": flagValue, "--protocol": flagValue,
	"--read-batch": flagValue, "--rsync-path": flagValue, "--sockopts": flagValue,
	"--timeout": flagValue, "--write-batch": flagValue,
}

var execNCHostFlagModel = commandFlagModel{
	"-4": flagBoolean, "-6": flagBoolean, "-k": flagBoolean,
	"-l": flagBoolean, "-n": flagBoolean, "-u": flagBoolean, "-v": flagBoolean, "-z": flagBoolean,
	"-p": flagValue, "-i": flagValue, "-o": flagValue, "-F": flagValue,
	"-w": flagValue, "-s": flagValue, "-e": flagValue, "--port": flagValue,
}

var execCurlFlagModel = commandFlagModel{
	"-I": flagBoolean, "--head": flagBoolean, "-L": flagBoolean, "--location": flagBoolean,
	"-M": flagBoolean, "--manual": flagBoolean,
	"-O": flagBoolean, "--remote-name": flagBoolean, "-s": flagBoolean, "--silent": flagBoolean,
	"-V": flagBoolean, "--version": flagBoolean, "-v": flagBoolean, "--verbose": flagBoolean,
	"-o": flagValue, "--output": flagValue, "-e": flagValue, "--referer": flagValue,
	"-x": flagValue, "--proxy": flagValue, "-U": flagValue, "--proxy-user": flagValue,
	"-H": flagValue, "--header": flagValue, "-u": flagValue, "--user": flagValue,
	"-A": flagValue, "--user-agent": flagValue, "-d": flagValue, "--data": flagValue,
	"--data-raw": flagValue, "--data-binary": flagValue, "--data-urlencode": flagValue,
	"-F": flagValue, "--form": flagValue, "-w": flagValue, "--write-out": flagValue,
}

var execWgetFlagModel = commandFlagModel{
	"-q": flagBoolean, "--quiet": flagBoolean, "-c": flagBoolean, "--continue": flagBoolean,
	"-V": flagBoolean, "--version": flagBoolean,
	"-O": flagValue, "--output-document": flagValue, "-o": flagValue, "--output-file": flagValue,
	"-e": flagValue, "--execute": flagValue, "--header": flagValue, "--referer": flagValue,
	"--user": flagValue, "--password": flagValue, "--post-data": flagValue,
	"-P": flagValue, "-U": flagValue, "--user-agent": flagValue,
}

func execHostFlagModelFor(word string) commandFlagModel {
	switch word {
	case "curl":
		return execCurlFlagModel
	case "wget":
		return execWgetFlagModel
	case "ssh":
		return execSSHFlagModel
	case "scp":
		return execSCPFlagModel
	case "rsync":
		return execRsyncFlagModel
	case "nc":
		return execNCHostFlagModel
	}
	return nil
}

// execRemoteHost returns the peer a command talks to: the first operand for ssh
// and nc, and the host half of a `user@host:path` operand for scp and rsync.
// curl and wget are deliberately absent: their operand grammar is a URL or a
// bare hostname, never `[user@]host:path`, so treating an arbitrary operand as
// that shape would read a flag value — a header, a `user:password` credential
// — as a contacted host. execNetwork already falls back to a target-free
// network.egress for those two when only an operand proves the reach.
func execRemoteHost(word string, operands []string) string {
	switch word {
	case "ssh":
		if len(operands) == 0 {
			return ""
		}
		return execHostName(operands[0])
	case "nc":
		if len(operands) < 2 { // host plus port; `nc -l 8080` is a listener
			return ""
		}
		return execHostName(operands[0])
	case "scp", "rsync":
		for _, operand := range operands {
			if host := execHostFromSpec(operand); host != "" {
				return host
			}
		}
	}
	return ""
}

// execHostFromSpec pulls the host spelling out of an `[user@]host:path`
// operand. appendCommandTarget applies the stricter publication-safe host
// grammar; returning an unsafe spelling still lets the remote form prove a
// target-free network.egress.
func execHostFromSpec(operand string) string {
	if strings.Contains(operand, "://") {
		return ""
	}
	colon, bracketed := -1, false
scan:
	for i := range operand {
		switch operand[i] {
		case '[':
			if bracketed {
				return ""
			}
			bracketed = true
		case ']':
			if !bracketed {
				return ""
			}
			bracketed = false
		case ':':
			if !bracketed {
				colon = i
				break scan
			}
		}
	}
	if colon <= 0 || bracketed || strings.ContainsRune(operand[:colon], '/') {
		return ""
	}
	authority := operand[:colon]
	if strings.Count(authority, "@") > 1 {
		return ""
	}
	if at := strings.IndexByte(authority, '@'); at >= 0 {
		if at == 0 || at == len(authority)-1 {
			return ""
		}
		authority = authority[at+1:]
	}
	if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") && len(authority) > 2 {
		return authority[1 : len(authority)-1]
	}
	if strings.ContainsAny(authority, "[]@") {
		return ""
	}
	return authority
}

func execHostName(operand string) string {
	if at := strings.LastIndexByte(operand, '@'); at >= 0 {
		operand = operand[at+1:]
	}
	if operand == "" || strings.ContainsAny(operand, "/"+fsShellMetacharacters) {
		return ""
	}
	if strings.Contains(operand, ":") && net.ParseIP(operand) == nil {
		return ""
	}
	if !validCommandHost(operand) {
		return ""
	}
	return operand
}

func validCommandHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if r != '-' && (r < '0' || r > '9') && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
				return false
			}
		}
	}
	return true
}

// execOperands returns the authoritative scanner's non-flag arguments,
// skipping separate, attached, and clustered values.
func execOperands(args []string, model commandFlagModel) []string {
	scan := scanCommandArgs(args, model)
	if scan.unknownFlag {
		return nil
	}
	return scan.operands
}

func execHasFlag(args []string, model commandFlagModel, flags ...string) bool {
	return scanCommandArgs(args, model).hasFlag(flags...)
}

// forge.mutate ---------------------------------------------------------------

var execForgeVerbs = map[string][]string{
	"pr":      {"create", "merge", "close"},
	"issue":   {"create", "comment", "close"},
	"release": {"create", "delete", "delete-asset", "edit", "upload"},
}

// execForge credits a gh invocation that changes state on the forge. The
// `git push` half of this category belongs to the vcs classifier.
func execForge(cmd execCommand) *commandFacts {
	if cmd.word != "gh" || !cmd.seg.exitOK {
		return nil
	}
	verbs, ok := execForgeVerbs[execSub(cmd.args)]
	if !ok {
		return nil
	}
	if len(cmd.args) > 1 && slices.Contains(verbs, cmd.args[1]) {
		if cmd.args[1] == "create" && (cmd.args[0] == "pr" || cmd.args[0] == "issue") &&
			slices.ContainsFunc(cmd.args[2:], func(arg string) bool {
				name, value, attached := strings.Cut(arg, "=")
				enabled := !attached
				if attached {
					enabled, _ = strconv.ParseBool(value)
				}
				return (name == "-w" || name == "--web") && enabled
			}) {
			return nil
		}
		return execFacts("forge.mutate")
	}
	return nil
}

// package.install ------------------------------------------------------------

var execNodeManagers = map[string]bool{"npm": true, "pnpm": true, "yarn": true}

var execInstallSubcommands = map[string][]string{
	"pip":   {"install"},
	"pip3":  {"install"},
	"go":    {"get"},
	"cargo": {"add"},
	"gem":   {"install"},
	"brew":  {"install"},
}

// execInstallArgs reports the arguments after the install subcommand, and
// whether this command installs packages at all.
func execInstallArgs(cmd execCommand) ([]string, bool) {
	sub := execSub(cmd.args)
	if execNodeManagers[cmd.word] {
		if sub == "add" || sub == "install" {
			return cmd.args[1:], true
		}
		return nil, false
	}
	if subs, ok := execInstallSubcommands[cmd.word]; ok && slices.Contains(subs, sub) {
		return cmd.args[1:], true
	}
	return nil, false
}

// Package value flags are manager-specific so a spelling that takes a value
// for one manager cannot swallow a real package operand for another.
var execPipFlagModel = commandFlagModel{
	"-q": flagBoolean, "--quiet": flagBoolean, "-U": flagBoolean, "--upgrade": flagBoolean,
	"--user": flagBoolean, "--dry-run": flagBoolean,
	"-r": flagValue, "--requirement": flagValue, "-i": flagValue, "--index-url": flagValue,
	"-t": flagValue, "--target": flagValue, "--prefix": flagValue, "--root": flagValue,
	"-c": flagValue, "--constraint": flagValue, "--extra-index-url": flagValue,
	"-f": flagValue, "--find-links": flagValue, "--proxy": flagValue, "--cert": flagValue,
	"--client-cert": flagValue, "--src": flagValue, "--platform": flagValue,
	"--python-version": flagValue, "--implementation": flagValue, "--abi": flagValue,
	"--timeout": flagValue, "--retries": flagValue, "--trusted-host": flagValue,
	"--upgrade-strategy": flagValue, "--no-binary": flagValue, "--only-binary": flagValue,
	"--log": flagValue, "--exists-action": flagValue, "--progress-bar": flagValue,
	"--global-option": flagValue, "--config-settings": flagValue, "-C": flagValue,
	"-e": flagValue, "--editable": flagValue, "--report": flagValue, "--group": flagValue,
	"--root-user-action": flagValue, "--keyring-provider": flagValue, "--python": flagValue,
}

var execCargoFlagModel = commandFlagModel{
	"--dry-run": flagBoolean, "--optional": flagBoolean,
	"-F": flagValue, "--features": flagValue, "--path": flagValue, "--git": flagValue,
	"--branch": flagValue, "--tag": flagValue, "--rev": flagValue, "--manifest-path": flagValue,
	"--registry": flagValue, "--rename": flagValue,
}

var execNodeFlagModel = commandFlagModel{
	"-g": flagBoolean, "--global": flagBoolean, "-D": flagBoolean, "--save-dev": flagBoolean,
	"--dry-run": flagBoolean, "--package-lock-only": flagBoolean, "--lockfile-only": flagBoolean,
	"-w": flagValue, "--workspace": flagValue, "--filter": flagValue,
	"--modules-folder": flagValue, "--cache-folder": flagValue,
	"--registry": flagValue, "--prefix": flagValue, "--cwd": flagValue,
	"--userconfig": flagValue, "--omit": flagValue, "--include": flagValue,
	"--install-strategy": flagValue, "--cpu": flagValue, "--os": flagValue, "--libc": flagValue,
	"--tag": flagValue, "--otp": flagValue, "--mode": flagValue,
	"--prefer-offline-dir": flagValue, "--store-dir": flagValue, "--virtual-store-dir": flagValue,
}

var execGemFlagModel = commandFlagModel{
	"--explain": flagBoolean,
	"-v":        flagValue, "--version": flagValue, "-i": flagValue, "--install-dir": flagValue,
	"-n": flagValue, "--bindir": flagValue, "--platform": flagValue,
	"--build-root": flagValue, "-P": flagValue, "--trust-policy": flagValue,
	"--without": flagValue, "-B": flagValue, "--bulk-threshold": flagValue,
	"-s": flagValue, "--source": flagValue, "--config-file": flagValue,
}

var execBrewFlagModel = commandFlagModel{
	"-d": flagBoolean, "--debug": flagBoolean, "-f": flagBoolean, "--force": flagBoolean,
	"-v": flagBoolean, "--verbose": flagBoolean, "-n": flagBoolean, "--dry-run": flagBoolean,
	"-y": flagBoolean, "--no-ask": flagBoolean, "--yes": flagBoolean,
	"--cc": flagValue, "--bottle-arch": flagValue, "--appdir": flagValue,
	"--appimagedir": flagValue, "--keyboard-layoutdir": flagValue,
	"--colorpickerdir": flagValue, "--prefpanedir": flagValue, "--qlplugindir": flagValue,
	"--mdimporterdir": flagValue, "--dictionarydir": flagValue, "--fontdir": flagValue,
	"--servicedir": flagValue, "--input-methoddir": flagValue,
	"--internet-plugindir": flagValue, "--audio-unit-plugindir": flagValue,
	"--vst-plugindir": flagValue, "--vst3-plugindir": flagValue,
	"--screen-saverdir": flagValue, "--language": flagValue,
}

var execGoGetFlagModel = commandFlagModel{
	"-n": flagBoolean, "-u": flagAttachedValue,
	"-mod": flagValue, "-modfile": flagValue, "-overlay": flagValue,
	"-p": flagValue, "-tags": flagValue,
}

func execPackageFlagModelFor(word string) commandFlagModel {
	switch word {
	case "pip", "pip3":
		return execPipFlagModel
	case "npm", "pnpm", "yarn":
		return execNodeFlagModel
	case "cargo":
		return execCargoFlagModel
	case "gem":
		return execGemFlagModel
	case "go":
		return execGoGetFlagModel
	case "brew":
		return execBrewFlagModel
	default:
		return nil
	}
}

func execPackage(cmd execCommand) *commandFacts {
	args, ok := execInstallArgs(cmd)
	model := execPackageFlagModelFor(cmd.word)
	if !ok || !cmd.seg.exitOK {
		return nil
	}
	scan := scanCommandArgs(args, model)
	if scan.unknownFlag {
		return nil
	}
	facts := execFacts("package.install")
	for _, name := range scan.operands {
		if name = strings.TrimSpace(name); name == "" {
			continue // an empty quoted operand (`npm install ""`) names nothing
		}
		if !execPackageName(cmd.word, name) {
			continue
		}
		appendCommandTarget(facts, CommandTarget{Kind: "package", Value: name})
	}
	return facts
}

// execPackageName is the single gate for package targets. Slash-bearing names
// are limited to scoped Node names, domain-qualified Go module paths, and
// Homebrew's user/tap/formula shape.
func execPackageName(word, name string) bool {
	if name == "" || execPackageSource(name) || execCredentialPackage(name) || strings.HasPrefix(name, ".") ||
		strings.HasPrefix(name, "-") || strings.ContainsFunc(name, func(r rune) bool {
		return !strings.ContainsRune("-_.@:=><!~^+,[]|/", r) &&
			(r < '0' || r > '9') && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z')
	}) {
		return false
	}
	ext := strings.ToLower(path.Ext(name))
	if slices.Contains([]string{".bz2", ".egg", ".gem", ".gz", ".jar", ".tar", ".tgz", ".whl", ".xz", ".zip"}, ext) {
		return false
	}
	if !strings.ContainsRune(name, '/') {
		return name[0] != '@'
	}
	if (word == "" || execNodeManagers[word]) && strings.HasPrefix(name, "@") &&
		strings.Count(name, "/") == 1 {
		slash := strings.IndexByte(name, '/')
		return slash > 1 && slash < len(name)-1 && name[slash+1] != '.'
	}
	if word == "" || word == "brew" {
		parts := strings.Split(name, "/")
		brewName := len(parts) == 3 && !slices.ContainsFunc(parts, func(part string) bool {
			return part == "" || strings.HasPrefix(part, ".")
		})
		if brewName || word == "brew" {
			return brewName
		}
	}
	if word == "" || word == "go" {
		parts := strings.Split(name, "/")
		if !strings.ContainsRune(parts[0], '.') {
			return false
		}
		return !slices.ContainsFunc(parts, func(part string) bool {
			return part == "" || strings.HasPrefix(part, ".")
		})
	}
	return false
}

func execPackageURL(name string) bool {
	return strings.HasPrefix(name, "//") || strings.Contains(name, "://") ||
		strings.HasPrefix(name, "git+")
}

func execPackageSource(name string) bool {
	name = strings.ReplaceAll(name, `\`, "/")
	return execPackageURL(name) || gitRemoteOrigin(name) != "" || strings.HasPrefix(strings.ToLower(name), "file:") ||
		fsOperandAbsolute(name) || name == "." || name == ".." ||
		strings.HasPrefix(name, "./") || strings.HasPrefix(name, "../")
}

// verify.run -----------------------------------------------------------------

var execVerifyCommands = map[string]bool{
	"pytest": true, "vitest": true, "jest": true, "tsc": true,
	"eslint": true, "ruff": true, "golangci-lint": true,
}

var execVerifySubcommands = map[string][]string{
	"go":    {"test", "build", "vet"},
	"cargo": {"test", "build", "clippy"},
	"make":  {"test", "build", "lint"},
}

// execMakeFlagModel declares the make flags needed by target extraction, so
// `make -C build install` does not read the value of -C as the make target.
var execMakeFlagModel = commandFlagModel{
	"-k": flagBoolean, "-n": flagBoolean, "-q": flagBoolean, "-s": flagBoolean, "-t": flagBoolean,
	"--just-print": flagBoolean, "--dry-run": flagBoolean, "--recon": flagBoolean,
	"--question": flagBoolean, "--touch": flagBoolean,
	"-C": flagValue, "--directory": flagValue, "-f": flagValue, "--file": flagValue,
}

var execPytestFlagModel = commandFlagModel{
	"-q": flagBoolean, "-v": flagBoolean, "-x": flagBoolean, "-h": flagBoolean,
	"-k": flagValue, "-m": flagValue, "-o": flagValue, "--override-ini": flagValue,
	"--maxfail": flagValue, "--tb": flagValue, "--capture": flagValue,
	"--rootdir": flagValue, "--confcutdir": flagValue, "--basetemp": flagValue,
	"--durations": flagValue,
}

// execVerifyScripts is the closed list of package scripts that prove a
// verification ran. `npm run dev` starts a server; it verifies nothing.
var execVerifyScripts = []string{"test", "lint", "build", "typecheck", "check"}

// execVerify credits a check the agent ran. A failing check is still a check,
// so this category is not gated on the exit status.
func execVerify(cmd execCommand) *commandFacts {
	if execVerifyCommands[cmd.word] {
		return execFacts("verify.run")
	}
	if subs, ok := execVerifySubcommands[cmd.word]; ok {
		if cmd.word == "make" {
			for _, target := range execOperands(cmd.args, execMakeFlagModel) {
				if slices.Contains(subs, target) {
					return execFacts("verify.run")
				}
			}
			return nil
		}
		if slices.Contains(subs, execSub(cmd.args)) {
			return execFacts("verify.run")
		}
		return nil
	}
	if execNodeManagers[cmd.word] && execSub(cmd.args) == "run" && len(cmd.args) > 1 &&
		slices.Contains(execVerifyScripts, cmd.args[1]) {
		return execFacts("verify.run")
	}
	return nil
}

// search.query ---------------------------------------------------------------

// execSearchGrepFlagModel declares grep's flags used to separate the pattern
// from file operands during read inference. grep's -r is --recursive and takes
// no value, unlike rg's -r/--replace, so the models stay command-specific.
var execSearchGrepFlagModel = commandFlagModel{
	"-n": flagBoolean, "-r": flagBoolean, "-R": flagBoolean,
	"-c": flagBoolean, "-l": flagBoolean, "-L": flagBoolean,
	"-e": flagValue, "--regexp": flagValue,
	"-A": flagValue, "--after-context": flagValue,
	"-B": flagValue, "--before-context": flagValue,
	"-C": flagValue, "--context": flagValue,
	"-m": flagValue, "--max-count": flagValue,
	"-f": flagValue, "--file": flagValue,
	"--include": flagValue, "--exclude": flagValue,
	"--exclude-dir": flagValue, "--exclude-from": flagValue,
	"-d": flagValue, "--directories": flagValue,
	"--binary-files": flagValue, "--label": flagValue,
}

// execSearchRGFlagModel declares ripgrep's flags used during read inference.
var execSearchRGFlagModel = commandFlagModel{
	"-n": flagBoolean, "--line-number": flagBoolean, "-l": flagBoolean,
	"--files-with-matches": flagBoolean, "--hidden": flagBoolean,
	"--files": flagBoolean, "--type-list": flagBoolean, "--pcre2-version": flagBoolean,
	"-e": flagValue, "--regexp": flagValue, "-g": flagValue, "--glob": flagValue, "--iglob": flagValue,
	"-t": flagValue, "--type": flagValue, "-T": flagValue, "--type-not": flagValue,
	"-A": flagValue, "-B": flagValue, "-C": flagValue, "--after-context": flagValue,
	"--before-context": flagValue, "--context": flagValue, "-m": flagValue, "--max-count": flagValue,
	"-r": flagValue, "--replace": flagValue, "-f": flagValue, "--file": flagValue,
	"--max-depth": flagValue, "--max-filesize": flagValue,
	"--sort": flagValue, "--sortr": flagValue, "--ignore-file": flagValue,
	"-M": flagValue, "--max-columns": flagValue, "--pre": flagValue, "--pre-glob": flagValue,
	"--engine": flagValue, "--dfa-size-limit": flagValue, "--regex-size-limit": flagValue,
	"--type-add": flagValue, "--type-clear": flagValue, "-j": flagValue, "--threads": flagValue,
	"-E": flagValue, "--encoding": flagValue,
	"--color": flagValue, "--colors": flagValue, "--context-separator": flagValue,
	"--field-context-separator": flagValue, "--field-match-separator": flagValue,
	"--hostname-bin": flagValue, "--hyperlink-format": flagValue,
	"--path-separator": flagValue, "--generate": flagValue,
}

func execSearchFlagModelFor(word string) commandFlagModel {
	if word == "grep" {
		return execSearchGrepFlagModel
	}
	return execSearchRGFlagModel
}

// execSearch credits a repository search. A search explicitly scoped to one
// file is left out only when retrievalFromCommand will actually credit that
// scope as a file read: it additionally requires
// searchCommandCanExposeFileContent (non-empty, untrusted-output-free
// output, none of -c/-l/--files and friends). When that predicate fails —
// `grep -c`, `rg -l`, a real search with no hits, output this package does
// not trust because the command was not a single segment — nothing else
// credits the search, so it must be credited here instead of vanishing.
func execSearch(cmd execCommand) *commandFacts {
	if cmd.word != "rg" && cmd.word != "grep" {
		return nil
	}
	scan := scanCommandArgs(cmd.args, execSearchFlagModelFor(cmd.word))
	if cmd.word == "rg" {
		if scan.hasFlag("--files", "--type-list", "--pcre2-version") {
			return nil
		}
		if _, ok := scan.flagValue("--generate"); ok {
			return nil
		}
	}
	_, hasRegexp := execCompleteFlagValue(cmd.args, scan, "-e", "--regexp")
	_, hasPatternFile := execCompleteFlagValue(cmd.args, scan, "-f", "--file")
	if len(scan.operands) == 0 && !hasRegexp && !hasPatternFile {
		return nil
	}
	if explicitSingleSearchFile(cmd.seg.tokens, cmd.seg.ws) != "" &&
		searchCommandCanExposeFileContent(cmd.seg.tokens, cmd.seg.output) {
		return nil
	}
	return execFacts("search.query")
}

// execCompleteFlagValue distinguishes a missing value from an explicitly
// supplied empty one. commandArgScan preserves both as "", so the original
// argument position is needed for value-taking search flags.
func execCompleteFlagValue(args []string, scan commandArgScan, names ...string) (string, bool) {
	for _, flag := range scan.flags {
		if !slices.Contains(names, flag.name) {
			continue
		}
		if flag.value != "" {
			return flag.value, true
		}
		if flag.index < 0 || flag.index >= len(args) {
			return "", false
		}
		arg := args[flag.index]
		if strings.HasPrefix(arg, "--") {
			return "", strings.Contains(arg, "=") || flag.index+1 < len(args)
		}
		if len(flag.name) == 2 {
			if at := strings.IndexByte(arg[1:], flag.name[1]); at >= 0 && at+2 < len(arg) {
				return "", true
			}
		}
		return "", flag.index+1 < len(args)
	}
	return "", false
}

// execSearchPattern identifies which operand is the pattern so read inference
// can exclude it from candidate file paths. Patterns are never published.
func execSearchPattern(word string, args []string) string {
	scan := scanCommandArgs(args, execSearchFlagModelFor(word))
	if scan.unknownFlag {
		return ""
	}
	if _, ok := scan.flagValue("-f", "--file"); ok {
		return ""
	}
	if pattern, ok := scan.flagValue("-e", "--regexp"); ok {
		return pattern
	}
	if len(scan.operands) != 0 {
		return scan.operands[0]
	}
	return ""
}

// container.run --------------------------------------------------------------

var execContainerSubcommands = []string{"build", "run", "compose", "exec"}

func execContainer(cmd execCommand) *commandFacts {
	if cmd.word != "docker" && cmd.word != "podman" {
		return nil
	}
	if !cmd.seg.exitOK || !slices.Contains(execContainerSubcommands, execSub(cmd.args)) {
		return nil
	}
	return execFacts("container.run")
}

// process.background ---------------------------------------------------------

var execBackgroundCommands = map[string]bool{
	"nohup": true, "setsid": true, "screen": true, "tmux": true,
}

var execComposeFlagModel = commandFlagModel{
	"-f": flagValue, "--file": flagValue, "-p": flagValue, "--project-name": flagValue,
	"--profile": flagValue, "--env-file": flagValue,
	"-d": flagBoolean, "--detach": flagBoolean,
}

var execScreenFlagModel = commandFlagModel{"-v": flagBoolean}

// execBackground credits work the agent left running behind it: a detached
// segment, a detaching launcher, or `docker compose up -d`.
func execBackground(cmd execCommand) *commandFacts {
	if execBackgroundCommands[cmd.word] || execTrailingAmpersand(cmd.seg) {
		return execFacts("process.background")
	}
	if (cmd.word == "docker" || cmd.word == "podman") && execSub(cmd.args) == "compose" {
		scan := scanCommandArgs(cmd.args[1:], execComposeFlagModel)
		if len(scan.operands) != 0 && scan.operands[0] == "up" && scan.hasFlag("-d", "--detach") {
			return execFacts("process.background")
		}
	}
	return nil
}

// execTrailingAmpersand tests the raw segment text, not the tokens: shellTokens
// strips quotes, so a quoted `&` argument (`echo "&"`) would otherwise be
// indistinguishable from the real detach operator. A quoted `&` is always
// followed by its closing quote, never by the end of the segment, so the raw
// suffix is unambiguous. splitCommandChain already splits on `&&`, so that
// case is excluded defensively rather than expected. A backslash-escaped `&`
// (`echo a\&`) also survives to the end of the segment as a literal argument
// character rather than the detach operator, so the run of backslashes
// immediately before it must be counted: an even run (including zero) leaves
// the `&` live, an odd run escapes it.
func execTrailingAmpersand(seg commandSegment) bool {
	raw := strings.TrimSpace(seg.raw)
	if !strings.HasSuffix(raw, "&") || strings.HasSuffix(raw, "&&") {
		return false
	}
	body := strings.TrimSuffix(raw, "&")
	if strings.TrimSpace(body) == "" {
		return false
	}
	return !execEndsWithOddBackslashes(body)
}

// execEndsWithOddBackslashes reports whether s ends in an odd run of
// backslashes, meaning whatever character followed s in the original text
// (here, the trailing `&` execTrailingAmpersand trimmed off) is escaped.
func execEndsWithOddBackslashes(s string) bool {
	n := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}

// archive.extract ------------------------------------------------------------

var (
	execTarFlagModel = commandFlagModel{
		"-c": flagBoolean, "-x": flagBoolean, "-t": flagBoolean,
		"-d": flagBoolean, "-u": flagBoolean, "-A": flagBoolean,
		"--extract": flagBoolean, "--create": flagBoolean, "--list": flagBoolean,
		"--diff": flagBoolean, "--compare": flagBoolean, "--update": flagBoolean,
		"--append": flagBoolean, "--catenate": flagBoolean, "--concatenate": flagBoolean,
		"-a": flagBoolean, "-j": flagBoolean, "-J": flagBoolean,
		"-k": flagBoolean, "-m": flagBoolean, "-O": flagBoolean,
		"--to-stdout": flagBoolean,
		"-p":          flagBoolean, "-v": flagBoolean, "-w": flagBoolean, "--interactive": flagBoolean, "-z": flagBoolean,
		"-f": flagValue, "--file": flagValue, "-C": flagValue, "--directory": flagValue,
		"-X": flagValue, "--exclude-from": flagValue, "-T": flagValue, "--files-from": flagValue,
		"--transform": flagValue, "--strip-components": flagValue, "--to-command": flagValue,
	}
	execUnzipFlagModel = commandFlagModel{
		"-c": flagBoolean, "-f": flagBoolean, "-j": flagBoolean, "-k": flagBoolean,
		"-h": flagBoolean,
		"-l": flagBoolean, "-n": flagBoolean, "-o": flagBoolean, "-p": flagBoolean,
		"-q": flagBoolean, "-t": flagBoolean, "-u": flagBoolean, "-v": flagBoolean,
		"-T": flagBoolean, "-Z": flagBoolean, "-z": flagBoolean, "-1": flagBoolean,
		"-d": flagValue, "-P": flagValue,
	}
	execGunzipFlagModel = commandFlagModel{
		"-c": flagBoolean, "-d": flagBoolean, "-f": flagBoolean, "-k": flagBoolean,
		"-l": flagBoolean, "-n": flagBoolean, "-N": flagBoolean, "-q": flagBoolean,
		"-r": flagBoolean, "-t": flagBoolean, "-V": flagBoolean, "-v": flagBoolean,
		"-S": flagValue, "--suffix": flagValue,
	}
)

// execTarExtract reports whether tar's arguments select extract mode, as
// opposed to create, list, or another non-extract mode. The first argument is
// also checked bare: `tar xzf f` is valid tar syntax without a leading dash.
func execTarExtract(args []string) bool {
	scan := execTarScan(args)
	for _, flag := range scan.flags {
		switch flag.name {
		case "-x", "--extract":
			return true
		case "-c", "--create", "-t", "--list", "-d", "--diff", "--compare",
			"-u", "--update", "-r", "--append", "-A", "--catenate", "--concatenate":
			return false
		}
	}
	return false
}

func execTarScan(args []string) commandArgScan {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return scanCommandArgs(args, execTarFlagModel)
	}
	var scan commandArgScan
	next := 1
	for _, letter := range args[0] {
		name := "-" + string(letter)
		arity := execTarFlagModel[name]
		if arity == 0 {
			scan.unknownFlag = true
			scan.flags = append(scan.flags, commandFlag{name: name})
			continue
		}
		flag := commandFlag{name: name, arity: arity}
		if arity == flagValue {
			if next >= len(args) {
				scan.unknownFlag = true
			} else {
				flag.value = args[next]
				next++
			}
		}
		scan.flags = append(scan.flags, flag)
	}
	rest := scanCommandArgs(args[next:], execTarFlagModel)
	for i := range rest.flags {
		rest.flags[i].index += next
	}
	for i := range rest.operandIndexes {
		rest.operandIndexes[i] += next
	}
	scan.flags = append(scan.flags, rest.flags...)
	scan.operands = append(scan.operands, rest.operands...)
	scan.operandIndexes = append(scan.operandIndexes, rest.operandIndexes...)
	scan.unknownFlag = scan.unknownFlag || rest.unknownFlag
	return scan
}

// execArchiveWritesToDisk is the single archive-mode predicate: every archive
// producer routes through it before archive.extract is credited.
func execArchiveWritesToDisk(cmd execCommand) bool {
	switch cmd.word {
	case "tar":
		scan := execTarScan(cmd.args)
		if scan.unknownFlag || !execTarExtract(cmd.args) || scan.hasFlag(
			"--to-stdout", "-O", "--to-command", "-T", "--files-from", "-w", "--interactive",
		) {
			return false
		}
		return true
	case "unzip":
		scan := scanCommandArgs(cmd.args, execUnzipFlagModel)
		// -p/-c stream content; -l/-t/-v/-Z/-z only inspect metadata. The
		// state-dependent -n/-f/-u modes can succeed without writing a member.
		return !scan.unknownFlag && len(scan.operands) != 0 && !scan.hasFlag(
			"-l", "-t", "-v", "-T", "-Z", "-p", "-c", "-z", "-n", "-f", "-u",
		)
	case "gunzip":
		scan := scanCommandArgs(cmd.args, execGunzipFlagModel)
		if !scan.unknownFlag && !scan.hasFlag("--list", "--test", "--stdout", "--to-stdout", "-l", "-t", "-c", "-r") {
			return slices.ContainsFunc(scan.operands, func(operand string) bool { return operand != "-" })
		}
		return false
	case "curl":
		return len(execDownloadOutputFiles(cmd)) != 0
	case "wget":
		return len(execDownloadOutputFiles(cmd)) != 0
	}
	return false
}

// execArchive credits a command that lands new files on disk from an archive
// or a download. Creating, listing, testing, and stdout modes land nothing.
func execArchive(cmd execCommand) *commandFacts {
	if !cmd.seg.exitOK || !execArchiveWritesToDisk(cmd) {
		return nil
	}
	var inside, escaped bool
	switch cmd.word {
	case "tar":
		scan := execTarScan(cmd.args)
		inside, escaped = execArchiveDestinationsWorkspace(cmd, scan, "-C", "--directory")
	case "unzip":
		scan := scanCommandArgs(cmd.args, execUnzipFlagModel)
		inside, escaped = execArchiveDestinationsWorkspace(cmd, scan, "-d")
	case "gunzip":
		destinations := slices.DeleteFunc(scanCommandArgs(cmd.args, execGunzipFlagModel).operands, func(operand string) bool { return operand == "-" })
		inside, escaped = execPathsWorkspace(cmd, destinations)
	case "curl":
		destinations := execDownloadOutputFiles(cmd)
		inside, escaped = execAnyPathWorkspace(cmd, destinations)
	case "wget":
		destinations := execDownloadOutputFiles(cmd)
		inside, escaped = execAnyPathWorkspace(cmd, destinations)
	}
	facts := &commandFacts{}
	if inside {
		facts.categories = append(facts.categories, "archive.extract")
	}
	if escaped {
		facts.categories = append(facts.categories, "workspace.escape")
	}
	if facts.empty() {
		return nil
	}
	return facts
}

// execDownloadOutputFiles returns the effective explicit disk outputs. Wget's
// last -O wins, while curl pairs output selectors and URLs in order; an extra
// selector with no URL is ignored by curl.
func execDownloadOutputFiles(cmd execCommand) []string {
	scan := scanCommandArgs(cmd.args, execHostFlagModelFor(cmd.word))
	if scan.unknownFlag {
		return nil
	}
	if cmd.word == "wget" {
		for i := len(scan.flags) - 1; i >= 0; i-- {
			flag := scan.flags[i]
			if flag.name == "-O" || flag.name == "--output-document" {
				if execOutputPath(flag.value) {
					return []string{flag.value}
				}
				return nil
			}
		}
		return nil
	}

	urls := len(scan.operands)
	var outputs []string
	for _, flag := range scan.flags {
		if urls == 0 {
			break
		}
		switch flag.name {
		case "-o", "--output":
			urls--
			if execOutputPath(flag.value) {
				outputs = append(outputs, flag.value)
			}
		case "-O", "--remote-name":
			if flag.enabled() {
				urls--
			}
		}
	}
	return outputs
}

// execOutputPath rejects output spellings that do not prove a regular file.
func execOutputPath(value string) bool {
	clean := canonicalWorkspacePath(value)
	if value == "" || value == "-" || strings.ContainsAny(value, fsShellMetacharacters) ||
		strings.HasPrefix(clean, "/dev/") || strings.HasPrefix(clean, "/proc/self/fd/") ||
		strings.HasPrefix(clean, "/proc/thread-self/fd/") {
		return false
	}
	return true
}

func execFlagValues(scan commandArgScan, names ...string) []string {
	var values []string
	for _, flag := range scan.flags {
		if slices.Contains(names, flag.name) {
			values = append(values, flag.value)
		}
	}
	return values
}

// execArchiveDestinationsWorkspace resolves the directory where extraction
// lands. tar applies each relative -C from the directory established by the
// preceding one; unzip's -d values remain relative to the command's cwd.
func execArchiveDestinationsWorkspace(cmd execCommand, scan commandArgScan, names ...string) (inside, escaped bool) {
	if cmd.word == "tar" {
		base := canonicalWorkspacePath(cmd.seg.ws.root)
		if cmd.seg.cwdKnown {
			base = cmd.seg.cwd
		}
		if base == "." {
			base = ""
		}
		known, selected := !cmd.seg.cwdUncertain || cmd.seg.cwdKnown, false
		record := func() {
			if !known {
				return
			}
			valueInside, valueEscaped := execPathsWorkspace(cmd, []string{base})
			inside = inside || valueInside
			escaped = escaped || valueEscaped
		}
		for i := range cmd.args {
			for _, flag := range scan.flags {
				if flag.index != i || !slices.Contains(names, flag.name) {
					continue
				}
				if flag.value == "" || strings.ContainsAny(flag.value, fsShellMetacharacters) {
					known = false
					continue
				}
				value := literalPath(flag.value)
				if fsOperandAbsolute(flag.value) || isPortableAbsolute(value) {
					base, known = value, true
				} else if known {
					base = literalPathJoin(base, value)
				}
			}
			if slices.Contains(scan.operandIndexes, i) {
				selected = true
				record()
			}
		}
		if !selected {
			record()
		}
		return inside, escaped
	}

	var values []string
	for _, flag := range scan.flags {
		if !slices.Contains(names, flag.name) {
			continue
		}
		values = append(values, flag.value)
	}
	if len(values) == 0 {
		return execPathsWorkspace(cmd, []string{"."})
	}
	return execPathsWorkspace(cmd, values)
}

// execPathsWorkspace is the single workspace-containment predicate for
// exec-side mutation destinations. It distinguishes a proven in-workspace
// destination from a proven escape while leaving expressions and relative
// paths under an uncertain cwd unclassified.
func execPathsWorkspace(cmd execCommand, values []string) (inside, escaped bool) {
	for _, value := range values {
		value, known := execResolvedPath(cmd, value)
		if !known {
			continue
		}
		if _, ok := fsDirectoryPath(value, cmd.seg.ws, false); ok {
			inside = true
		} else if !fsIsWorkspaceRoot(value, cmd.seg.ws) {
			escaped = true
		}
	}
	return inside, escaped
}

func execResolvedPath(cmd execCommand, value string) (string, bool) {
	if value == "" || strings.ContainsAny(value, fsShellMetacharacters) {
		return "", false
	}
	if fsOperandAbsolute(value) {
		return literalPath(value), true
	}
	if cmd.seg.cwdKnown {
		return literalPathJoin(cmd.seg.cwd, value), true
	}
	if cmd.seg.cwdUncertain {
		return "", false
	}
	return value, true
}

func execWorkspacePaths(cmd execCommand, values []string) []string {
	var paths []string
	for _, value := range values {
		value, known := execResolvedPath(cmd, value)
		if !known {
			continue
		}
		if value, ok := normalizeWorkspacePath(value, cmd.seg.ws); ok {
			paths = append(paths, value)
		}
	}
	return paths
}

func execAnyPathWorkspace(cmd execCommand, values []string) (inside, escaped bool) {
	for _, value := range values {
		valueInside, valueEscaped := execPathsWorkspace(cmd, []string{value})
		inside = inside || valueInside
		escaped = escaped || valueEscaped
	}
	return inside, escaped
}

func execCWDUncertainRelativeDestination(cmd execCommand, values []string) bool {
	if !cmd.seg.cwdUncertain || cmd.seg.cwdKnown {
		return false
	}
	return slices.ContainsFunc(values, func(value string) bool {
		return value != "" && !fsOperandAbsolute(value) && !strings.ContainsAny(value, fsShellMetacharacters)
	})
}

// permission.changed ---------------------------------------------------------

var execPermissionCommands = map[string]bool{"chmod": true, "chown": true, "chgrp": true}

var execChmodFlagModel = commandFlagModel{
	"-R": flagBoolean, "-f": flagBoolean, "-v": flagBoolean, "-c": flagBoolean,
	"--recursive": flagBoolean, "--changes": flagBoolean, "--quiet": flagBoolean,
	"--silent": flagBoolean, "--verbose": flagBoolean, "--preserve-root": flagBoolean,
	"--no-preserve-root": flagBoolean, "--reference": flagValue,
}

var execOwnerFlagModel = commandFlagModel{
	"-R": flagBoolean, "-h": flagBoolean, "-f": flagBoolean, "-v": flagBoolean,
	"-c": flagBoolean, "-H": flagBoolean, "-L": flagBoolean, "-P": flagBoolean,
	"--recursive": flagBoolean, "--dereference": flagBoolean, "--no-dereference": flagBoolean,
	"--changes": flagBoolean, "--quiet": flagBoolean, "--silent": flagBoolean,
	"--verbose": flagBoolean, "--preserve-root": flagBoolean, "--no-preserve-root": flagBoolean,
	"--from": flagValue, "--reference": flagValue,
}

func execPermissionFlagModelFor(word string) commandFlagModel {
	if word == "chmod" {
		return execChmodFlagModel
	}
	return execOwnerFlagModel
}

func execPermissionPaths(cmd execCommand) ([]string, bool) {
	args := cmd.args
	if cmd.word == "chmod" {
		for i, arg := range args {
			prefix := scanCommandArgs(args[:i], execChmodFlagModel)
			if prefix.unknownFlag || len(prefix.operands) != 0 {
				break
			}
			if execChmodSymbolicMode(arg) {
				args = slices.Clone(args)
				args[i] = strings.TrimPrefix(arg, "-")
				break
			}
		}
	}
	scan := scanCommandArgs(args, execPermissionFlagModelFor(cmd.word))
	if scan.unknownFlag || scan.hasFlag("--from") {
		return nil, false
	}
	paths := scan.operands
	if !scan.hasFlag("--reference") {
		if len(paths) == 0 {
			return nil, false
		}
		paths = paths[1:]
	}
	return paths, len(paths) != 0
}

// execPermissionReportsEveryChange reports whether the invocation asked the
// tool to name every change it made, which turns absent output into evidence.
// Only chmod's -c/--changes is listed: chown/chmod's -v prints a line for
// unchanged files too, so its silence would prove nothing.
func execPermissionReportsEveryChange(cmd execCommand) bool {
	if cmd.word != "chmod" {
		return false
	}
	scan := scanCommandArgs(cmd.args, execPermissionFlagModelFor(cmd.word))
	return !scan.unknownFlag && scan.hasFlag("-c", "--changes")
}

func execChmodSymbolicMode(value string) bool {
	if !strings.HasPrefix(value, "-") {
		return false
	}
	for _, clause := range strings.Split(value, ",") {
		i := strings.IndexAny(clause, "+-=")
		if i < 0 || i == len(clause)-1 || strings.Trim(clause[:i], "ugoa") != "" ||
			strings.Trim(clause[i+1:], "rwxXstugo") != "" {
			return false
		}
	}
	return true
}

func execPermission(cmd execCommand) *commandFacts {
	if !execPermissionCommands[cmd.word] || !cmd.seg.exitOK {
		return nil
	}
	paths, ok := execPermissionPaths(cmd)
	if !ok {
		return nil
	}
	if execPermissionReportsEveryChange(cmd) && cmd.seg.outputTrusted && cmd.seg.output == "" {
		// `chmod -c` prints one line per file it actually changed, so output
		// that is readable and empty proves it changed none. A command whose
		// output cannot be attributed to this segment is not silence — it is
		// no evidence — and still credits, as does an empty run without -c.
		return nil
	}
	inside, escaped := execPathsWorkspace(cmd, paths)
	facts := &commandFacts{}
	if inside || execCWDUncertainRelativeDestination(cmd, paths) {
		facts.categories = append(facts.categories, "permission.changed")
	}
	if inside {
		for _, p := range execWorkspacePaths(cmd, paths) {
			appendCommandTarget(facts, CommandTarget{Kind: "path", Value: p})
		}
	}
	if escaped {
		facts.categories = append(facts.categories, "workspace.escape")
	}
	if facts.empty() {
		return nil
	}
	return facts
}

// env.inspect ----------------------------------------------------------------

var execEnvReaders = map[string]bool{
	"cat": true, "head": true, "tail": true, "nl": true, "sed": true,
	"less": true, "more": true, "source": true, ".": true,
}

var execEnvReaderFlagModels = map[string]commandFlagModel{
	"head": {"-n": flagValue, "--lines": flagValue, "-c": flagValue, "--bytes": flagValue},
	"tail": {"-n": flagValue, "--lines": flagValue, "-c": flagValue, "--bytes": flagValue},
	"sed":  {"-e": flagValue, "--expression": flagValue, "-f": flagValue, "--file": flagValue},
	"less": {"-P": flagValue, "--prompt": flagValue, "-x": flagValue, "--tabs": flagValue},
}

// execEnvInspect records that the agent looked at the environment. It is
// deliberately target-free: naming the variable, let alone its value, is
// exactly what this category must never leak.
func execEnvInspect(cmd execCommand) *commandFacts {
	switch cmd.word {
	case "printenv":
		return execFacts("env.inspect")
	case "env", "set":
		// Only the bare forms: `set -e` configures the shell, and `env cmd`
		// runs something else (execLeadingTokens already dropped that prefix).
		if len(cmd.args) == 0 {
			return execFacts("env.inspect")
		}
		return nil
	}
	if execEnvReaders[cmd.word] && execReadsDotEnv(cmd.word, cmd.args) {
		return execFacts("env.inspect")
	}
	return nil
}

func execReadsDotEnv(word string, args []string) bool {
	scan := scanCommandArgs(args, execEnvReaderFlagModels[word])
	if scan.unknownFlag {
		return false
	}
	values := scan.operands
	if word == "sed" {
		if !scan.hasFlag("-e", "--expression", "-f", "--file") && len(values) != 0 {
			values = values[1:]
		}
		values = append(values, execFlagValues(scan, "-f", "--file")...)
	}
	for _, arg := range values {
		if strings.HasPrefix(path.Base(arg), ".env") {
			return true
		}
	}
	return false
}

// command.interactive --------------------------------------------------------

var execInteractiveCommands = map[string]bool{
	"vim": true, "vi": true, "nano": true, "less": true,
	"more": true, "top": true, "htop": true,
}

// execInteractive credits a command that waits for a human. The two git forms
// are here rather than with the other git verbs because what they prove is the
// interactivity, not the version-control effect.
func execInteractive(cmd execCommand) *commandFacts {
	if execInteractiveCommands[cmd.word] {
		return execFacts("command.interactive")
	}
	if cmd.word == "git" && (execSub(cmd.args) == "rebase" || execSub(cmd.args) == "add") {
		args := cmd.args[1:]
		scan := scanCommandArgs(args, gitFlagModels[execSub(cmd.args)])
		for _, flag := range scan.flags {
			if !scan.unknownFlag && (flag.name == "-i" || flag.name == "--interactive") && args[flag.index] == flag.name {
				return execFacts("command.interactive")
			}
		}
	}
	return nil
}

// workspace.escape -----------------------------------------------------------

// execGitConfigWriteFlags are the git config flags that mutate the config
// using only the key, not a second value operand (`--unset name` removes
// `name`; it does not take a value the way `-r`-style flags do elsewhere).
var execGitConfigWriteFlags = []string{"--unset", "--unset-all", "--add", "--replace-all"}
var execGitConfigReadFlags = []string{
	"--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l",
	"--get-color", "--get-colorbool",
}

var execGitConfigFlagModel = commandFlagModel{
	"--global": flagBoolean, "--system": flagBoolean, "--local": flagBoolean, "--worktree": flagBoolean,
	"--get": flagBoolean, "--get-all": flagBoolean, "--get-regexp": flagBoolean,
	"--get-urlmatch": flagBoolean, "--list": flagBoolean, "-l": flagBoolean,
	"--get-color": flagBoolean, "--get-colorbool": flagBoolean,
	"--unset": flagBoolean, "--unset-all": flagBoolean, "--add": flagBoolean,
	"--replace-all": flagBoolean, "--edit": flagBoolean, "-e": flagBoolean,
	"--type": flagValue, "--default": flagValue,
}

// execGitConfigWrites reports whether a `git config --global ...` invocation
// mutates the config, as opposed to reading it: `--get`, `--get-all`,
// `--list`/`-l`, and a lone key (git's shorthand for reading its value) all
// read; only a name-plus-value pair or an explicit write flag changes anything.
func execGitConfigWrites(configArgs []string) bool {
	scan := scanCommandArgs(configArgs, execGitConfigFlagModel)
	if scan.unknownFlag {
		return false
	}
	if scan.hasFlag(execGitConfigReadFlags...) {
		return false
	}
	if scan.hasFlag("--edit", "-e") {
		return false
	}
	if scan.hasFlag(execGitConfigWriteFlags...) {
		return true
	}
	return len(scan.operands) >= 2
}

func execPackageDestinationFlags(word string) []string {
	switch word {
	case "pip", "pip3":
		return []string{"-t", "--target", "--prefix", "--root", "--report"}
	case "npm", "pnpm", "yarn":
		return []string{"--prefix", "--cwd", "--modules-folder"}
	case "cargo":
		return []string{"--manifest-path"}
	case "gem":
		return []string{"-i", "--install-dir", "-n", "--bindir", "--build-root"}
	}
	return nil
}

func execPackageDestinations(scan commandArgScan, word string) []string {
	names := execPackageDestinationFlags(word)
	var values []string
	seen := make(map[string]bool)
	for i := len(scan.flags) - 1; i >= 0; i-- {
		flag := scan.flags[i]
		if slices.Contains(names, flag.name) {
			name := flag.name
			switch name {
			case "-t":
				name = "--target"
			case "-i":
				name = "--install-dir"
			case "-n":
				name = "--bindir"
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			if flag.name == "--report" && !execOutputPath(flag.value) {
				continue
			}
			values = append(values, flag.value)
		}
	}
	return values
}

// execEscapeFlags credits global and user package installs, package destination
// flags outside the workspace, and global git config writes.
func execEscapeFlags(cmd execCommand) *commandFacts {
	if !cmd.seg.exitOK {
		return nil
	}
	args, isInstall := execInstallArgs(cmd)
	if isInstall {
		scan := scanCommandArgs(args, execPackageFlagModelFor(cmd.word))
		if scan.unknownFlag {
			return nil
		}
		if _, escaped := execPathsWorkspace(cmd, execPackageDestinations(scan, cmd.word)); escaped {
			return execFacts("workspace.escape")
		}
	}
	switch {
	case isInstall && execNodeManagers[cmd.word] && execHasFlag(args, execPackageFlagModelFor(cmd.word), "-g", "--global"):
	case isInstall && (cmd.word == "pip" || cmd.word == "pip3") && execHasFlag(args, execPackageFlagModelFor(cmd.word), "--user"):
	case cmd.word == "git" && execSub(cmd.args) == "config" && execHasFlag(cmd.args[1:], execGitConfigFlagModel, "--global") &&
		execGitConfigWrites(cmd.args[1:]):
	default:
		return nil
	}
	return execFacts("workspace.escape")
}

// execNoChangeWrites preserves explicit side effects of otherwise non-mutating
// modes. pip's dry-run report is currently the only such supported spelling.
func execNoChangeWrites(cmd execCommand) *commandFacts {
	if cmd.word != "pip" && cmd.word != "pip3" {
		return nil
	}
	args, isInstall := execInstallArgs(cmd)
	if !isInstall || !cmd.seg.exitOK {
		return nil
	}
	scan := scanCommandArgs(args, execPipFlagModel)
	if scan.unknownFlag {
		return nil
	}
	for _, report := range execFlagValues(scan, "--report") {
		if execOutputPath(report) {
			if _, escaped := execPathsWorkspace(cmd, []string{report}); escaped {
				return execFacts("workspace.escape")
			}
		}
	}
	return nil
}

// execFlagModelFor supplies classifyExec's shared informational gate with the
// same command grammar its target or mode extractor uses.
func execFlagModelFor(cmd execCommand) commandFlagModel {
	switch {
	case execNetworkCommands[cmd.word]:
		return execHostFlagModelFor(cmd.word)
	case execNodeManagers[cmd.word] || cmd.word == "pip" || cmd.word == "pip3" ||
		cmd.word == "cargo" || cmd.word == "gem" || cmd.word == "go" || cmd.word == "brew":
		return execPackageFlagModelFor(cmd.word)
	case cmd.word == "rg" || cmd.word == "grep":
		return execSearchFlagModelFor(cmd.word)
	case cmd.word == "make":
		return execMakeFlagModel
	case cmd.word == "screen":
		return execScreenFlagModel
	case cmd.word == "pytest":
		return execPytestFlagModel
	case cmd.word == "tar":
		return execTarFlagModel
	case cmd.word == "unzip":
		return execUnzipFlagModel
	case cmd.word == "gunzip":
		return execGunzipFlagModel
	case execPermissionCommands[cmd.word]:
		return execPermissionFlagModelFor(cmd.word)
	case cmd.word == "git" && execSub(cmd.args) == "config":
		return execGitConfigFlagModel
	case cmd.word == "git":
		return gitFlagModels[execSub(cmd.args)]
	case execEnvReaders[cmd.word]:
		return execEnvReaderFlagModels[cmd.word]
	default:
		return nil
	}
}

// execCommandAssertsNoChange adds command-specific modes to the shared help,
// version and dry-run gate. These spellings cannot be global: -G connects for
// some tools but only prints configuration for ssh, while -n is Homebrew's
// dry-run flag but has unrelated meanings elsewhere.
func execCommandAssertsNoChange(cmd execCommand) bool {
	model := execFlagModelFor(cmd)
	if cmd.word != "gem" && commandAssertsNoChange(cmd.args, model) {
		return true
	}
	scan := scanCommandArgs(cmd.args, model)
	switch cmd.word {
	case "npm":
		return scan.hasFlag("--package-lock-only")
	case "pnpm":
		return scan.hasFlag("--lockfile-only")
	case "yarn":
		mode, ok := scan.flagValue("--mode")
		return ok && mode == "update-lockfile"
	case "brew":
		return scan.hasFlag("-n", "--dry-run")
	case "curl":
		return scan.hasFlag("-M", "--manual")
	case "gem":
		return scan.hasModeFlag("--help", "-h", "--usage", "--dry-run") || scan.hasFlag("--explain")
	case "go":
		return slices.Contains(execVerifySubcommands["go"], execSub(cmd.args)) && scan.hasFlag("-n")
	case "make":
		return scan.hasFlag("-n", "--just-print", "--dry-run", "--recon", "-q", "--question", "-t", "--touch")
	case "screen":
		return scan.hasFlag("-v")
	case "ssh":
		return scan.hasFlag("-G", "-Q")
	}
	return false
}
