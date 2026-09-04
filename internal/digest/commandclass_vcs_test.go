package digest

import (
	"reflect"
	"slices"
	"testing"
)

// vcsSegment builds the single-segment input classifyVCS is handed, so these
// tests exercise the git classifier alone and not its siblings.
func vcsSegment(command, output string, exitOK bool) commandSegment {
	return commandSegment{
		raw:     command,
		tokens:  tokensForSegment(command),
		command: command,
		output:  output,
		exitOK:  exitOK,
		ws:      testWorkspace(),
	}
}

func vcsCategories(facts *commandFacts) []string {
	if facts == nil {
		return nil
	}
	return facts.categories
}

func TestClassifyVCSCategories(t *testing.T) {
	cases := []struct {
		name    string
		command string
		exitOK  bool
		want    []string
	}{
		// vcs.read
		{"status", "git status", true, []string{"vcs.read"}},
		{"diff with args", "git diff --stat HEAD~1", true, []string{"vcs.read"}},
		{"log", "git log --oneline -n 5", true, []string{"vcs.read"}},
		{"show", "git show abc123", true, []string{"vcs.read"}},
		{"blame", "git blame internal/digest/trace.go", true, []string{"vcs.read"}},
		{"ls-files", "git ls-files", true, []string{"vcs.read"}},
		{"global flag before verb", "git -C /work/repo status", true, []string{"vcs.read"}},
		{"config override before verb", "git -c core.pager=cat log", true, []string{"vcs.read"}},
		{"absolute git path", "/usr/bin/git status", true, []string{"vcs.read"}},
		{"leading env assignment", "GIT_PAGER=cat git diff", true, []string{"vcs.read"}},
		{"sudo prefix", "sudo git status", true, []string{"vcs.read"}},
		// `env NAME=val cmd` is a prefix, same as classifyExec's execLeadingTokens
		{"env prefix before git", "env GIT_PAGER=cat git diff", true, []string{"vcs.read"}},
		{"direct git dir redirect withholds mutation", "GIT_DIR=../other/.git git commit -m x", true, nil},
		{"direct work tree redirect withholds mutation", "GIT_WORK_TREE=../other git commit -m x", true, nil},
		{"env git dir redirect withholds mutation", "env GIT_DIR=../other/.git git commit -m x", true, nil},
		{"env work tree redirect withholds mutation", "env GIT_WORK_TREE=../other git commit -m x", true, nil},
		{"assignment ending in git does not hide later redirect", "PATH_TO_GIT=/usr/bin/git GIT_DIR=/tmp/other/.git git commit -m x", true, nil},
		// a read is an observation, so it survives a nonzero exit
		{"failed status still read", "git status", false, []string{"vcs.read"}},
		{"failed unknown global option never invokes status", "git --definitely-unknown status", false, nil},
		{"status help credits nothing", "git status --help", true, nil},
		{"global help before mutation credits nothing", "git --help commit", true, nil},
		{"global version before mutation credits nothing", "git --version commit", true, nil},
		{"bare exec path before mutation credits nothing", "git --exec-path commit", true, nil},
		{"html path before mutation credits nothing", "git --html-path commit", true, nil},
		{"man path before mutation credits nothing", "git --man-path commit", true, nil},
		{"info path before mutation credits nothing", "git --info-path commit", true, nil},
		{"list commands before mutation credits nothing", "git --list-cmds=main commit", true, nil},

		// vcs.mutate
		{"add", "git add -A", true, []string{"vcs.mutate"}},
		{"commit", "git commit -m 'feat: thing'", true, []string{"vcs.mutate"}},
		{"attached exec path permits mutation", "git --exec-path=/usr/libexec/git-core commit -m x", true, []string{"vcs.mutate"}},
		{"checkout", "git checkout -b feature", true, []string{"vcs.mutate"}},
		{"switch", "git switch main", true, []string{"vcs.mutate"}},
		{"branch delete", "git branch -d old", true, []string{"vcs.mutate"}},
		{"branch create", "git branch newfeature", true, []string{"vcs.mutate"}},
		{"merge", "git merge origin/main", true, []string{"vcs.mutate"}},
		{"stash", "git stash", true, []string{"vcs.mutate"}},
		{"stash push", "git stash push -m wip", true, []string{"vcs.mutate"}},
		{"tag create", "git tag v1.2.3", true, []string{"vcs.mutate"}},
		{"restore", "git restore internal/digest/trace.go", true, []string{"vcs.mutate"}},
		{"plain reset is mutate", "git reset HEAD~1", true, []string{"vcs.mutate"}},
		// a state change is only credited when the command succeeded
		{"failed commit credits nothing", "git commit -m 'feat: thing'", false, nil},
		{"failed add credits nothing", "git add -A", false, nil},
		// a dry run asserts a commit/stage that never happened, the same
		// no-op class as a dry-run push below.
		{"commit --dry-run credits nothing", "git commit --dry-run -m 'wip'", true, nil},
		{"commit help credits nothing", "git commit --help", true, nil},
		{"commit short help credits nothing", "git commit -h", true, nil},
		{"commit message equal to help still mutates", "git commit -m --help", true, []string{"vcs.mutate"}},
		{"commit message equal to amend still mutates", "git commit -m --amend", true, []string{"vcs.mutate"}},
		{"add -n credits nothing", "git add -n .", true, nil},
		{"add --dry-run credits nothing", "git add --dry-run .", true, nil},
		// -n clustered with another boolean short flag is still a dry run.
		{"add -fn clustered still credits nothing", "git add -fn .", true, nil},
		{"add -nv clustered still credits nothing", "git add -nv .", true, nil},
		// branch/tag list by default; only a mutating shape proves a change
		{"bare branch lists, credits nothing", "git branch", true, nil},
		{"branch -a lists, credits nothing", "git branch -a", true, nil},
		{"clustered branch listing flags credit nothing", "git branch -av feature/x", true, nil},
		{"branch --list credits nothing", "git branch --list", true, nil},
		{"branch --contains lists, credits nothing", "git branch --contains HEAD", true, nil},
		{"branch format lists, credits nothing", "git branch --format '%(refname)'", true, nil},
		{"branch sort with filter operand lists, credits nothing", "git branch --sort committerdate 'feature/*'", true, nil},
		{"branch unmodeled option withholds operand inference", "git branch --color always 'feature/*'", true, nil},
		{"bare tag lists, credits nothing", "git tag", true, nil},
		{"tag -l credits nothing", "git tag -l", true, nil},
		{"tag format lists, credits nothing", "git tag --format '%(refname)'", true, nil},
		{"tag annotations with filter operand list, credits nothing", "git tag -n1 'v*'", true, nil},
		{"tag sort with filter operand lists, credits nothing", "git tag --sort version:refname 'v*'", true, nil},
		{"clustered tag listing flags credit nothing", "git tag -ln v1.4", true, nil},
		{"stash list credits nothing", "git stash list", true, nil},
		{"stash show credits nothing", "git stash show", true, nil},
		{"stash message equal to drop still mutates", "git stash -m drop", true, []string{"vcs.mutate"}},
		// a redirection's target is not a branch/tag name to act on: these are
		// listings, not mutations, exactly like their unredirected forms above
		{"tag redirected to file credits nothing", "git tag > tags.txt", true, nil},
		{"branch redirected to file credits nothing", "git branch > /tmp/b.txt", true, nil},
		{"branch stderr redirected credits nothing", "git branch 2>/dev/null", true, nil},
		{"tag appended to file credits nothing", "git tag >> tags.txt", true, nil},
		{"branch redirected from file credits nothing", "git branch < /dev/null", true, nil},

		// vcs.rewrite, which outranks the mutate it is a variant of
		{"amend is rewrite only", "git commit --amend --no-edit", true, []string{"vcs.rewrite"}},
		{"rebase", "git rebase main", true, []string{"vcs.rewrite"}},
		{"rebase help credits nothing", "git rebase --help", true, nil},
		{"interactive rebase", "git rebase -i HEAD~3", true, []string{"vcs.rewrite"}},
		{"hard reset is rewrite only", "git reset --hard HEAD~1", true, []string{"vcs.rewrite"}},
		{"stash drop is rewrite only", "git stash drop stash@{0}", true, []string{"vcs.rewrite"}},
		{"filter-branch", "git filter-branch --tree-filter true HEAD", true, []string{"vcs.rewrite"}},
		// A force push rewrote history *and* changed the forge; the two facts
		// live in different places and are both credited.
		{"force push long", "git push --force origin main", true, []string{"vcs.rewrite", "forge.mutate"}},
		{"force push short", "git push -f origin main", true, []string{"vcs.rewrite", "forge.mutate"}},
		{"force push clustered", "git push -fu origin main", true, []string{"vcs.rewrite", "forge.mutate"}},
		{"force with lease", "git push --force-with-lease origin main", true, []string{"vcs.rewrite", "forge.mutate"}},
		{"force with lease valued", "git push --force-with-lease=main:abc origin main", true, []string{"vcs.rewrite", "forge.mutate"}},
		{"push option value is not a force flag", "git push -ofoo origin main", true, []string{"forge.mutate"}},
		{"long push option value is not a force flag", "git push --push-option=foo origin main", true, []string{"forge.mutate"}},
		{"failed rebase credits nothing", "git rebase main", false, nil},

		// forge.mutate
		{"push", "git push", true, []string{"forge.mutate"}},
		{"push upstream", "git push -u origin feature", true, []string{"forge.mutate"}},
		{"clustered quiet dry-run push credits nothing", "git push -qn origin main", true, nil},
		{"opaque push cluster credits nothing", "git push -xq origin main", true, nil},
		{"failed push credits nothing", "git push", false, nil},
		{"push help credits nothing", "git push --help", true, nil},
		{"stash help credits nothing", "git stash --help", true, nil},

		// vcs.provenance, an observation like the reads
		{"rev-parse head", "git rev-parse HEAD", true, []string{"vcs.provenance"}},
		{"rev-parse head verified", "git rev-parse --verify HEAD", true, []string{"vcs.provenance"}},
		{"remote verbose", "git remote -v", true, []string{"vcs.provenance"}},
		{"remote long verbose", "git remote --verbose", true, []string{"vcs.provenance"}},
		{"remote verbose add is not provenance", "git remote -v add origin https://example.com/repo.git", true, nil},
		{"remote verbose remove is not provenance", "git remote -v remove origin", true, nil},
		{"remote verbose set-url is not provenance", "git remote -v set-url origin https://example.com/repo.git", true, nil},
		{"failed rev-parse still provenance", "git rev-parse HEAD", false, []string{"vcs.provenance"}},
		{"rev-parse without HEAD", "git rev-parse --show-toplevel", true, nil},
		{"bare remote is not provenance", "git remote", true, nil},
		{"rev-parse with another operand is not provenance", "git rev-parse HEAD main", true, nil},

		// a redirected repo cannot be proven to be the workspace, so state
		// changes are uncredited even though the verb and exit status match
		{"commit behind -C credits nothing", "git -C ../other-repo commit -m x", true, nil},
		{"force push behind --work-tree credits nothing", "git --work-tree /elsewhere push --force", true, nil},
		{"force push behind -C credits nothing", "git -C /elsewhere push --force", true, nil},
		{"commit behind --git-dir= equals form credits nothing", "git --git-dir=/other/.git commit -m x", true, nil},
		{"push behind --work-tree= equals form credits nothing", "git --work-tree=/elsewhere push --force", true, nil},
		// A provenance read behind a redirect still happened, so the category
		// stands; only the identifying sha is withheld, exactly as vcs.read
		// stays credited for `git -C other status`.
		{"rev-parse behind -C keeps the category without the sha", "git -C ../other rev-parse HEAD", true, []string{"vcs.provenance"}},

		// a dry-run push changes nothing, remote or local
		{"dry-run force push credits nothing", "git push --force --dry-run", true, nil},
		{"dry-run push short flag credits nothing", "git push -n", true, nil},
		{"clustered verbose dry-run push credits nothing", "git push -nv origin main", true, nil},
		{"attached dry-run push credits nothing", "git push --dry-run=true origin main", true, nil},

		// nothing here invokes git as the command word
		{"echoed git push", "echo git push", true, nil},
		{"git later in a pipeline", "python x.py | git hash-object --stdin", true, nil},
		{"git inside a commit message", "echo 'run git commit'", true, nil},
		{"unbalanced quotes refuse tokenization", `git commit -m "unterminated`, true, nil},
		{"empty command", "", true, nil},
		{"git with no subcommand", "git --version", true, nil},
		{"another vcs", "hg status", true, nil},
		{"unknown subcommand", "git bisect start", true, nil},
		// gh is the exec classifier's half of forge.mutate, not this one
		{"gh pr create", "gh pr create --fill", true, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := vcsCategories(classifyVCS(vcsSegment(c.command, "", c.exitOK)))
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("classifyVCS(%q, exitOK=%v) categories = %v, want %v", c.command, c.exitOK, got, c.want)
			}
		})
	}
}

func TestClassifyVCSSkippedConditional(t *testing.T) {
	for _, c := range []struct {
		name    string
		command string
		exitOK  bool
	}{
		{"successful left side skips or branch", "true || git status", true},
		{"failed left side skips and branch", "false && git status", false},
		{"wrapped failed left side skips and branch", "command false && git status", false},
		{"successful printf skips or branch", "printf x || git status", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			facts := classifyCommand(c.command, "", c.exitOK, testWorkspace())
			if facts != nil && slices.Contains(facts.categories, "vcs.read") {
				t.Fatalf("classifyCommand(%q) categories = %v, want no vcs.read", c.command, facts.categories)
			}
		})
	}
}

// vcsSegmentCwdUncertain builds a segment as if an earlier `cd`/`pushd` in the
// same command had already made the shell's working directory unknown — the
// same handoff commandclass_fs_test.go's fsSegmentCwdUncertain exercises for
// classifyFS.
func vcsSegmentCwdUncertain(command string, exitOK bool) commandSegment {
	seg := vcsSegment(command, "", exitOK)
	seg.cwdUncertain = true
	return seg
}

// TestClassifyVCSCwdUncertain covers `cd ../other-repo && git commit -m wip`:
// the same act as `git -C ../other-repo commit -m wip`, which is already
// denied via redirected. Without also checking cwdUncertain, this spelling
// slipped through and credited a state change to a repository this run is not
// about. vcs.read stays credited, but provenance requires a proven repository
// identity and therefore does not.
func TestClassifyVCSCwdUncertain(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		{"commit after an unresolved cd credits nothing", "git commit -m wip", nil},
		{"push after an unresolved cd credits nothing", "git push", nil},
		{"force push after an unresolved cd credits nothing", "git push --force", nil},
		{"add after an unresolved cd credits nothing", "git add -A", nil},
		{"amend after an unresolved cd credits nothing", "git commit --amend --no-edit", nil},
		{"status after an unresolved cd still reads", "git status", []string{"vcs.read"}},
		// Same rule as `status` above: an observational category survives an
		// unresolved cd, its identifying value does not.
		{"rev-parse after an unresolved cd keeps the category", "git rev-parse HEAD", []string{"vcs.provenance"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := vcsCategories(classifyVCS(vcsSegmentCwdUncertain(c.command, true)))
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("classifyVCS(%q) with cwdUncertain categories = %v, want %v", c.command, got, c.want)
			}
		})
	}
}

func TestClassifyVCSProvenanceTargets(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"
	cases := []struct {
		name    string
		command string
		output  string
		want    []CommandTarget
	}{
		{"head sha", "git rev-parse HEAD", sha + "\n", []CommandTarget{{Kind: "ref", Value: sha}}},
		{"multiple sha lines prove nothing", "git rev-parse HEAD", sha + "\n" + sha + "\n", nil},
		{"diagnostic sha line proves nothing", "git rev-parse HEAD", "def_param scope:command SECRET=" + sha + "\n" + sha + "\n", nil},
		{"another rev operand proves nothing", "git rev-parse main HEAD", sha + "\n", nil},
		{"redirected repository proves nothing", "git -C ../other rev-parse HEAD", sha + "\n", nil},
		{"environment redirected repository proves nothing", "GIT_DIR=../other/.git git rev-parse HEAD", sha + "\n", nil},
		{"abbreviated sha proves nothing", "git rev-parse --short HEAD", "0123456\n", nil},
		{"empty output proves nothing", "git rev-parse HEAD", "", nil},
		{
			"remote urls",
			"git remote -v",
			"origin\tgit@github.com:nobbettt/acta.git (fetch)\norigin\tgit@github.com:nobbettt/acta.git (push)\n",
			[]CommandTarget{{Kind: "url", Value: "github.com"}},
		},
		{
			"two remotes",
			"git remote -v",
			"origin\thttps://example.test/a.git (fetch)\nupstream\thttps://example.test/b.git (fetch)\n",
			[]CommandTarget{{Kind: "url", Value: "https://example.test"}},
		},
		{"unmarked lines are not remotes", "git remote -v", "origin https://example.test/a.git\n", nil},
		{
			"embedded token is stripped",
			"git remote -v",
			"origin\thttps://x-access-token:ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@github.com/org/repo.git (fetch)\n",
			[]CommandTarget{{Kind: "url", Value: "https://github.com"}},
		},
		{
			"embedded ssh password is stripped",
			"git remote -v",
			"origin\tssh://deploy:hunter2@example.test/org/repo.git (fetch)\n",
			[]CommandTarget{{Kind: "url", Value: "ssh://example.test"}},
		},
		{
			"scp-like remote has no userinfo to strip",
			"git remote -v",
			"origin\tgit@github.com:nobbettt/acta.git (fetch)\n",
			[]CommandTarget{{Kind: "url", Value: "github.com"}},
		},
		{"read verb invents no target", "git log --oneline", sha + " subject\n", nil},
		{
			// net/url.Parse rejects a "|" in userinfo, so this must not fall back
			// to publishing raw with the credential still attached.
			"credential with url-illegal char is stripped",
			"git remote -v",
			"origin\thttps://u:p|ss@example.test/o/r.git (fetch)\n",
			[]CommandTarget{{Kind: "url", Value: "https://example.test"}},
		},
		{
			// net/url.Parse rejects an invalid "%" escape the same way.
			"credential with invalid percent escape is stripped",
			"git remote -v",
			"origin\thttps://u:p%ZZss@example.test/o/r.git (fetch)\n",
			[]CommandTarget{{Kind: "url", Value: "https://example.test"}},
		},
		{
			// Regression: gitRemoteURLs only stripped userinfo, unlike execFirstURL
			// and execPackage's identical url targets, both of which also cut the
			// query string. A query-string credential (a private/access token) on
			// a configured remote would otherwise reach the published target.
			"query string credential is stripped",
			"git remote -v",
			"origin\thttps://git.example.test/o/r.git?private_token=glpat-SECRET (fetch)\n",
			[]CommandTarget{{Kind: "url", Value: "https://git.example.test"}},
		},
		{
			"url fragment is stripped",
			"git remote -v",
			"origin\thttps://git.example.test/o/r.git#internal-token (fetch)\n",
			[]CommandTarget{{Kind: "url", Value: "https://git.example.test"}},
		},
		{
			"expanded path credential is stripped",
			"git remote -v",
			"origin\thttps://git.example.test/sk-live-SECRET/repo.git\t(fetch)\n",
			[]CommandTarget{{Kind: "url", Value: "https://git.example.test"}},
		},
		{
			"opaque remote is dropped closed",
			"git remote -v",
			"origin\tu:p@h/x\t(fetch)\n",
			nil,
		},
		{
			"ambiguous schemeless userinfo is dropped closed",
			"git remote -v",
			"origin\tuser@host/path\t(fetch)\n",
			nil,
		},
		{
			"unknown remote scheme is dropped closed",
			"git remote -v",
			"origin\tsecret123://example.com/repo\t(fetch)\n",
			nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts := classifyVCS(vcsSegment(c.command, c.output, true))
			var got []CommandTarget
			if facts != nil {
				got = facts.targets
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("classifyVCS(%q) targets = %v, want %v", c.command, got, c.want)
			}
		})
	}
}
