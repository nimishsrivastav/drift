package repo

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestNormalizeURL(t *testing.T) {
	const want = "https://github.com/acme/demo.git"
	tests := []struct {
		name, raw, want string
		wantErr         bool
	}{
		{name: "https", raw: "https://github.com/acme/demo", want: want},
		{name: "https with .git", raw: "https://github.com/acme/demo.git", want: want},
		{name: "git+https", raw: "git+https://github.com/acme/demo.git", want: want},
		{name: "git scheme", raw: "git://github.com/acme/demo.git", want: want},
		{name: "http is upgraded", raw: "http://github.com/acme/demo", want: want},
		{name: "ssh", raw: "ssh://git@github.com/acme/demo.git", want: want},
		{name: "git+ssh", raw: "git+ssh://git@github.com/acme/demo.git", want: want},
		{name: "invalid but common ssh", raw: "git+ssh://git@github.com:acme/demo.git", want: want},
		{name: "scp form", raw: "git@github.com:acme/demo.git", want: want},
		{name: "github shorthand", raw: "github:acme/demo", want: want},
		{name: "shorthand with branch", raw: "github:acme/demo#main", want: want},
		{name: "bare shorthand", raw: "acme/demo", want: want},
		{name: "subpath link", raw: "https://github.com/acme/demo/tree/main/packages/x", want: want},
		{name: "trailing slash", raw: "https://github.com/acme/demo/", want: want},
		{name: "mixed-case host", raw: "https://GitHub.com/acme/demo", want: want},
		{name: "fragment", raw: "https://github.com/acme/demo#readme", want: want},
		{name: "whitespace", raw: "  https://github.com/acme/demo\n", want: want},
		{name: "credentials are dropped", raw: "https://user:token@github.com/acme/demo", want: want}, //nolint:gosec // not a real credential
		{name: "port is dropped", raw: "https://github.com:8443/acme/demo", want: want},
		{name: "gitlab shorthand", raw: "gitlab:acme/demo", want: "https://gitlab.com/acme/demo.git"},
		{name: "gitlab subgroup", raw: "https://gitlab.com/acme/group/demo.git", want: "https://gitlab.com/acme/group/demo.git"},
		{name: "gitlab subpath", raw: "https://gitlab.com/acme/demo/-/tree/main", want: "https://gitlab.com/acme/demo.git"},
		{name: "bitbucket", raw: "https://bitbucket.org/acme/demo", want: "https://bitbucket.org/acme/demo.git"},

		{name: "transport helper", raw: "ext::sh -c touch%20/tmp/pwned", wantErr: true},
		{name: "fd helper", raw: "fd::3", wantErr: true},
		{name: "ext behind git+", raw: "git+ext::sh -c id", wantErr: true},
		{name: "file URL", raw: "file:///etc/passwd", wantErr: true},
		{name: "local path", raw: "/srv/git/demo.git", wantErr: true},
		{name: "relative path", raw: "../demo", wantErr: true},
		{name: "option injection", raw: "--upload-pack=touch/pwned", wantErr: true},
		{name: "option as owner", raw: "https://github.com/--upload-pack=x/demo", wantErr: true},
		{name: "other host", raw: "https://evil.example/acme/demo", wantErr: true},
		{name: "lookalike host", raw: "https://github.com.evil.example/acme/demo", wantErr: true},
		{name: "userinfo trick", raw: "https://github.com@evil.example/acme/demo", wantErr: true},
		{name: "internal address", raw: "http://169.254.169.254/latest/meta", wantErr: true},
		{name: "scp to other host", raw: "git@evil.example:acme/demo.git", wantErr: true},
		{name: "traversal", raw: "https://github.com/../../acme/demo", wantErr: true},
		{name: "repo name only .git", raw: "https://github.com/acme/.git", wantErr: true},
		{name: "owner only", raw: "https://github.com/acme", wantErr: true},
		{name: "no path", raw: "https://github.com", wantErr: true},
		{name: "unknown shorthand", raw: "gist:12345", wantErr: true},
		{name: "empty", raw: "   ", wantErr: true},
		{name: "space in path", raw: "https://github.com/acme/de mo", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeURL(tt.raw)
			if tt.wantErr {
				if !errors.Is(err, ErrUnsupportedURL) {
					t.Fatalf("got %q, err %v, want ErrUnsupportedURL", got, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTagCandidates(t *testing.T) {
	tests := []struct {
		name, pkg, version string
		want               []string
	}{
		{"plain", "demo", "1.2.3", []string{"demo@1.2.3", "v1.2.3", "1.2.3"}},
		{"scoped", "@acme/demo", "1.2.3", []string{"@acme/demo@1.2.3", "demo@1.2.3", "v1.2.3", "1.2.3"}},
		{"prerelease and build", "demo", "1.0.0-rc.1+b2", []string{"demo@1.0.0-rc.1+b2", "v1.0.0-rc.1+b2", "1.0.0-rc.1+b2"}},
		{"glob in version", "demo", "1.*", nil},
		{"traversal in version", "demo", "1..2", nil},
		{"space in version", "demo", "1 2", nil},
		{"lock suffix", "demo", "1.lock", nil},
		{"option-like version", "demo", "--upload-pack=x", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TagCandidates(tt.pkg, tt.version)
			if !slices.Equal(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseRefs(t *testing.T) {
	oid := strings.Repeat("a", 40)
	input := oid + "\trefs/tags/v1\n" + "not-an-oid\trefs/tags/v2\n" + "garbage line\n\n" + strings.Repeat("b", 64) + "\trefs/tags/v3\n"
	got := parseRefs([]byte(input))
	if len(got) != 2 || got["refs/tags/v1"] != oid || got["refs/tags/v3"] != strings.Repeat("b", 64) {
		t.Errorf("got %v", got)
	}
}

func TestCapWriter(t *testing.T) {
	w := &capWriter{limit: 4}
	for _, chunk := range []string{"ab", "cdef", "gh"} {
		if n, err := w.Write([]byte(chunk)); err != nil || n != len(chunk) {
			t.Fatalf("Write(%q) = %d, %v", chunk, n, err)
		}
	}
	if w.buf.String() != "abcd" || !w.truncated {
		t.Errorf("buf = %q, truncated = %v", w.buf.String(), w.truncated)
	}
}

// fixtureGit runs git for building test repositories, isolated from the host's configuration.
func fixtureGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", args...) //nolint:gosec // fixed by the tests
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=fixture",
		"GIT_AUTHOR_EMAIL=fixture@example.invalid",
		"GIT_COMMITTER_NAME=fixture",
		"GIT_COMMITTER_EMAIL=fixture@example.invalid",
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func commitAll(t *testing.T, dir, message string) string {
	t.Helper()
	fixtureGit(t, dir, "add", "-A")
	fixtureGit(t, dir, "commit", "-q", "-m", message)
	return fixtureGit(t, dir, "rev-parse", "HEAD")
}

// newFixture creates a repository and a Resolver allowed to read it. Nothing else in these
// tests needs the file protocol: the default Resolver refuses it.
func newFixture(t *testing.T) (repoDir, cloneURL string, r *Resolver) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repoDir = t.TempDir()
	fixtureGit(t, repoDir, "init", "-q", "-b", "main")
	r, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r.protocols = []string{"file"}
	return repoDir, "file://" + repoDir, r
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func noTempLeft(t *testing.T, r *Resolver) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(r.root, "tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("work directories left behind: %v", entries)
	}
}

func TestCheckoutTagKinds(t *testing.T) {
	tests := []struct {
		name    string
		pkg     string
		tagArgs []string
		wantRef string
	}{
		{"lightweight v tag", "demo", []string{"tag", "v1.0.0"}, "v1.0.0"},
		{"annotated v tag", "demo", []string{"tag", "-a", "-m", "release", "v1.0.0"}, "v1.0.0"},
		{"bare tag", "demo", []string{"tag", "1.0.0"}, "1.0.0"},
		{"name tag", "demo", []string{"tag", "demo@1.0.0"}, "demo@1.0.0"},
		{"scoped tag", "@acme/demo", []string{"tag", "@acme/demo@1.0.0"}, "@acme/demo@1.0.0"},
		{"unscoped tag for scoped package", "@acme/demo", []string{"tag", "demo@1.0.0"}, "demo@1.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoDir, cloneURL, r := newFixture(t)
			writeFile(t, filepath.Join(repoDir, "index.js"), "tagged\n")
			commit := commitAll(t, repoDir, "release")
			fixtureGit(t, repoDir, tt.tagArgs...)
			writeFile(t, filepath.Join(repoDir, "index.js"), "later\n")
			commitAll(t, repoDir, "after the release")

			got, err := r.checkout(t.Context(), cloneURL, tt.pkg, "1.0.0")
			if err != nil {
				t.Fatal(err)
			}
			if got.Ref != tt.wantRef || got.Commit != commit {
				t.Errorf("checkout = %+v, want ref %s commit %s", got, tt.wantRef, commit)
			}
			content, err := os.ReadFile(filepath.Join(got.Path, "index.js"))
			if err != nil {
				t.Fatal(err)
			}
			if string(content) != "tagged\n" {
				t.Errorf("content = %q", content)
			}
			if exists(filepath.Join(got.Path, ".git")) {
				t.Error(".git was left in the checkout")
			}
			noTempLeft(t, r)
		})
	}
}

func TestCheckoutPrefersSpecificTag(t *testing.T) {
	repoDir, cloneURL, r := newFixture(t)
	writeFile(t, filepath.Join(repoDir, "owner"), "other package\n")
	commitAll(t, repoDir, "other package release")
	fixtureGit(t, repoDir, "tag", "v1.0.0")
	writeFile(t, filepath.Join(repoDir, "owner"), "this package\n")
	want := commitAll(t, repoDir, "this package release")
	fixtureGit(t, repoDir, "tag", "demo@1.0.0")

	got, err := r.checkout(t.Context(), cloneURL, "demo", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if got.Ref != "demo@1.0.0" || got.Commit != want {
		t.Errorf("checkout = %+v, want demo@1.0.0 at %s", got, want)
	}
}

func TestCheckoutBranchCannotImpersonateTag(t *testing.T) {
	repoDir, cloneURL, r := newFixture(t)
	writeFile(t, filepath.Join(repoDir, "index.js"), "tag\n")
	want := commitAll(t, repoDir, "tagged")
	fixtureGit(t, repoDir, "tag", "v1.0.0")
	fixtureGit(t, repoDir, "checkout", "-q", "-b", "other")
	writeFile(t, filepath.Join(repoDir, "index.js"), "branch\n")
	commitAll(t, repoDir, "same name as the tag")
	fixtureGit(t, repoDir, "branch", "v1.0.0")

	got, err := r.checkout(t.Context(), cloneURL, "demo", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if got.Commit != want {
		t.Errorf("commit = %s, want the tag's %s", got.Commit, want)
	}
}

func TestCheckoutNoMatchingTag(t *testing.T) {
	repoDir, cloneURL, r := newFixture(t)
	writeFile(t, filepath.Join(repoDir, "index.js"), "x\n")
	commitAll(t, repoDir, "release")
	fixtureGit(t, repoDir, "tag", "v1.0.0")
	fixtureGit(t, repoDir, "tag", "x1.0.1")
	fixtureGit(t, repoDir, "branch", "1.0.1") // a branch is not a tag

	if _, err := r.checkout(t.Context(), cloneURL, "demo", "1.0.1"); !errors.Is(err, ErrNoMatchingTag) {
		t.Fatalf("err = %v, want ErrNoMatchingTag", err)
	}
	if _, err := r.checkout(t.Context(), cloneURL, "demo", "1.*"); !errors.Is(err, ErrNoMatchingTag) {
		t.Fatalf("err = %v, want ErrNoMatchingTag for an unusable version", err)
	}
	noTempLeft(t, r)
}

func TestCheckoutReusesExistingTree(t *testing.T) {
	repoDir, cloneURL, r := newFixture(t)
	writeFile(t, filepath.Join(repoDir, "index.js"), "x\n")
	commitAll(t, repoDir, "release")
	fixtureGit(t, repoDir, "tag", "v1.0.0")

	first, err := r.checkout(t.Context(), cloneURL, "demo", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(first.Path, "marker")
	writeFile(t, marker, "still here")
	second, err := r.checkout(t.Context(), cloneURL, "demo", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("first = %+v, second = %+v", first, second)
	}
	if !exists(marker) {
		t.Error("the existing checkout was replaced")
	}
}

func TestCheckoutTreatsContentAsData(t *testing.T) {
	repoDir, cloneURL, r := newFixture(t)

	// A symlink out of the tree, and a submodule pointing at a repository with a marker file.
	sub := t.TempDir()
	fixtureGit(t, sub, "init", "-q", "-b", "main")
	writeFile(t, filepath.Join(sub, "from-submodule"), "x")
	commitAll(t, sub, "submodule")
	fixtureGit(t, repoDir, "-c", "protocol.file.allow=always", "submodule", "add", "-q", "file://"+sub, "vendored")
	if err := os.Symlink("/etc/passwd", filepath.Join(repoDir, "escape")); err != nil {
		t.Fatal(err)
	}
	commitAll(t, repoDir, "release")
	fixtureGit(t, repoDir, "tag", "v1.0.0")

	got, err := r.checkout(t.Context(), cloneURL, "demo", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(got.Path, "vendored", "from-submodule")) {
		t.Error("submodule was fetched")
	}
	info, err := os.Lstat(filepath.Join(got.Path, "escape"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		t.Error("symlink was materialized")
	}
}

func TestGitIgnoresHostEnvironment(t *testing.T) {
	repoDir, cloneURL, r := newFixture(t)

	// A host config with a filter and a hooks path, each of which would touch a marker,
	// matched by attributes that the repository itself supplies.
	marker := filepath.Join(t.TempDir(), "marker")
	script := filepath.Join(t.TempDir(), "run")
	writeFile(t, script, fmt.Sprintf("#!/bin/sh\ntouch %q\ncat\n", marker))
	if err := os.Chmod(script, 0o700); err != nil { //nolint:gosec // test script must be executable
		t.Fatal(err)
	}
	hooks := t.TempDir()
	writeFile(t, filepath.Join(hooks, "post-checkout"), fmt.Sprintf("#!/bin/sh\ntouch %q\n", marker))
	if err := os.Chmod(filepath.Join(hooks, "post-checkout"), 0o700); err != nil { //nolint:gosec // test script must be executable
		t.Fatal(err)
	}
	config := filepath.Join(t.TempDir(), "gitconfig")
	writeFile(t, config, fmt.Sprintf("[filter \"evil\"]\n\tsmudge = %s\n\tclean = cat\n[core]\n\thooksPath = %s\n", script, hooks))

	t.Setenv("GIT_CONFIG_GLOBAL", config)
	t.Setenv("GIT_DIR", "/nonexistent")
	t.Setenv("GIT_ALLOW_PROTOCOL", "ext:file:https")

	writeFile(t, filepath.Join(repoDir, ".gitattributes"), "*.js filter=evil\n")
	writeFile(t, filepath.Join(repoDir, "index.js"), "x\n")
	commitAll(t, repoDir, "release")
	fixtureGit(t, repoDir, "tag", "v1.0.0")

	if _, err := r.checkout(t.Context(), cloneURL, "demo", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if exists(marker) {
		t.Error("host configuration ran during checkout")
	}
}

func TestDefaultProtocolsRefuseFile(t *testing.T) {
	repoDir, cloneURL, _ := newFixture(t)
	writeFile(t, filepath.Join(repoDir, "index.js"), "x\n")
	commitAll(t, repoDir, "release")
	fixtureGit(t, repoDir, "tag", "v1.0.0")

	r, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.checkout(t.Context(), cloneURL, "demo", "1.0.0")
	if err == nil {
		t.Fatal("the file protocol was allowed")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("err = %v, want git to refuse the transport", err)
	}
}

func TestResolveRejectsBeforeRunningGit(t *testing.T) {
	r, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r.gitPath = "/nonexistent/git" // running it would be a different error
	_, err = r.Resolve(t.Context(), "ext::sh -c id", "demo", "1.0.0")
	if !errors.Is(err, ErrUnsupportedURL) {
		t.Fatalf("err = %v", err)
	}
}

func TestCheckoutSizeLimits(t *testing.T) {
	tests := []struct {
		name  string
		limit func(*Resolver)
	}{
		{"bytes", func(r *Resolver) { r.maxBytes = 1024 }},
		{"files", func(r *Resolver) { r.maxFiles = 5 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoDir, cloneURL, r := newFixture(t)
			tt.limit(r)
			for i := range 20 {
				writeFile(t, filepath.Join(repoDir, fmt.Sprintf("f%d", i)), strings.Repeat("x", 4096))
			}
			commit := commitAll(t, repoDir, "big")
			fixtureGit(t, repoDir, "tag", "v1.0.0")

			_, err := r.checkout(t.Context(), cloneURL, "demo", "1.0.0")
			if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("err = %v, want ErrTooLarge", err)
			}
			if exists(r.checkoutPath(cloneURL, commit)) {
				t.Error("oversized checkout was published")
			}
			noTempLeft(t, r)
		})
	}
}

func TestCheckoutStopsWhenCancelled(t *testing.T) {
	repoDir, cloneURL, r := newFixture(t)
	writeFile(t, filepath.Join(repoDir, "index.js"), "x\n")
	commitAll(t, repoDir, "release")
	fixtureGit(t, repoDir, "tag", "v1.0.0")

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.checkout(ctx, cloneURL, "demo", "1.0.0"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	noTempLeft(t, r)
}

// TestRealRepositories checks real forges and real tag conventions. It needs network access, so
// it runs only when asked: DRIFT_NETWORK_TESTS=1 go test ./orchestrator/internal/repo/
func TestRealRepositories(t *testing.T) {
	if os.Getenv("DRIFT_NETWORK_TESTS") == "" {
		t.Skip("set DRIFT_NETWORK_TESTS=1 to run")
	}
	tests := []struct{ declared, pkg, version, wantRef, wantFile string }{
		{"git+https://github.com/chalk/chalk.git", "chalk", "5.3.0", "v5.3.0", "package.json"},
		{"git://github.com/lodash/lodash.git", "lodash", "4.17.21", "4.17.21", "package.json"},
		{"git+https://github.com/npm/node-semver.git", "semver", "7.6.0", "v7.6.0", "package.json"},
		{"https://github.com/changesets/changesets", "@changesets/cli", "2.27.1", "@changesets/cli@2.27.1", "package.json"},
		{"github:chalk/chalk", "chalk", "99.99.99", "", ""},
	}
	r, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.pkg+"@"+tt.version, func(t *testing.T) {
			got, err := r.Resolve(t.Context(), tt.declared, tt.pkg, tt.version)
			if tt.wantRef == "" {
				if !errors.Is(err, ErrNoMatchingTag) {
					t.Fatalf("err = %v, want ErrNoMatchingTag", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s at %s in %s", got.Ref, got.Commit, got.Path)
			if got.Ref != tt.wantRef {
				t.Errorf("ref = %s, want %s", got.Ref, tt.wantRef)
			}
			if !exists(filepath.Join(got.Path, tt.wantFile)) {
				t.Errorf("%s is missing from the checkout", tt.wantFile)
			}
			if exists(filepath.Join(got.Path, ".git")) {
				t.Error(".git was left in the checkout")
			}
		})
	}
}
