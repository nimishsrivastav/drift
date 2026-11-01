// Package repo finds the source repository for a package version and checks it out at the
// matching tag, so that analyzers can compare the published tarball against it.
//
// Everything that reaches git here came from package metadata or a remote the package chose.
// Git only fetches and checks out: no hooks, no submodules, no filters, no host configuration.
package repo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	defaultTimeout  = 5 * time.Minute
	defaultMaxBytes = 2 << 30
	defaultMaxFiles = 500_000
	defaultPoll     = time.Second
	outputCapBytes  = 1 << 20
	stderrCapBytes  = 512
	killGracePeriod = 5 * time.Second
)

var (
	// ErrNoMatchingTag means the repository has no tag for this version. It is a finding for
	// later analysis, not a failure: not every release is tagged.
	ErrNoMatchingTag = errors.New("no matching tag")
	// ErrTooLarge means a checkout went over the size limits.
	ErrTooLarge = errors.New("repository exceeds size limits")

	// Stricter than git's own ref rules. It also excludes the glob characters that
	// ls-remote would otherwise expand.
	safeTag   = regexp.MustCompile(`^[A-Za-z0-9@][A-Za-z0-9@._+/-]*$`)
	objectID  = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	hardening = []string{
		"-c", "core.hooksPath=/dev/null",
		"-c", "core.symlinks=false",
		"-c", "core.fsmonitor=false",
		"-c", "credential.helper=",
		"-c", "fetch.recurseSubmodules=false",
		"-c", "submodule.recurse=false",
		"-c", "gc.auto=0",
		"-c", "maintenance.auto=false",
	}
)

// Checkout is a source tree at a resolved tag. It holds no .git directory.
type Checkout struct {
	Path   string
	Ref    string // tag name
	Commit string
	URL    string // normalized repository URL
}

// Resolver checks repositories out under <root>/<url hash>/<commit>.
type Resolver struct {
	root      string
	gitPath   string
	timeout   time.Duration
	maxBytes  int64
	maxFiles  int64
	poll      time.Duration
	protocols []string
}

// New returns a Resolver that stores checkouts under root.
func New(root string) (*Resolver, error) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("find git: %w", err)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve repo root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(abs, "tmp"), 0o750); err != nil {
		return nil, fmt.Errorf("create repo directory: %w", err)
	}
	return &Resolver{
		root:      abs,
		gitPath:   gitPath,
		timeout:   defaultTimeout,
		maxBytes:  defaultMaxBytes,
		maxFiles:  defaultMaxFiles,
		poll:      defaultPoll,
		protocols: []string{"https"},
	}, nil
}

// TagCandidates lists the tags that could mark a version, most specific first. In a monorepo a
// package-named tag identifies this package, while a bare v1.2.3 may belong to another one.
func TagCandidates(name, version string) []string {
	candidates := []string{name + "@" + version}
	if _, unscoped, scoped := strings.Cut(name, "/"); scoped {
		candidates = append(candidates, unscoped+"@"+version)
	}
	candidates = append(candidates, "v"+version, version)
	return slices.DeleteFunc(candidates, func(tag string) bool {
		return !safeTag.MatchString(tag) || strings.Contains(tag, "..") ||
			strings.HasSuffix(tag, ".lock") || strings.HasSuffix(tag, "/")
	})
}

// Resolve checks out the tag matching name and version from the declared repository URL.
// Reusing an earlier checkout of the same commit is safe, because one only appears at its
// final path once it is complete.
func (r *Resolver) Resolve(ctx context.Context, rawURL, name, version string) (Checkout, error) {
	normalized, err := NormalizeURL(rawURL)
	if err != nil {
		return Checkout{}, err
	}
	return r.checkout(ctx, normalized, name, version)
}

func (r *Resolver) checkout(ctx context.Context, cloneURL, name, version string) (Checkout, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	work, err := os.MkdirTemp(filepath.Join(r.root, "tmp"), "clone-*")
	if err != nil {
		return Checkout{}, fmt.Errorf("create work directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(work) }()
	home := filepath.Join(work, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		return Checkout{}, fmt.Errorf("create git home: %w", err)
	}

	tag, commit, err := r.findTag(ctx, home, cloneURL, name, version)
	if err != nil {
		return Checkout{}, err
	}
	result := Checkout{Ref: tag, Commit: commit, URL: cloneURL}
	result.Path = r.checkoutPath(cloneURL, commit)
	if _, err := os.Stat(result.Path); err == nil {
		return result, nil
	}

	tree := filepath.Join(work, "tree")
	actual, err := r.fetchTree(ctx, home, tree, cloneURL, tag)
	if err != nil {
		return Checkout{}, err
	}
	// The tag may have moved since ls-remote. What we checked out is what we record.
	result.Commit = actual
	result.Path = r.checkoutPath(cloneURL, actual)

	if err := os.MkdirAll(filepath.Dir(result.Path), 0o750); err != nil {
		return Checkout{}, fmt.Errorf("create checkout directory: %w", err)
	}
	if err := os.Rename(tree, result.Path); err != nil {
		if _, statErr := os.Stat(result.Path); statErr == nil {
			return result, nil // a concurrent job published the same commit
		}
		return Checkout{}, fmt.Errorf("publish checkout: %w", err)
	}
	return result, nil
}

func (r *Resolver) checkoutPath(cloneURL, commit string) string {
	sum := sha256.Sum256([]byte(cloneURL))
	return filepath.Join(r.root, hex.EncodeToString(sum[:8]), commit)
}

// findTag asks the remote which candidate tag exists and returns the commit it points at.
func (r *Resolver) findTag(ctx context.Context, home, cloneURL, name, version string) (tag, commit string, err error) {
	candidates := TagCandidates(name, version)
	if len(candidates) == 0 {
		return "", "", fmt.Errorf("%w: no usable tag name for %s@%s", ErrNoMatchingTag, name, version)
	}
	args := []string{"ls-remote", "--", cloneURL}
	for _, candidate := range candidates {
		args = append(args, "refs/tags/"+candidate, "refs/tags/"+candidate+"^{}")
	}
	output, err := r.git(ctx, home, args...)
	if err != nil {
		return "", "", fmt.Errorf("list tags: %w", err)
	}
	refs := parseRefs(output)
	for _, candidate := range candidates {
		ref := "refs/tags/" + candidate
		// An annotated tag's own object is not the commit: prefer the peeled entry.
		if oid, ok := refs[ref+"^{}"]; ok {
			return candidate, oid, nil
		}
		if oid, ok := refs[ref]; ok {
			return candidate, oid, nil
		}
	}
	return "", "", fmt.Errorf("%w: %s@%s in %s", ErrNoMatchingTag, name, version, cloneURL)
}

// parseRefs reads ls-remote output, ignoring any line that isn't "<object id>\t<ref>".
func parseRefs(output []byte) map[string]string {
	refs := map[string]string{}
	for line := range strings.Lines(string(output)) {
		oid, ref, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if ok && objectID.MatchString(oid) {
			refs[ref] = oid
		}
	}
	return refs
}

// fetchTree fetches one tag at depth 1, checks it out and removes .git, returning the commit.
// Fetching an explicit refs/tags/ ref means a same-named branch can't stand in for the tag,
// which clone --branch would allow.
func (r *Resolver) fetchTree(ctx context.Context, home, tree, cloneURL, tag string) (string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var overLimit atomic.Bool
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(r.poll)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if !r.withinLimits(tree) {
					overLimit.Store(true)
					cancel()
					return
				}
			}
		}
	}()

	steps := [][]string{
		{"init", "--quiet", "--template=", "--", tree},
		{"-C", tree, "fetch", "--quiet", "--depth=1", "--no-tags", "--no-recurse-submodules", "--", cloneURL, "refs/tags/" + tag},
		{"-C", tree, "checkout", "--quiet", "--detach", "FETCH_HEAD^{commit}"},
	}
	for _, step := range steps {
		if _, err := r.git(ctx, home, step...); err != nil {
			if overLimit.Load() {
				return "", ErrTooLarge
			}
			return "", fmt.Errorf("fetch tag %s: %w", tag, err)
		}
	}
	output, err := r.git(ctx, home, "-C", tree, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("read commit: %w", err)
	}
	commit := strings.TrimSpace(string(output))
	if !objectID.MatchString(commit) {
		return "", fmt.Errorf("git reported an invalid commit %q", commit)
	}
	// A fast checkout can finish between polls.
	if !r.withinLimits(tree) {
		return "", ErrTooLarge
	}
	// Analyzers need only the tree, so don't leave them a .git to trip over.
	if err := os.RemoveAll(filepath.Join(tree, ".git")); err != nil {
		return "", fmt.Errorf("remove .git: %w", err)
	}
	return commit, nil
}

func (r *Resolver) withinLimits(dir string) bool {
	var size, files int64
	err := filepath.WalkDir(dir, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil {
			// Git renames its temp files while we walk. A missing entry is not a problem.
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		files++
		if info, infoErr := entry.Info(); infoErr == nil {
			size += info.Size()
		}
		if size > r.maxBytes || files > r.maxFiles {
			return fs.SkipAll
		}
		return nil
	})
	return err == nil && size <= r.maxBytes && files <= r.maxFiles
}

// git runs one git command in an environment built from nothing, so neither the host's
// configuration nor inherited GIT_* variables can change what it does. Only the listed
// protocols work, which also applies to anything git would reach through a redirect.
func (r *Resolver) git(ctx context.Context, home string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, r.gitPath, slices.Concat(hardening, args)...) //nolint:gosec // arguments are validated and git gets no shell
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + home,
		"LC_ALL=C",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_LFS_SKIP_SMUDGE=1",
		"GIT_ALLOW_PROTOCOL=" + strings.Join(r.protocols, ":"),
	}
	// Git runs helpers such as git-remote-https and index-pack. Killing the whole group stops
	// them too, so that a cancelled fetch stops writing to disk.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = killGracePeriod

	stdout := &capWriter{limit: outputCapBytes}
	stderr := &capWriter{limit: stderrCapBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		// Quoted, because a remote can put anything it likes in here.
		return nil, fmt.Errorf("git %s: %w: %q", args[0], err, stderr.buf.String())
	}
	if stdout.truncated {
		return nil, fmt.Errorf("git %s: output over %d bytes", args[0], outputCapBytes)
	}
	return stdout.buf.Bytes(), nil
}

// capWriter keeps the first limit bytes and quietly drops the rest.
type capWriter struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	if room := w.limit - w.buf.Len(); room < len(p) {
		w.truncated = true
		if room > 0 {
			w.buf.Write(p[:room])
		}
		return len(p), nil
	}
	w.buf.Write(p)
	return len(p), nil
}
