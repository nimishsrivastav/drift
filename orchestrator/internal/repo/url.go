package repo

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ErrUnsupportedURL means a repository URL is not one drift is willing to fetch.
var ErrUnsupportedURL = errors.New("unsupported repository URL")

// allowedHosts are the only forges drift fetches from. The URL is attacker-controlled package
// metadata, so an open list would let a package aim git at internal hosts.
var allowedHosts = map[string]bool{
	"github.com":    true,
	"gitlab.com":    true,
	"bitbucket.org": true,
}

var shorthandHosts = map[string]string{
	"github":    "github.com",
	"gitlab":    "gitlab.com",
	"bitbucket": "bitbucket.org",
}

var (
	pathSegment = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)
	scpForm     = regexp.MustCompile(`^(?:[A-Za-z0-9_-]+@)?([A-Za-z0-9.-]+):([^/].*)$`)
)

// NormalizeURL turns a declared repository value into https://<forge>/<path>.git. It accepts
// the forms npm packages use: full URLs with git+, git:// or ssh schemes, scp-like
// git@host:path, and the github:owner/repo and owner/repo shorthands. Whatever the input said,
// the result is always https to an allowed host, with no credentials, port, query or fragment.
func NormalizeURL(raw string) (string, error) {
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "git+")
	if raw == "" {
		return "", fmt.Errorf("%w: empty", ErrUnsupportedURL)
	}
	host, path, err := splitURL(raw)
	if err != nil {
		return "", err
	}
	host = strings.ToLower(host)
	if !allowedHosts[host] {
		return "", fmt.Errorf("%w: host %q is not an allowed forge", ErrUnsupportedURL, host)
	}

	segments := strings.Split(strings.Trim(path, "/"), "/")
	// GitHub and Bitbucket repos are exactly owner/repo, and links often continue with
	// /tree/main/packages/x. GitLab has subgroups, but cuts its own subpaths at "/-/".
	if host == "gitlab.com" {
		for i, segment := range segments {
			if segment == "-" {
				segments = segments[:i]
				break
			}
		}
	} else if len(segments) > 2 {
		segments = segments[:2]
	}
	if len(segments) < 2 {
		return "", fmt.Errorf("%w: %q has no owner and repository", ErrUnsupportedURL, raw)
	}
	segments[len(segments)-1] = strings.TrimSuffix(segments[len(segments)-1], ".git")
	for _, segment := range segments {
		if !pathSegment.MatchString(segment) {
			return "", fmt.Errorf("%w: bad path segment in %q", ErrUnsupportedURL, raw)
		}
	}
	return "https://" + host + "/" + strings.Join(segments, "/") + ".git", nil
}

func splitURL(raw string) (host, path string, err error) {
	if scheme, rest, ok := strings.Cut(raw, "://"); ok {
		// ssh://git@host:owner/repo is common in old packages, though it isn't a valid URL.
		if scheme == "ssh" {
			if m := scpForm.FindStringSubmatch(rest); m != nil {
				return m[1], m[2], nil
			}
		}
		u, parseErr := url.Parse(raw)
		if parseErr != nil {
			return "", "", fmt.Errorf("%w: %w", ErrUnsupportedURL, parseErr)
		}
		switch u.Scheme {
		case "https", "http", "git", "ssh":
		default:
			return "", "", fmt.Errorf("%w: scheme %q", ErrUnsupportedURL, u.Scheme)
		}
		return u.Hostname(), u.Path, nil
	}

	// A transport helper such as ext::sh -c ... has no "://", and looks a lot like
	// scp-style host:path. Git would run that command, so it must never get this far.
	if strings.Contains(raw, "::") {
		return "", "", fmt.Errorf("%w: transport helper syntax", ErrUnsupportedURL)
	}
	raw, _, _ = strings.Cut(raw, "#") // github:owner/repo#branch
	if prefix, rest, ok := strings.Cut(raw, ":"); ok {
		if forge, isShorthand := shorthandHosts[prefix]; isShorthand {
			return forge, rest, nil
		}
	}
	if m := scpForm.FindStringSubmatch(raw); m != nil {
		return m[1], m[2], nil
	}
	if !strings.Contains(raw, ":") && strings.Count(raw, "/") == 1 {
		return "github.com", raw, nil // owner/repo means GitHub to npm
	}
	return "", "", fmt.Errorf("%w: unrecognized form %q", ErrUnsupportedURL, raw)
}
