// Package npm is the npm registry adapter: packument fetch, version resolution, tarball
// download and integrity checks.
package npm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	driftv1 "github.com/nimishsrivastav/drift/gen/go/drift/v1"
	"github.com/nimishsrivastav/drift/orchestrator/internal/ingest"
	"github.com/nimishsrivastav/drift/orchestrator/internal/store"
)

const (
	// DefaultRegistry is the public npm registry. Access is anonymous (CLAUDE.md rule 7).
	DefaultRegistry = "https://registry.npmjs.org"

	userAgent = "drift/0.1 (+https://github.com/nimishsrivastav/drift)"

	// Limits on what a registry response may make us read. A full packument is large for
	// packages with thousands of releases, but it fits comfortably in these.
	defaultMaxPackumentBytes = 256 << 20
	defaultMaxTarballBytes   = 512 << 20

	requestTimeout = 5 * time.Minute
	maxAttempts    = 3
	maxRedirects   = 3
	errorBodyBytes = 512
)

// npm allows uppercase only in legacy names, but those still resolve (JSONStream).
var packageName = regexp.MustCompile(`^(@[A-Za-z0-9~-][A-Za-z0-9._~-]*/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$`)

// Client is an ingest.Adapter for an npm-compatible registry.
type Client struct {
	http              *http.Client
	registry          *url.URL
	maxPackumentBytes int64
	maxTarballBytes   int64
	retryDelay        time.Duration
}

var _ ingest.Adapter = (*Client)(nil)

// New returns a client for the registry at registryURL.
func New(registryURL string) (*Client, error) {
	registry, err := url.Parse(strings.TrimRight(registryURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("parse registry URL: %w", err)
	}
	if (registry.Scheme != "https" && registry.Scheme != "http") || registry.Host == "" {
		return nil, fmt.Errorf("registry URL %q must be http or https with a host", registryURL)
	}
	c := &Client{
		registry:          registry,
		maxPackumentBytes: defaultMaxPackumentBytes,
		maxTarballBytes:   defaultMaxTarballBytes,
		retryDelay:        time.Second,
	}
	c.http = &http.Client{Timeout: requestTimeout, CheckRedirect: c.checkRedirect}
	return c, nil
}

// Ecosystem implements ingest.Adapter.
func (c *Client) Ecosystem() driftv1.Ecosystem { return driftv1.Ecosystem_ECOSYSTEM_NPM }

// Resolve implements ingest.Adapter.
func (c *Client) Resolve(ctx context.Context, name, from, to string) (ingest.Resolution, error) {
	if !packageName.MatchString(name) {
		return ingest.Resolution{}, fmt.Errorf("invalid npm package name %q", name)
	}
	doc, err := c.fetchPackument(ctx, name)
	if err != nil {
		return ingest.Resolution{}, err
	}
	return doc.resolve(name, from, to)
}

// Download implements ingest.Adapter.
func (c *Client) Download(ctx context.Context, v ingest.Version, s *store.Store) (store.Blob, error) {
	tarball, err := c.checkTarballURL(v.TarballURL)
	if err != nil {
		return store.Blob{}, fmt.Errorf("%s@%s: %w", v.Name, v.Version, err)
	}
	verify, err := newVerifier(v.Integrity, v.Shasum)
	if err != nil {
		return store.Blob{}, fmt.Errorf("%s@%s: %w", v.Name, v.Version, err)
	}

	// Identity stops the transport from transparently gunzipping, so the hash covers the
	// published bytes.
	resp, err := c.get(ctx, tarball, "application/octet-stream", "identity")
	if err != nil {
		return store.Blob{}, fmt.Errorf("download %s@%s: %w", v.Name, v.Version, err)
	}
	defer func() { _ = resp.Body.Close() }()

	blob, err := s.Put(resp.Body, c.maxTarballBytes, verify)
	if err != nil {
		return store.Blob{}, fmt.Errorf("store %s@%s: %w", v.Name, v.Version, err)
	}
	return blob, nil
}

func (c *Client) fetchPackument(ctx context.Context, name string) (*packument, error) {
	// A scoped name's slash must stay encoded: @scope%2Fname.
	endpoint := *c.registry
	endpoint.Path = c.registry.Path + "/" + name
	endpoint.RawPath = c.registry.EscapedPath() + "/" + url.PathEscape(name)

	// The abbreviated install-v1 form lacks the publish times and repository fields we need.
	resp, err := c.get(ctx, endpoint.String(), "application/json", "")
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil, fmt.Errorf("%w: %s", ingest.ErrPackageNotFound, name)
		}
		return nil, fmt.Errorf("fetch packument for %s: %w", name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	limited := io.LimitReader(resp.Body, c.maxPackumentBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read packument for %s: %w", name, err)
	}
	if int64(len(data)) > c.maxPackumentBytes {
		return nil, fmt.Errorf("packument for %s exceeds %d bytes", name, c.maxPackumentBytes)
	}
	var doc packument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse packument for %s: %w", name, err)
	}
	if doc.Name != name {
		return nil, fmt.Errorf("registry answered for %q when asked for %q", doc.Name, name)
	}
	return &doc, nil
}

// checkTarballURL keeps downloads on the configured registry. A packument's tarball field is
// data from the registry, and following it blindly would let it point us at any host.
func (c *Client) checkTarballURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse tarball URL: %w", err)
	}
	// Old packuments still say http:// for what the registry now serves over TLS.
	if u.Scheme == "http" && c.registry.Scheme == "https" {
		u.Scheme = "https"
	}
	if u.Scheme != c.registry.Scheme || u.Host != c.registry.Host {
		return "", fmt.Errorf("tarball URL %q is not on registry %s", raw, c.registry.Host)
	}
	return u.String(), nil
}

// checkRedirect refuses a downgrade from TLS and caps the chain.
func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if req.URL.Scheme != "https" && c.registry.Scheme == "https" {
		return fmt.Errorf("refusing redirect to non-https URL %q", req.URL)
	}
	return nil
}

var errNotFound = errors.New("not found")

// get performs a GET, retrying rate limits, server errors and transport failures.
// The caller closes the response body.
func (c *Client) get(ctx context.Context, target, accept, encoding string) (*http.Response, error) {
	var lastErr error
	for attempt := range maxAttempts {
		if attempt > 0 {
			slog.DebugContext(ctx, "retrying registry request", "url", target, "err", lastErr)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(c.retryDelay << (attempt - 1)):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", accept)
		if encoding != "" {
			req.Header.Set("Accept-Encoding", encoding)
		}

		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		switch resp.StatusCode {
		case http.StatusOK:
			return resp, nil
		case http.StatusNotFound:
			_ = resp.Body.Close()
			return nil, errNotFound
		default:
			snippet, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyBytes))
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("unexpected status %d: %q", resp.StatusCode, snippet)
			if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
				return nil, lastErr
			}
		}
	}
	return nil, lastErr
}
