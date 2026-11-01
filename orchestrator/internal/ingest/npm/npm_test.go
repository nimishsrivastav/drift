package npm

import (
	"context"
	"crypto/sha1" //nolint:gosec // the code under test checks legacy shasums
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimishsrivastav/drift/orchestrator/internal/ingest"
	"github.com/nimishsrivastav/drift/orchestrator/internal/store"
)

func TestResolve(t *testing.T) {
	doc := &packument{
		Name:     "demo",
		DistTags: map[string]string{"latest": "2.0.0", "next": "3.0.0-rc.1"},
		Versions: map[string]versionDoc{
			"0.9.0":      {Repository: json.RawMessage(`"github:acme/demo"`)},
			"1.0.0":      {Repository: json.RawMessage(`{"type":"git","url":"https://github.com/acme/one.git"}`)},
			"1.1.0":      {},
			"2.0.0-rc.1": {},
			"2.0.0":      {},
			"1.2.0":      {}, // backport, published after 2.0.0
			"3.0.0-rc.1": {},
			"not-semver": {},
		},
		Time: map[string]json.RawMessage{
			"created":    json.RawMessage(`"2019-01-01T00:00:00.000Z"`),
			"unpublish":  json.RawMessage(`{"weird":"shape"}`),
			"0.9.0":      json.RawMessage(`"2020-01-01T00:00:00.000Z"`),
			"1.0.0":      json.RawMessage(`"2020-02-01T00:00:00.000Z"`),
			"1.1.0":      json.RawMessage(`"2020-03-01T00:00:00.000Z"`),
			"2.0.0-rc.1": json.RawMessage(`"2020-04-01T00:00:00.000Z"`),
			"2.0.0":      json.RawMessage(`"2020-05-01T00:00:00.000Z"`),
			"1.2.0":      json.RawMessage(`"2020-06-01T00:00:00.000Z"`),
			"3.0.0-rc.1": json.RawMessage(`"2020-07-01T00:00:00.000Z"`),
		},
		Repository: json.RawMessage(`{"url":"https://github.com/acme/top.git"}`),
	}

	tests := []struct {
		name     string
		from, to string
		wantOld  string
		wantNew  string
		wantRepo string
		wantErr  error
	}{
		{name: "defaults to latest and its predecessor", wantOld: "1.1.0", wantNew: "2.0.0", wantRepo: "https://github.com/acme/top.git"},
		{name: "explicit pair", from: "0.9.0", to: "1.0.0", wantOld: "0.9.0", wantNew: "1.0.0", wantRepo: "https://github.com/acme/one.git"},
		{name: "same version rerun", from: "1.0.0", to: "1.0.0", wantOld: "1.0.0", wantNew: "1.0.0", wantRepo: "https://github.com/acme/one.git"},
		{name: "dist-tag target", to: "next", wantOld: "2.0.0", wantNew: "3.0.0-rc.1", wantRepo: "https://github.com/acme/top.git"},
		{name: "backport compares with its own line", to: "1.2.0", wantOld: "1.1.0", wantNew: "1.2.0", wantRepo: "https://github.com/acme/top.git"},
		{name: "first release is new-package mode", to: "0.9.0", wantNew: "0.9.0", wantRepo: "github:acme/demo"},
		{name: "non-semver target has no predecessor", to: "not-semver", wantNew: "not-semver", wantRepo: "https://github.com/acme/top.git"},
		{name: "removed target version", from: "1.0.0", to: "1.0.1", wantErr: ingest.ErrVersionNotFound},
		{name: "removed from version", from: "0.0.1", to: "1.0.0", wantErr: ingest.ErrVersionNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := doc.resolve("demo", tt.from, tt.to)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.New.Version != tt.wantNew {
				t.Errorf("new = %s, want %s", got.New.Version, tt.wantNew)
			}
			if got.New.RepositoryURL != tt.wantRepo {
				t.Errorf("repository = %q, want %q", got.New.RepositoryURL, tt.wantRepo)
			}
			switch {
			case tt.wantOld == "" && got.Old != nil:
				t.Errorf("old = %s, want unset", got.Old.Version)
			case tt.wantOld != "" && (got.Old == nil || got.Old.Version != tt.wantOld):
				t.Errorf("old = %+v, want %s", got.Old, tt.wantOld)
			}
		})
	}
}

func TestResolveNoVersions(t *testing.T) {
	doc := &packument{Name: "gone"}
	if _, err := doc.resolve("gone", "", ""); !errors.Is(err, ingest.ErrVersionNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestRepositoryURL(t *testing.T) {
	tests := []struct{ name, raw, want string }{
		{"string", `"https://github.com/a/b"`, "https://github.com/a/b"},
		{"object", `{"type":"git","url":"git+https://github.com/a/b.git"}`, "git+https://github.com/a/b.git"},
		{"list of objects", `[{"url":"https://github.com/a/b"},{"url":"x"}]`, "https://github.com/a/b"},
		{"empty list", `[]`, ""},
		{"number", `3`, ""},
		{"object without url", `{"type":"git"}`, ""},
		{"absent", ``, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := repositoryURL(json.RawMessage(tt.raw)); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func sri(algorithm string, sum []byte) string {
	return algorithm + "-" + base64.StdEncoding.EncodeToString(sum)
}

func TestVerifier(t *testing.T) {
	content := []byte("tarball")
	s1 := sha1.Sum(content) //nolint:gosec // the code under test checks legacy shasums
	s256 := sha256.Sum256(content)
	s512 := sha512.Sum512(content)
	got := store.Digests{SHA1: s1[:], SHA256: s256[:], SHA512: s512[:]}
	bad := make([]byte, 64)
	badSHA1 := make([]byte, 20)
	goodShasum := hex.EncodeToString(s1[:])

	tests := []struct {
		name          string
		integrity     string
		shasum        string
		wantBuildErr  bool
		wantIntegrity bool
	}{
		{name: "sha512 matches", integrity: sri("sha512", s512[:])},
		{name: "sha512 mismatch", integrity: sri("sha512", bad), wantIntegrity: true},
		{name: "shasum only", shasum: goodShasum},
		{name: "shasum mismatch", shasum: hex.EncodeToString(badSHA1), wantIntegrity: true},
		{name: "good sha512 cannot excuse a bad shasum", integrity: sri("sha512", s512[:]), shasum: hex.EncodeToString(badSHA1), wantIntegrity: true},
		{name: "strongest algorithm decides", integrity: sri("sha1", s1[:]) + " " + sri("sha512", bad), wantIntegrity: true},
		{name: "any value of the strongest algorithm", integrity: sri("sha512", bad) + " " + sri("sha512", s512[:])},
		{name: "SRI options are ignored", integrity: sri("sha512", s512[:]) + "?foo"},
		{name: "unknown algorithm plus shasum", integrity: "md5-AAAA", shasum: goodShasum},
		{name: "nothing usable", integrity: "md5-AAAA", wantBuildErr: true},
		{name: "nothing at all", wantBuildErr: true},
		{name: "invalid base64", integrity: "sha512-!!!", wantBuildErr: true},
		{name: "invalid shasum", shasum: "zz", wantBuildErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verify, err := newVerifier(tt.integrity, tt.shasum)
			if tt.wantBuildErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			err = verify(got)
			if tt.wantIntegrity != errors.Is(err, ingest.ErrIntegrity) {
				t.Errorf("err = %v, want integrity failure: %v", err, tt.wantIntegrity)
			}
			if !tt.wantIntegrity && err != nil {
				t.Errorf("unexpected err: %v", err)
			}
		})
	}
}

// fakeRegistry serves one package, version 1.0.0.
func fakeRegistry(t *testing.T, name string, tarball []byte, integrity string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.EscapedPath() == "/"+strings.ReplaceAll(name, "/", "%2F"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":      name,
				"dist-tags": map[string]string{"latest": "1.0.0"},
				"versions": map[string]any{"1.0.0": map[string]any{
					"dist": map[string]string{"tarball": srv.URL + "/t.tgz", "integrity": integrity},
				}},
			})
		case r.URL.Path == "/t.tgz":
			if r.Header.Get("Accept-Encoding") != "identity" {
				t.Errorf("tarball requested with Accept-Encoding %q", r.Header.Get("Accept-Encoding"))
			}
			_, _ = w.Write(tarball)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestResolveAndDownload(t *testing.T) {
	tarball := []byte("published bytes")
	sum := sha512.Sum512(tarball)
	wrong := make([]byte, 64)

	for _, name := range []string{"plain", "@scope/pkg"} {
		t.Run(name, func(t *testing.T) {
			srv := fakeRegistry(t, name, tarball, sri("sha512", sum[:]))
			c, err := New(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			res, err := c.Resolve(t.Context(), name, "", "")
			if err != nil {
				t.Fatal(err)
			}
			if res.Old != nil || res.New.Version != "1.0.0" {
				t.Fatalf("resolution = %+v", res)
			}
			blob, err := c.Download(t.Context(), res.New, newStore(t))
			if err != nil {
				t.Fatal(err)
			}
			wantHash := sha256.Sum256(tarball)
			if blob.SHA256 != hex.EncodeToString(wantHash[:]) {
				t.Errorf("sha256 = %s", blob.SHA256)
			}
		})
	}

	t.Run("tampered tarball is rejected", func(t *testing.T) {
		srv := fakeRegistry(t, "plain", tarball, sri("sha512", wrong))
		c, err := New(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		res, err := c.Resolve(t.Context(), "plain", "", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Download(t.Context(), res.New, newStore(t)); !errors.Is(err, ingest.ErrIntegrity) {
			t.Fatalf("err = %v, want integrity failure", err)
		}
	})

	t.Run("oversized tarball is rejected", func(t *testing.T) {
		srv := fakeRegistry(t, "plain", tarball, sri("sha512", sum[:]))
		c, err := New(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		c.maxTarballBytes = 4
		res, err := c.Resolve(t.Context(), "plain", "", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Download(t.Context(), res.New, newStore(t)); !errors.Is(err, store.ErrTooLarge) {
			t.Fatalf("err = %v, want size failure", err)
		}
	})
}

func TestResolveErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/wrong-name":
			_, _ = fmt.Fprint(w, `{"name":"other"}`)
		case "/garbage":
			_, _ = fmt.Fprint(w, `not json`)
		case "/huge":
			_, _ = fmt.Fprintf(w, `{"name":"huge","padding":"%s"}`, strings.Repeat("x", 4096))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.maxPackumentBytes = 1024

	tests := []struct {
		name    string
		pkg     string
		wantErr error
	}{
		{name: "unknown package", pkg: "missing", wantErr: ingest.ErrPackageNotFound},
		{name: "wrong package returned", pkg: "wrong-name"},
		{name: "invalid JSON", pkg: "garbage"},
		{name: "oversized packument", pkg: "huge"},
		{name: "path traversal in name", pkg: "../admin"},
		{name: "option-like name", pkg: "a b"},
		{name: "empty name", pkg: ""},
		{name: "scope without package", pkg: "@scope/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.Resolve(t.Context(), tt.pkg, "", "")
			if err == nil {
				t.Fatal("expected an error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckTarballURL(t *testing.T) {
	c, err := New(DefaultRegistry)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, raw, want string
		wantErr         bool
	}{
		{name: "on registry", raw: "https://registry.npmjs.org/a/-/a-1.0.0.tgz", want: "https://registry.npmjs.org/a/-/a-1.0.0.tgz"},
		{name: "old http is upgraded", raw: "http://registry.npmjs.org/a/-/a-1.0.0.tgz", want: "https://registry.npmjs.org/a/-/a-1.0.0.tgz"},
		{name: "other host", raw: "https://evil.example/a.tgz", wantErr: true},
		{name: "lookalike host", raw: "https://registry.npmjs.org.evil.example/a.tgz", wantErr: true},
		{name: "file URL", raw: "file:///etc/passwd", wantErr: true},
		{name: "metadata service", raw: "http://169.254.169.254/latest", wantErr: true},
		{name: "empty", raw: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.checkTarballURL(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("got %q, expected an error", got)
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

func TestRetries(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		wantCalls int32
	}{
		{name: "server errors are retried", status: http.StatusBadGateway, wantCalls: maxAttempts},
		{name: "rate limits are retried", status: http.StatusTooManyRequests, wantCalls: maxAttempts},
		{name: "client errors are not", status: http.StatusForbidden, wantCalls: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()
			c, err := New(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			c.retryDelay = time.Millisecond
			if _, err := c.Resolve(t.Context(), "demo", "", ""); err == nil {
				t.Fatal("expected an error")
			}
			if got := calls.Load(); got != tt.wantCalls {
				t.Errorf("calls = %d, want %d", got, tt.wantCalls)
			}
		})
	}
}

func TestRetryStopsWhenCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	c, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.retryDelay = time.Hour
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Resolve(ctx, "demo", "", ""); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestNewRejectsBadRegistry(t *testing.T) {
	for _, raw := range []string{"", "registry.npmjs.org", "ftp://registry.npmjs.org", "file:///tmp"} {
		if _, err := New(raw); err == nil {
			t.Errorf("New(%q) succeeded", raw)
		}
	}
}
