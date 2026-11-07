package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	driftv1 "github.com/nimishsrivastav/drift/gen/go/drift/v1"
	"github.com/nimishsrivastav/drift/orchestrator/internal/db"
	"github.com/nimishsrivastav/drift/orchestrator/internal/repo"
)

type output struct {
	JobID   string `json:"job_id"`
	Status  string `json:"status"`
	Error   string `json:"error"`
	Package string `json:"package"`
	Pair    struct {
		JobID string `json:"job_id"`
		Old   *struct {
			Version string `json:"version"`
		} `json:"old"`
		New struct {
			Version       string `json:"version"`
			TarballPath   string `json:"tarball_path"`
			TarballSha256 string `json:"tarball_sha256"`
			RepoRef       string `json:"repo_ref"`
		} `json:"new"`
	} `json:"pair"`
}

// fakeRegistry serves demo@1.0.0 and demo@1.0.1. The second version's hash is wrong when
// tamper is set.
func fakeRegistry(t *testing.T, tamper bool) *httptest.Server {
	t.Helper()
	versionDoc := func(serverURL, version string, wrongHash bool) map[string]any {
		sum := sha512.Sum512([]byte("tarball " + version))
		if wrongHash {
			sum = [64]byte{}
		}
		return map[string]any{"dist": map[string]string{
			"tarball":   serverURL + "/demo/-/demo-" + version + ".tgz",
			"integrity": "sha512-" + base64.StdEncoding.EncodeToString(sum[:]),
		}}
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/demo":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":      "demo",
				"dist-tags": map[string]string{"latest": "1.0.1"},
				"versions": map[string]any{
					"1.0.0": versionDoc(srv.URL, "1.0.0", false),
					"1.0.1": versionDoc(srv.URL, "1.0.1", tamper),
				},
				"time": map[string]string{"1.0.0": "2020-01-01T00:00:00Z", "1.0.1": "2020-02-01T00:00:00Z"},
			})
		case strings.HasSuffix(r.URL.Path, ".tgz"):
			version := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/demo/-/demo-"), ".tgz")
			_, _ = fmt.Fprint(w, "tarball "+version) //nolint:gosec // test server, plain text to a test client
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAnalyze(t *testing.T) {
	srv := fakeRegistry(t, false)
	tests := []struct {
		name    string
		args    func(data string) []string
		wantOld string
		wantNew string
	}{
		{
			name: "flags after the positional arguments, as PLAN.md writes it",
			args: func(data string) []string {
				return []string{"npm", "demo", "--from", "1.0.0", "--to", "1.0.1", "--registry", srv.URL, "--data-dir", data}
			},
			wantOld: "1.0.0", wantNew: "1.0.1",
		},
		{
			name: "flags before the positional arguments",
			args: func(data string) []string {
				return []string{"--registry", srv.URL, "--data-dir", data, "--to", "1.0.1", "npm", "demo"}
			},
			wantOld: "1.0.0", wantNew: "1.0.1",
		},
		{
			name: "defaults to latest and its predecessor",
			args: func(data string) []string {
				return []string{"npm", "demo", "--registry", srv.URL, "--data-dir", data}
			},
			wantOld: "1.0.0", wantNew: "1.0.1",
		},
		{
			name: "first release runs in new-package mode",
			args: func(data string) []string {
				return []string{"npm", "demo", "--to", "1.0.0", "--registry", srv.URL, "--data-dir", data}
			},
			wantNew: "1.0.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := t.TempDir()
			var stdout, stderr bytes.Buffer
			if code := analyze(t.Context(), tt.args(data), &stdout, &stderr); code != exitOK {
				t.Fatalf("code = %d, stderr = %s", code, stderr.String())
			}
			var got output
			if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
				t.Fatalf("stdout is not JSON: %v\n%s", err, stdout.String())
			}
			if got.Status != "ingested" || got.Package != "demo" || got.Pair.JobID != got.JobID {
				t.Errorf("output = %+v", got)
			}
			if got.Pair.New.Version != tt.wantNew {
				t.Errorf("new = %s, want %s", got.Pair.New.Version, tt.wantNew)
			}
			switch {
			case tt.wantOld == "" && got.Pair.Old != nil:
				t.Errorf("old = %s, want unset", got.Pair.Old.Version)
			case tt.wantOld != "" && (got.Pair.Old == nil || got.Pair.Old.Version != tt.wantOld):
				t.Errorf("old = %+v, want %s", got.Pair.Old, tt.wantOld)
			}
			if got.Pair.New.RepoRef != repo.Unresolved {
				t.Errorf("repo_ref = %q", got.Pair.New.RepoRef)
			}

			// The tarball is stored whole and read-only, under the data directory.
			content, err := os.ReadFile(got.Pair.New.TarballPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(content) != "tarball "+tt.wantNew {
				t.Errorf("tarball = %q", content)
			}
			if !strings.HasPrefix(got.Pair.New.TarballPath, data) || !strings.HasSuffix(got.Pair.New.TarballPath, got.Pair.New.TarballSha256[2:]) {
				t.Errorf("tarball path = %s", got.Pair.New.TarballPath)
			}

			// The job can be read back from the database by a separate command.
			var shown bytes.Buffer
			if code := showJob(t.Context(), []string{got.JobID, "--data-dir", data}, &shown, &stderr); code != exitOK {
				t.Fatalf("job: code = %d, stderr = %s", code, stderr.String())
			}
			if shown.String() != stdout.String() {
				t.Errorf("job output differs:\n%s\nvs\n%s", shown.String(), stdout.String())
			}
		})
	}
}

func TestAnalyzeFailuresAreRecorded(t *testing.T) {
	tests := []struct {
		name       string
		tamper     bool
		args       []string
		wantStderr string
	}{
		{name: "tampered tarball", tamper: true, args: []string{"npm", "demo"}, wantStderr: "integrity check failed"},
		{name: "removed version", args: []string{"npm", "demo", "--to", "9.9.9"}, wantStderr: "version not found"},
		{name: "unknown package", args: []string{"npm", "missing"}, wantStderr: "package not found"},
		{name: "invalid package name", args: []string{"npm", "../evil"}, wantStderr: "invalid npm package name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := fakeRegistry(t, tt.tamper)
			data := t.TempDir()
			args := slices.Concat(tt.args, []string{"--registry", srv.URL, "--data-dir", data})
			var stdout, stderr bytes.Buffer
			if code := analyze(t.Context(), args, &stdout, &stderr); code != exitFailed {
				t.Fatalf("code = %d, stderr = %s", code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %s", stdout.String())
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %s", stderr.String())
			}

			// The message names the job, and the job holds the reason.
			fields := strings.Fields(stderr.String())
			if len(fields) < 3 || fields[1] != "job" {
				t.Fatalf("stderr does not name the job: %s", stderr.String())
			}
			var shown bytes.Buffer
			if code := showJob(t.Context(), []string{fields[2], "--data-dir", data}, &shown, io.Discard); code != exitOK {
				t.Fatalf("job: code = %d", code)
			}
			var got output
			if err := json.Unmarshal(shown.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.Status != "failed" || !strings.Contains(got.Error, tt.wantStderr) {
				t.Errorf("output = %+v", got)
			}
		})
	}
}

func TestUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "no arguments", args: nil},
		{name: "ecosystem only", args: []string{"npm"}},
		{name: "extra argument", args: []string{"npm", "demo", "extra"}},
		{name: "unsupported ecosystem", args: []string{"pypi", "demo"}},
		{name: "unknown flag", args: []string{"npm", "demo", "--nope"}},
		{name: "flag without value", args: []string{"npm", "demo", "--to"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A data directory proves that usage errors stop before touching anything.
			data := filepath.Join(t.TempDir(), "unused")
			t.Setenv("DRIFT_DATA_DIR", data)
			var stdout, stderr bytes.Buffer
			if code := analyze(t.Context(), tt.args, &stdout, &stderr); code != exitUsage {
				t.Errorf("code = %d, stderr = %s", code, stderr.String())
			}
			if _, err := os.Stat(data); !errors.Is(err, os.ErrNotExist) {
				t.Error("a usage error created the data directory")
			}
		})
	}
}

func TestResolvePaths(t *testing.T) {
	tests := []struct {
		name         string
		flag         string
		env          map[string]string
		wantTarballs string
		wantDatabase string
	}{
		{
			name:         "flag wins",
			flag:         "/flag",
			env:          map[string]string{"DRIFT_DATA_DIR": "/env", "XDG_DATA_HOME": "/xdg", "HOME": "/home/u"},
			wantTarballs: "/flag/tarballs", wantDatabase: "/flag/drift.db",
		},
		{
			name:         "environment",
			env:          map[string]string{"DRIFT_DATA_DIR": "/env", "XDG_DATA_HOME": "/xdg", "HOME": "/home/u"},
			wantTarballs: "/env/tarballs", wantDatabase: "/env/drift.db",
		},
		{
			name:         "XDG",
			env:          map[string]string{"XDG_DATA_HOME": "/xdg", "HOME": "/home/u"},
			wantTarballs: "/xdg/drift/tarballs", wantDatabase: "/xdg/drift/drift.db",
		},
		{
			name:         "home",
			env:          map[string]string{"HOME": "/home/u"},
			wantTarballs: "/home/u/.local/share/drift/tarballs", wantDatabase: "/home/u/.local/share/drift/drift.db",
		},
		{
			name:         "database kept apart from artifacts",
			env:          map[string]string{"DRIFT_DATA_DIR": "/artifacts", "DRIFT_DB": "/var/lib/drift/drift.db"},
			wantTarballs: "/artifacts/tarballs", wantDatabase: "/var/lib/drift/drift.db",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, name := range []string{"DRIFT_DATA_DIR", "DRIFT_DB", "XDG_DATA_HOME", "HOME"} {
				t.Setenv(name, tt.env[name])
			}
			got, err := resolvePaths(tt.flag)
			if err != nil {
				t.Fatal(err)
			}
			if got.tarballs != tt.wantTarballs || got.database != tt.wantDatabase {
				t.Errorf("paths = %+v", got)
			}
		})
	}
}

func TestParseInterleaved(t *testing.T) {
	flags := flag.NewFlagSet("t", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	value := flags.String("x", "", "")
	got, err := parseInterleaved(flags, []string{"a", "--x", "1", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"a", "b"}) || *value != "1" {
		t.Errorf("positional = %v, x = %q", got, *value)
	}
}

func TestPrintErrorRemovesControlCharacters(t *testing.T) {
	var buf bytes.Buffer
	printError(&buf, errors.New("bad \x1b[2Jversion\r\nspoofed line"))
	if strings.ContainsAny(strings.TrimSuffix(buf.String(), "\n"), "\x1b\r\n") {
		t.Errorf("output = %q", buf.String())
	}
}

func TestPrintJobEscapesControlCharacters(t *testing.T) {
	const hostile = "\x1b[2Jspoofed"
	job := &db.Job{
		ID:      "id",
		Package: hostile,
		Error:   hostile,
		Pair: &driftv1.ArtifactPair{
			JobId: "id",
			New:   &driftv1.PackageVersion{Name: hostile, Version: hostile},
		},
	}
	var stdout bytes.Buffer
	if err := printJob(&stdout, job); err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsRune(stdout.Bytes(), 0x1b) {
		t.Errorf("raw escape character in the output: %q", stdout.String())
	}
	var got output
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Package != hostile || got.Pair.New.Version != hostile {
		t.Errorf("escaped values did not round-trip: %+v", got)
	}
}
