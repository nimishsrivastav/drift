package jobs

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	driftv1 "github.com/nimishsrivastav/drift/gen/go/drift/v1"
	"github.com/nimishsrivastav/drift/orchestrator/internal/db"
	"github.com/nimishsrivastav/drift/orchestrator/internal/ingest"
	"github.com/nimishsrivastav/drift/orchestrator/internal/repo"
	"github.com/nimishsrivastav/drift/orchestrator/internal/store"
)

const npm = driftv1.Ecosystem_ECOSYSTEM_NPM

type fakeAdapter struct {
	resolution  ingest.Resolution
	resolveErr  error
	downloadErr map[string]error // by version
	onDownload  func()
	// deps resolves dependencies by package name, at version 1.0.0 unless listed.
	deps      map[string]string
	mu        sync.Mutex
	downloads []string // name@version
}

func (f *fakeAdapter) Ecosystem() driftv1.Ecosystem { return npm }

func (f *fakeAdapter) Resolve(context.Context, string, string, string) (ingest.Resolution, error) {
	return f.resolution, f.resolveErr
}

func (f *fakeAdapter) ResolveDependency(_ context.Context, name, spec string) (ingest.Version, error) {
	if strings.HasPrefix(name, "missing") {
		return ingest.Version{}, fmt.Errorf("%w: %s@%s", ingest.ErrVersionNotFound, name, spec)
	}
	v := f.deps[name]
	if v == "" {
		v = "1.0.0"
	}
	return ingest.Version{Name: name, Version: v}, nil
}

func (f *fakeAdapter) Download(_ context.Context, v ingest.Version, s *store.Store) (store.Blob, error) {
	if f.onDownload != nil {
		f.onDownload()
	}
	f.mu.Lock()
	f.downloads = append(f.downloads, v.Name+"@"+v.Version)
	f.mu.Unlock()
	if err := f.downloadErr[v.Version]; err != nil {
		return store.Blob{}, err
	}
	return s.Put(strings.NewReader("tarball of "+v.Name+"@"+v.Version), 1024, nil)
}

type fakeRepos struct {
	checkouts map[string]repo.Checkout // by version
	err       error
	calls     int
}

func (f *fakeRepos) Resolve(_ context.Context, _, _, version string) (repo.Checkout, error) {
	f.calls++
	if f.err != nil {
		return repo.Checkout{}, f.err
	}
	checkout, ok := f.checkouts[version]
	if !ok {
		return repo.Checkout{}, repo.ErrNoMatchingTag
	}
	return checkout, nil
}

func newService(t *testing.T, adapter ingest.Adapter, repos RepoResolver) *Service {
	t.Helper()
	database, err := db.Open(t.Context(), filepath.Join(t.TempDir(), "drift.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	blobs, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &Service{
		DB:       database,
		Store:    blobs,
		Repos:    repos,
		Adapters: map[driftv1.Ecosystem]ingest.Adapter{npm: adapter},
	}
}

func version(v, repository string) ingest.Version {
	return ingest.Version{Name: "demo", Version: v, RepositoryURL: repository}
}

func TestIngestStoresThePair(t *testing.T) {
	old := version("1.0.0", "github:acme/demo")
	adapter := &fakeAdapter{resolution: ingest.Resolution{Old: &old, New: version("1.0.1", "github:acme/demo")}}
	repos := &fakeRepos{checkouts: map[string]repo.Checkout{
		"1.0.0": {Path: "/repos/a", Ref: "v1.0.0"},
		"1.0.1": {Path: "/repos/b", Ref: "v1.0.1"},
	}}
	s := newService(t, adapter, repos)

	job, err := s.Ingest(t.Context(), Request{Ecosystem: npm, Package: "demo", From: "1.0.0", To: "1.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != db.StatusIngested || job.RequestedFrom != "1.0.0" || job.RequestedTo != "1.0.1" {
		t.Errorf("job = %+v", job)
	}
	pair := job.Pair
	if pair.GetJobId() != job.ID || pair.GetDepth() != 0 || pair.GetParentJobId() != "" {
		t.Errorf("pair = %v", pair)
	}
	tests := []struct {
		name          string
		got           *driftv1.PackageVersion
		version, path string
		ref           string
	}{
		{"old", pair.GetOld(), "1.0.0", "/repos/a", "v1.0.0"},
		{"new", pair.GetNew(), "1.0.1", "/repos/b", "v1.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got.GetEcosystem() != npm || tt.got.GetName() != "demo" || tt.got.GetVersion() != tt.version {
				t.Errorf("version = %v", tt.got)
			}
			if tt.got.GetRepoPath() != tt.path || tt.got.GetRepoRef() != tt.ref {
				t.Errorf("repo = %q at %q", tt.got.GetRepoRef(), tt.got.GetRepoPath())
			}
			if tt.got.GetTarballPath() == "" || tt.got.GetTarballSha256() == "" {
				t.Errorf("tarball = %v", tt.got)
			}
		})
	}
	if pair.GetOld().GetTarballSha256() == pair.GetNew().GetTarballSha256() {
		t.Error("both versions point at the same tarball")
	}
}

func TestIngestNewPackageMode(t *testing.T) {
	adapter := &fakeAdapter{resolution: ingest.Resolution{New: version("1.0.0", "")}}
	s := newService(t, adapter, &fakeRepos{})
	job, err := s.Ingest(t.Context(), Request{Ecosystem: npm, Package: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if job.Pair.GetOld() != nil {
		t.Errorf("old = %v, want unset", job.Pair.GetOld())
	}
}

func TestIngestSubJobCarriesParentAndDepth(t *testing.T) {
	adapter := &fakeAdapter{resolution: ingest.Resolution{New: version("1.0.0", "")}}
	s := newService(t, adapter, &fakeRepos{})
	parent, err := s.Ingest(t.Context(), Request{Ecosystem: npm, Package: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := s.Ingest(t.Context(), Request{ParentJobID: parent.ID, Ecosystem: npm, Package: "dep"})
	if err != nil {
		t.Fatal(err)
	}
	if child.Pair.GetParentJobId() != parent.ID || child.Pair.GetDepth() != 1 {
		t.Errorf("pair = %v", child.Pair)
	}
}

func TestIngestUnresolvedRepoIsNotFatal(t *testing.T) {
	tests := []struct {
		name          string
		repository    string
		repos         *fakeRepos
		wantRepoCalls int
	}{
		{name: "none declared", repository: "", repos: &fakeRepos{}, wantRepoCalls: 0},
		{name: "no matching tag", repository: "github:acme/demo", repos: &fakeRepos{}, wantRepoCalls: 1},
		{name: "unsupported URL", repository: "ext::sh", repos: &fakeRepos{err: repo.ErrUnsupportedURL}, wantRepoCalls: 1},
		{name: "repository gone", repository: "github:acme/gone", repos: &fakeRepos{err: errors.New("remote says no")}, wantRepoCalls: 1},
		{name: "too large", repository: "github:acme/huge", repos: &fakeRepos{err: repo.ErrTooLarge}, wantRepoCalls: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := &fakeAdapter{resolution: ingest.Resolution{New: version("1.0.0", tt.repository)}}
			s := newService(t, adapter, tt.repos)
			job, err := s.Ingest(t.Context(), Request{Ecosystem: npm, Package: "demo"})
			if err != nil {
				t.Fatal(err)
			}
			got := job.Pair.GetNew()
			if job.Status != db.StatusIngested || got.GetRepoRef() != repo.Unresolved || got.GetRepoPath() != "" {
				t.Errorf("status = %s, new = %v", job.Status, got)
			}
			if got.GetTarballPath() == "" {
				t.Error("tarball missing")
			}
			if tt.repos.calls != tt.wantRepoCalls {
				t.Errorf("repo calls = %d, want %d", tt.repos.calls, tt.wantRepoCalls)
			}
		})
	}
}

func TestIngestFailuresAreRecorded(t *testing.T) {
	old := version("1.0.0", "")
	pairResolution := ingest.Resolution{Old: &old, New: version("1.0.1", "")}
	tests := []struct {
		name    string
		adapter *fakeAdapter
		wantErr error
	}{
		{
			name:    "version removed from the registry",
			adapter: &fakeAdapter{resolveErr: ingest.ErrVersionNotFound},
			wantErr: ingest.ErrVersionNotFound,
		},
		{
			name:    "new tarball fails its integrity check",
			adapter: &fakeAdapter{resolution: pairResolution, downloadErr: map[string]error{"1.0.1": ingest.ErrIntegrity}},
			wantErr: ingest.ErrIntegrity,
		},
		{
			name:    "old tarball fails to download",
			adapter: &fakeAdapter{resolution: pairResolution, downloadErr: map[string]error{"1.0.0": ingest.ErrIntegrity}},
			wantErr: ingest.ErrIntegrity,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newService(t, tt.adapter, &fakeRepos{})
			job, err := s.Ingest(t.Context(), Request{Ecosystem: npm, Package: "demo"})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if job == nil {
				t.Fatal("no job returned")
			}
			stored, getErr := s.DB.GetJob(t.Context(), job.ID)
			if getErr != nil {
				t.Fatal(getErr)
			}
			if stored.Status != db.StatusFailed || !strings.Contains(stored.Error, tt.wantErr.Error()) {
				t.Errorf("status = %s, error = %q", stored.Status, stored.Error)
			}
			if stored.Pair != nil {
				t.Errorf("a failed job has a pair: %v", stored.Pair)
			}
		})
	}
}

// A cancelled repo fetch must fail the job, not record a misleading "unresolved".
func TestIngestCancellationIsNotUnresolved(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	adapter := &fakeAdapter{
		resolution: ingest.Resolution{New: version("1.0.0", "github:acme/demo")},
		onDownload: cancel,
	}
	s := newService(t, adapter, &fakeRepos{err: context.Canceled})

	job, err := s.Ingest(ctx, Request{Ecosystem: npm, Package: "demo"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	stored, getErr := s.DB.GetJob(t.Context(), job.ID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if stored.Status != db.StatusFailed || stored.Pair != nil {
		t.Errorf("job = %+v", stored)
	}
}

func TestIngestUnsupportedEcosystem(t *testing.T) {
	s := newService(t, &fakeAdapter{}, &fakeRepos{})
	job, err := s.Ingest(t.Context(), Request{Ecosystem: driftv1.Ecosystem_ECOSYSTEM_PYPI, Package: "demo"})
	if !errors.Is(err, ErrUnsupportedEcosystem) || job != nil {
		t.Fatalf("job = %v, err = %v", job, err)
	}
}

type fakeAnalyzers struct {
	got      *driftv1.ArtifactPair
	findings []*driftv1.DriftFinding
	runs     []db.AnalyzerRun
}

func (f *fakeAnalyzers) Run(_ context.Context, pair *driftv1.ArtifactPair) ([]*driftv1.DriftFinding, []db.AnalyzerRun) {
	f.got = pair
	return f.findings, f.runs
}

func TestAnalyzeStoresFindings(t *testing.T) {
	adapter := &fakeAdapter{resolution: ingest.Resolution{New: version("1.0.0", "")}}
	s := newService(t, adapter, &fakeRepos{})
	analyzers := &fakeAnalyzers{
		findings: []*driftv1.DriftFinding{{Analyzer: "static-rs", Kind: "install_hook_added", Confidence: 0.9}},
		runs:     []db.AnalyzerRun{{Analyzer: "static-rs", Status: db.RunOK, Findings: 1}},
	}
	s.Analyzers = analyzers

	ingested, err := s.Ingest(t.Context(), Request{Ecosystem: npm, Package: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	job, err := s.Analyze(t.Context(), ingested.ID)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != db.StatusDone {
		t.Errorf("status = %s, want done", job.Status)
	}
	if analyzers.got.GetJobId() != job.ID || analyzers.got.GetNew().GetVersion() != "1.0.0" {
		t.Errorf("analyzers got %v", analyzers.got)
	}
	findings, err := s.DB.Findings(t.Context(), job.ID)
	if err != nil || len(findings) != 1 {
		t.Errorf("findings = %v, %v", findings, err)
	}

	// A job can't be analyzed twice.
	if _, err := s.Analyze(t.Context(), job.ID); err == nil || !strings.Contains(err.Error(), "not ingested") {
		t.Errorf("second Analyze: err = %v", err)
	}
}

func TestAnalyzeWithoutAnalyzers(t *testing.T) {
	s := newService(t, &fakeAdapter{}, &fakeRepos{})
	if _, err := s.Analyze(t.Context(), "missing"); err == nil {
		t.Error("expected an error")
	}
}
