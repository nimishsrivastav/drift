package jobs

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	driftv1 "github.com/nimishsrivastav/drift/gen/go/drift/v1"
	"github.com/nimishsrivastav/drift/orchestrator/internal/db"
	"github.com/nimishsrivastav/drift/orchestrator/internal/ingest"
)

// scriptedAnalyzers answers by package name, the way static-rs would for each fixture.
type scriptedAnalyzers struct {
	mu      sync.Mutex
	by      map[string][]*driftv1.DriftFinding
	calls   []string
	isNewPk map[string]bool
}

func (s *scriptedAnalyzers) Run(_ context.Context, pair *driftv1.ArtifactPair) ([]*driftv1.DriftFinding, []db.AnalyzerRun) {
	name := pair.GetNew().GetName()
	s.mu.Lock()
	s.calls = append(s.calls, name)
	if s.isNewPk == nil {
		s.isNewPk = map[string]bool{}
	}
	s.isNewPk[name] = pair.GetOld() == nil
	s.mu.Unlock()
	var out []*driftv1.DriftFinding
	for _, f := range s.by[name] {
		out = append(out, &driftv1.DriftFinding{
			Analyzer: f.GetAnalyzer(), Kind: f.GetKind(), Capability: f.GetCapability(),
			Context: f.GetContext(), Confidence: f.GetConfidence(), Attrs: f.GetAttrs(),
		})
	}
	return out, []db.AnalyzerRun{{Analyzer: "static-rs", Status: db.RunOK, Findings: len(out)}}
}

func added(name string, attrs ...string) *driftv1.DriftFinding {
	a := map[string]string{"dependency": name, "source": "registry", "package": name, "range": "^1.0.0", "bundled": "false"}
	for i := 0; i+1 < len(attrs); i += 2 {
		a[attrs[i]] = attrs[i+1]
	}
	return &driftv1.DriftFinding{Analyzer: "static-rs", Kind: "dependency_added", Confidence: 0.5, Attrs: a,
		Context: driftv1.ExecContext_EXEC_CONTEXT_INSTALL}
}

func installHook() *driftv1.DriftFinding {
	return &driftv1.DriftFinding{Analyzer: "static-rs", Kind: "install_hook_added", Confidence: 0.9,
		Capability: driftv1.Capability_CAPABILITY_INSTALL_HOOK, Context: driftv1.ExecContext_EXEC_CONTEXT_INSTALL}
}

func analyzeDemo(t *testing.T, s *Service) *db.Job {
	t.Helper()
	old := version("1.0.0", "")
	s.Adapters[npm].(*fakeAdapter).resolution = ingest.Resolution{Old: &old, New: version("1.0.1", "")}
	ingested, err := s.Ingest(t.Context(), Request{Ecosystem: npm, Package: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	job, err := s.Analyze(t.Context(), ingested.ID)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != db.StatusDone {
		t.Fatalf("status = %s (%s)", job.Status, job.Error)
	}
	return job
}

func expansionNotes(t *testing.T, s *Service, jobID string) []string {
	t.Helper()
	runs, err := s.DB.AnalyzerRuns(t.Context(), jobID)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range runs {
		if r.Analyzer == ExpansionRun {
			return r.Notes
		}
	}
	return nil
}

func TestExpansionRollsUpDependencyFindings(t *testing.T) {
	adapter := &fakeAdapter{deps: map[string]string{"evil": "1.2.0"}}
	s := newService(t, adapter, &fakeRepos{})
	analyzers := &scriptedAnalyzers{by: map[string][]*driftv1.DriftFinding{
		"demo":   {added("evil")},
		"evil":   {installHook(), added("deeper")},
		"deeper": {installHook(), added("deepest")},
	}}
	s.Analyzers = analyzers

	job := analyzeDemo(t, s)
	findings, err := s.DB.Findings(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range findings {
		got = append(got, fmt.Sprintf("%s via %q", f.GetKind(), f.GetViaDependency()))
	}
	want := []string{
		`dependency_added via ""`,
		`install_hook_added via "evil@1.2.0"`,
		`dependency_added via "evil@1.2.0"`,
		`install_hook_added via "evil@1.2.0 > deeper@1.0.0"`,
		`dependency_added via "evil@1.2.0 > deeper@1.0.0"`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("findings =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// deepest sits below the depth limit and is never analyzed.
	if !slices.Equal(analyzers.calls, []string{"demo", "evil", "deeper"}) {
		t.Errorf("analyzed %v", analyzers.calls)
	}
	if !analyzers.isNewPk["evil"] || !analyzers.isNewPk["deeper"] || analyzers.isNewPk["demo"] {
		t.Errorf("new-package mode = %v", analyzers.isNewPk)
	}
	notes := expansionNotes(t, s, job.ID)
	if len(notes) != 1 || !strings.Contains(notes[0], "evil@1.2.0: 4 findings rolled up from sub-job") {
		t.Errorf("notes = %q", notes)
	}

	// The sub-jobs carry their parent and depth.
	children := subJobs(t, s, job.ID)
	if len(children) != 1 || children[0].Depth != 1 || children[0].Package != "evil" || children[0].RequestedTo != "^1.0.0" {
		t.Fatalf("children = %+v", children)
	}
	grandchildren := subJobs(t, s, children[0].ID)
	if len(grandchildren) != 1 || grandchildren[0].Depth != 2 {
		t.Fatalf("grandchildren = %+v", grandchildren)
	}
	deepNotes := expansionNotes(t, s, grandchildren[0].ID)
	if len(deepNotes) != 1 || !strings.Contains(deepNotes[0], "depth limit 2") {
		t.Errorf("depth-2 notes = %q", deepNotes)
	}
}

func subJobs(t *testing.T, s *Service, parent string) []*db.Job {
	t.Helper()
	ids, err := s.DB.SubJobs(t.Context(), parent)
	if err != nil {
		t.Fatal(err)
	}
	var out []*db.Job
	for _, id := range ids {
		job, err := s.DB.GetJob(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, job)
	}
	return out
}

func TestExpansionLimitsFanOut(t *testing.T) {
	var deps []*driftv1.DriftFinding
	for i := range MaxSubJobs + 5 {
		deps = append(deps, added(fmt.Sprintf("dep%02d", i)))
	}
	// The most confident ones are expanded first.
	deps[24].Confidence = 0.9
	s := newService(t, &fakeAdapter{}, &fakeRepos{})
	analyzers := &scriptedAnalyzers{by: map[string][]*driftv1.DriftFinding{"demo": deps}}
	s.Analyzers = analyzers

	job := analyzeDemo(t, s)
	if n := len(subJobs(t, s, job.ID)); n != MaxSubJobs {
		t.Errorf("%d sub-jobs, want %d", n, MaxSubJobs)
	}
	if !slices.Contains(analyzers.calls, "dep24") || slices.Contains(analyzers.calls, "dep23") {
		t.Errorf("analyzed %v", analyzers.calls)
	}
	var over int
	for _, n := range expansionNotes(t, s, job.ID) {
		if strings.Contains(n, "over the limit") {
			over++
		}
	}
	if over != 5 {
		t.Errorf("%d over-limit notes, want 5", over)
	}
}

func TestExpansionReusesCachedAnalyses(t *testing.T) {
	adapter := &fakeAdapter{}
	s := newService(t, adapter, &fakeRepos{})
	analyzers := &scriptedAnalyzers{by: map[string][]*driftv1.DriftFinding{
		"demo": {added("evil"), added("alias-of-evil", "package", "evil", "range", "~1.0.0")},
		"evil": {installHook()},
	}}
	s.Analyzers = analyzers

	first := analyzeDemo(t, s)
	second := analyzeDemo(t, s)

	// Analyzed once: the alias resolves to the same version, and the second parent reuses it.
	if got := slices.DeleteFunc(slices.Clone(analyzers.calls), func(n string) bool { return n == "demo" }); !slices.Equal(got, []string{"evil"}) {
		t.Errorf("analyzed %v", analyzers.calls)
	}
	if n := len(subJobs(t, s, second.ID)); n != 0 {
		t.Errorf("second parent has %d sub-jobs, want 0", n)
	}
	for _, job := range []*db.Job{first, second} {
		findings, err := s.DB.Findings(t.Context(), job.ID)
		if err != nil {
			t.Fatal(err)
		}
		var rolled int
		for _, f := range findings {
			if f.GetViaDependency() == "evil@1.0.0" {
				rolled++
			}
		}
		if rolled != 1 {
			t.Errorf("job %s: %d rolled-up findings, want 1", job.ID, rolled)
		}
	}
	notes := strings.Join(expansionNotes(t, s, second.ID), "\n")
	if !strings.Contains(notes, "from cached job") || !strings.Contains(notes, "rolled up once") {
		t.Errorf("notes = %s", notes)
	}
}

func TestExpansionSkipsWhatItCannotFetch(t *testing.T) {
	s := newService(t, &fakeAdapter{}, &fakeRepos{})
	s.Analyzers = &scriptedAnalyzers{by: map[string][]*driftv1.DriftFinding{"demo": {
		added("from-git", "source", "git", "spec", "github:a/b", "package", ""),
		added("inside", "bundled", "true"),
		added("missing-dep"),
	}}}

	job := analyzeDemo(t, s)
	if n := len(subJobs(t, s, job.ID)); n != 0 {
		t.Errorf("%d sub-jobs, want 0", n)
	}
	notes := strings.Join(expansionNotes(t, s, job.ID), "\n")
	for _, want := range []string{
		`from-git: not expanded, git source "github:a/b"`,
		"inside: not expanded, bundled in the tarball",
		"missing-dep: not expanded, version not found",
	} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}
}

func TestExpansionSurvivesAFailingSubJob(t *testing.T) {
	adapter := &fakeAdapter{deps: map[string]string{"broken": "6.6.6"}, downloadErr: map[string]error{"6.6.6": ingest.ErrIntegrity}}
	s := newService(t, adapter, &fakeRepos{})
	s.Analyzers = &scriptedAnalyzers{by: map[string][]*driftv1.DriftFinding{"demo": {added("broken")}}}

	job := analyzeDemo(t, s)
	children := subJobs(t, s, job.ID)
	if len(children) != 1 || children[0].Status != db.StatusFailed {
		t.Fatalf("children = %+v", children)
	}
	notes := strings.Join(expansionNotes(t, s, job.ID), "\n")
	if !strings.Contains(notes, "broken@6.6.6: sub-job "+children[0].ID+" failed") {
		t.Errorf("notes = %s", notes)
	}
}

func TestNoExpansionRecordWithoutDependencies(t *testing.T) {
	s := newService(t, &fakeAdapter{}, &fakeRepos{})
	s.Analyzers = &scriptedAnalyzers{by: map[string][]*driftv1.DriftFinding{"demo": {installHook()}}}
	job := analyzeDemo(t, s)
	if notes := expansionNotes(t, s, job.ID); notes != nil {
		t.Errorf("notes = %q", notes)
	}
	runs, _ := s.DB.AnalyzerRuns(t.Context(), job.ID)
	if len(runs) != 1 {
		t.Errorf("runs = %+v", runs)
	}
}
