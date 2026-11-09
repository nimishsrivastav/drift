package db

import (
	"path/filepath"
	"strings"
	"testing"

	driftv1 "github.com/nimishsrivastav/drift/gen/go/drift/v1"
)

func ingestedJob(t *testing.T) (*DB, string) {
	t.Helper()
	database, err := Open(t.Context(), filepath.Join(t.TempDir(), "drift.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	job, err := database.CreateJob(t.Context(), NewJob{Ecosystem: driftv1.Ecosystem_ECOSYSTEM_NPM, Package: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	pair := &driftv1.ArtifactPair{JobId: job.ID, New: &driftv1.PackageVersion{Name: "demo", Version: "1.0.1"}}
	if err := database.CompleteIngest(t.Context(), job.ID, pair); err != nil {
		t.Fatal(err)
	}
	return database, job.ID
}

func TestCompleteAnalysis(t *testing.T) {
	database, id := ingestedJob(t)
	findings := []*driftv1.DriftFinding{{Analyzer: "static-rs", Kind: "install_hook_added", Confidence: 0.9}}
	runs := []AnalyzerRun{
		{Analyzer: "static-rs", Status: RunOK, Notes: []string{"a note", strings.Repeat("x", maxErrorBytes+10)}, Findings: 1, DurationMS: 12},
		{Analyzer: "meta-go", Status: RunUnimplemented, Error: "not yet"},
	}
	if err := database.CompleteAnalysis(t.Context(), id, findings, runs); err != nil {
		t.Fatal(err)
	}

	job, err := database.GetJob(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != StatusDone {
		t.Errorf("status = %s, want done", job.Status)
	}
	stored, err := database.Findings(t.Context(), id)
	if err != nil || len(stored) != 1 || stored[0].GetKind() != "install_hook_added" {
		t.Errorf("findings = %v, %v", stored, err)
	}
	got, err := database.AnalyzerRuns(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Analyzer != "meta-go" || got[1].Analyzer != "static-rs" {
		t.Fatalf("runs = %+v", got)
	}
	if got[1].DurationMS != 12 || got[1].Findings != 1 || got[1].Notes[0] != "a note" || !strings.HasSuffix(got[1].Notes[1], "(truncated)") {
		t.Errorf("static-rs run = %+v", got[1])
	}
}

func TestCompleteAnalysisIsAllOrNothing(t *testing.T) {
	database, id := ingestedJob(t)
	// The schema rejects a confidence over 1, so the whole completion must roll back.
	bad := []*driftv1.DriftFinding{{Analyzer: "a", Kind: "k", Confidence: 0.5}, {Analyzer: "a", Kind: "k", Confidence: 2}}
	if err := database.CompleteAnalysis(t.Context(), id, bad, []AnalyzerRun{{Analyzer: "a", Status: RunOK}}); err == nil {
		t.Fatal("expected an error")
	}
	job, _ := database.GetJob(t.Context(), id)
	findings, _ := database.Findings(t.Context(), id)
	runs, _ := database.AnalyzerRuns(t.Context(), id)
	if job.Status != StatusIngested || len(findings) != 0 || len(runs) != 0 {
		t.Errorf("partial completion: status %s, %d findings, %d runs", job.Status, len(findings), len(runs))
	}
}
