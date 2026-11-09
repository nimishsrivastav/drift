package analyze

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	driftv1 "github.com/nimishsrivastav/drift/gen/go/drift/v1"
	"github.com/nimishsrivastav/drift/orchestrator/internal/db"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeClient struct {
	response *driftv1.AnalyzeResponse
	err      error
	block    bool
}

func (f fakeClient) Analyze(ctx context.Context, _ *driftv1.ArtifactPair, _ ...grpc.CallOption) (*driftv1.AnalyzeResponse, error) {
	if f.block {
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	return f.response, f.err
}

func finding(kind string, confidence float64) *driftv1.DriftFinding {
	return &driftv1.DriftFinding{Analyzer: "someone-else", Kind: kind, Confidence: confidence, ViaDependency: "forged@1.0.0"}
}

func TestRunCollectsAndSanitizes(t *testing.T) {
	runner := &Runner{
		Timeout: 50 * time.Millisecond,
		Endpoints: []Endpoint{
			{Name: "static-rs", Client: fakeClient{response: &driftv1.AnalyzeResponse{
				Findings: []*driftv1.DriftFinding{
					finding("install_hook_added", 0.9),
					finding("too_sure", 3),
					finding("negative", -1),
					finding("not_a_number", math.NaN()),
					finding("", 0.5),
					nil,
				},
				Errors: []string{"tarball-vs-repo diff skipped"},
			}}},
			{Name: "meta-go", Client: fakeClient{err: status.Error(codes.Unimplemented, "not yet")}},
			{Name: "trace-rs", Client: fakeClient{block: true}},
			{Name: "broken", Client: fakeClient{err: errors.New("connection refused")}},
		},
	}
	findings, runs := runner.Run(t.Context(), &driftv1.ArtifactPair{JobId: "j"})

	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3: %v", len(findings), findings)
	}
	for _, f := range findings {
		if f.GetAnalyzer() != "static-rs" || f.GetViaDependency() != "" {
			t.Errorf("finding kept a forged origin: %v", f)
		}
		if f.GetConfidence() < 0 || f.GetConfidence() > 1 {
			t.Errorf("confidence %v out of range", f.GetConfidence())
		}
	}

	want := map[string]db.RunStatus{"static-rs": db.RunOK, "meta-go": db.RunUnimplemented, "trace-rs": db.RunFailed, "broken": db.RunFailed}
	for _, run := range runs {
		if run.Status != want[run.Analyzer] {
			t.Errorf("%s: status %s, want %s", run.Analyzer, run.Status, want[run.Analyzer])
		}
	}
	if runs[0].Findings != 3 || len(runs[0].Notes) != 2 || !strings.Contains(runs[0].Notes[1], "dropped 3") {
		t.Errorf("static-rs run = %+v", runs[0])
	}
	if runs[2].Error != "timed out" {
		t.Errorf("trace-rs error = %q, want a timeout", runs[2].Error)
	}
}

func TestRunCapsFindings(t *testing.T) {
	many := make([]*driftv1.DriftFinding, maxFindings+10)
	for i := range many {
		many[i] = finding("file_added", 0.1)
	}
	runner := &Runner{Endpoints: []Endpoint{{Name: "a", Client: fakeClient{response: &driftv1.AnalyzeResponse{Findings: many}}}}}
	findings, runs := runner.Run(t.Context(), &driftv1.ArtifactPair{})
	if len(findings) != maxFindings || runs[0].Findings != maxFindings || len(runs[0].Notes) != 1 {
		t.Errorf("kept %d findings, run %+v", len(findings), runs[0])
	}
}
