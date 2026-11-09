// Package analyze sends an ArtifactPair to every configured analyzer and collects what they
// find. An analyzer that is down, slow or not yet implemented never fails the job: its run is
// recorded, and the others' findings still count.
package analyze

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	driftv1 "github.com/nimishsrivastav/drift/gen/go/drift/v1"
	"github.com/nimishsrivastav/drift/orchestrator/internal/db"
	"github.com/nimishsrivastav/drift/orchestrator/internal/registry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const (
	// DefaultTimeout bounds one analyzer's Analyze call.
	DefaultTimeout = 5 * time.Minute
	// maxFindings caps what one analyzer can add to a job.
	maxFindings = 5000
	// maxResponseBytes caps one Analyze response.
	maxResponseBytes = 64 << 20
)

// Client is the part of driftv1.AnalyzerClient the runner uses.
type Client interface {
	Analyze(ctx context.Context, in *driftv1.ArtifactPair, opts ...grpc.CallOption) (*driftv1.AnalyzeResponse, error)
}

// Endpoint is one analyzer and how to reach it.
type Endpoint struct {
	Name   string
	Client Client
}

// Runner calls analyzers.
type Runner struct {
	Endpoints []Endpoint
	Timeout   time.Duration
}

// Dial connects to the analyzers in the registry, leaving out the scorer. The returned
// function closes the connections.
func Dial(analyzers []registry.Analyzer, timeout time.Duration) (*Runner, func(), error) {
	runner := &Runner{Timeout: timeout}
	var conns []*grpc.ClientConn
	closeAll := func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}
	for _, a := range registry.Analyzers(analyzers) {
		// Analyzers talk over the private compose network; see docs/DECISIONS.md.
		conn, err := grpc.NewClient(a.Endpoint,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxResponseBytes)))
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("analyzer %s: %w", a.Name, err)
		}
		conns = append(conns, conn)
		runner.Endpoints = append(runner.Endpoints, Endpoint{Name: a.Name, Client: driftv1.NewAnalyzerClient(conn)})
	}
	return runner, closeAll, nil
}

// Run calls every analyzer at once and returns their findings, in endpoint order, and one run
// record per analyzer.
func (r *Runner) Run(ctx context.Context, pair *driftv1.ArtifactPair) ([]*driftv1.DriftFinding, []db.AnalyzerRun) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	findings := make([][]*driftv1.DriftFinding, len(r.Endpoints))
	runs := make([]db.AnalyzerRun, len(r.Endpoints))
	var wg sync.WaitGroup
	for i, endpoint := range r.Endpoints {
		wg.Go(func() {
			findings[i], runs[i] = call(ctx, endpoint, pair, timeout)
		})
	}
	wg.Wait()

	var all []*driftv1.DriftFinding
	for _, f := range findings {
		all = append(all, f...)
	}
	return all, runs
}

func call(ctx context.Context, endpoint Endpoint, pair *driftv1.ArtifactPair, timeout time.Duration) ([]*driftv1.DriftFinding, db.AnalyzerRun) {
	run := db.AnalyzerRun{Analyzer: endpoint.Name}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	started := time.Now()
	response, err := endpoint.Client.Analyze(callCtx, pair, grpc.WaitForReady(true))
	run.DurationMS = time.Since(started).Milliseconds()
	if err != nil {
		run.Status, run.Error = classify(err)
		level := slog.LevelWarn
		if run.Status == db.RunUnimplemented {
			level = slog.LevelDebug
		}
		slog.Log(ctx, level, "analyzer gave no result", "analyzer", endpoint.Name, "status", run.Status, "err", run.Error)
		return nil, run
	}

	run.Status = db.RunOK
	run.Notes = response.GetErrors()
	findings := sanitize(endpoint.Name, response.GetFindings(), &run)
	run.Findings = len(findings)
	slog.InfoContext(ctx, "analyzer finished", "analyzer", endpoint.Name, "findings", run.Findings,
		"notes", len(run.Notes), "duration_ms", run.DurationMS)
	return findings, run
}

func classify(err error) (db.RunStatus, string) {
	if s, ok := status.FromError(err); ok && s.Code() == codes.Unimplemented {
		return db.RunUnimplemented, s.Message()
	}
	if errors.Is(err, context.DeadlineExceeded) || status.Code(err) == codes.DeadlineExceeded {
		return db.RunFailed, "timed out"
	}
	return db.RunFailed, err.Error()
}

// sanitize makes an analyzer's findings safe to store: the analyzer can only speak for itself,
// confidence must be a number in [0, 1], and the count is capped.
func sanitize(name string, findings []*driftv1.DriftFinding, run *db.AnalyzerRun) []*driftv1.DriftFinding {
	out := make([]*driftv1.DriftFinding, 0, min(len(findings), maxFindings))
	dropped := 0
	for _, f := range findings {
		if f == nil || f.GetKind() == "" || math.IsNaN(f.GetConfidence()) {
			dropped++
			continue
		}
		if len(out) == maxFindings {
			run.Notes = append(run.Notes, fmt.Sprintf("orchestrator: kept the first %d findings of %d", maxFindings, len(findings)))
			break
		}
		f.Analyzer = name
		// Roll-up from dependencies is the orchestrator's job, not an analyzer's.
		f.ViaDependency = ""
		f.Confidence = math.Min(1, math.Max(0, f.GetConfidence()))
		out = append(out, f)
	}
	if dropped > 0 {
		run.Notes = append(run.Notes, fmt.Sprintf("orchestrator: dropped %d malformed findings", dropped))
	}
	return out
}
