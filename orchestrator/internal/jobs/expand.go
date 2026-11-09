package jobs

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	driftv1 "github.com/nimishsrivastav/drift/gen/go/drift/v1"
	"github.com/nimishsrivastav/drift/orchestrator/internal/db"
	"github.com/nimishsrivastav/drift/orchestrator/internal/ingest"
	"google.golang.org/protobuf/proto"
)

const (
	// MaxDependencyDepth is the deepest sub-job: dependencies of dependencies, and no further.
	MaxDependencyDepth = 2
	// MaxSubJobs caps the dependencies expanded for one parent.
	MaxSubJobs = 20
	// ExpansionRun names the analyzer-run record that describes a job's expansion.
	ExpansionRun = "dependency-expansion"
	// expansionWorkers bounds the sub-jobs of one parent that run at once.
	expansionWorkers = 4
	// viaSeparator joins a chain of dependencies in via_dependency: "a@1.0.0 > b@2.0.0".
	viaSeparator = " > "
)

// candidate is one newly added dependency to analyze on its own.
type candidate struct {
	declared   string // the name it is installed under
	pkg        string // the registry name to fetch, which differs for an alias
	spec       string
	confidence float64
}

// candidates picks the dependency_added findings that can be fetched from the registry,
// most confident first, and describes the rest. Git, tarball and local sources have no
// registry version to analyze, and bundled dependencies are already in the parent's tarball.
func candidates(findings []*driftv1.DriftFinding) ([]candidate, []string) {
	var out []candidate
	var notes []string
	seen := map[string]bool{}
	for _, f := range findings {
		if f.GetKind() != "dependency_added" {
			continue
		}
		attrs := f.GetAttrs()
		name := attrs["dependency"]
		switch {
		case attrs["bundled"] == "true":
			notes = append(notes, fmt.Sprintf("%s: not expanded, bundled in the tarball", name))
			continue
		case attrs["source"] != "registry" && attrs["source"] != "alias":
			notes = append(notes, fmt.Sprintf("%s: not expanded, %s source %q", name, attrs["source"], attrs["spec"]))
			continue
		case attrs["package"] == "":
			notes = append(notes, fmt.Sprintf("%s: not expanded, no package name", name))
			continue
		}
		key := attrs["package"] + "@" + attrs["range"]
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, candidate{declared: name, pkg: attrs["package"], spec: attrs["range"], confidence: f.GetConfidence()})
	}
	slices.SortStableFunc(out, func(a, b candidate) int {
		if c := cmp.Compare(b.confidence, a.confidence); c != 0 {
			return c
		}
		return cmp.Compare(a.declared, b.declared)
	})
	if len(out) > MaxSubJobs {
		for _, c := range out[MaxSubJobs:] {
			notes = append(notes, fmt.Sprintf("%s: not expanded, over the limit of %d sub-jobs", c.declared, MaxSubJobs))
		}
		out = out[:MaxSubJobs]
	}
	return out, notes
}

// expanded is what one dependency contributed.
type expanded struct {
	findings []*driftv1.DriftFinding
	note     string
}

// expand analyzes each newly added dependency in new-package mode, as a sub-job, and returns
// the sub-jobs' findings marked with the dependency they came through. A dependency that can't
// be resolved or analyzed becomes a note, never a failure of the parent; only cancellation is
// returned as an error. The run record is nil when there was nothing to expand.
func (s *Service) expand(ctx context.Context, job *db.Job, findings []*driftv1.DriftFinding) ([]*driftv1.DriftFinding, *db.AnalyzerRun, error) {
	deps, notes := candidates(findings)
	if len(deps) == 0 && len(notes) == 0 {
		return nil, nil, nil
	}
	run := &db.AnalyzerRun{Analyzer: ExpansionRun, Status: db.RunOK}
	started := time.Now()
	if job.Depth >= MaxDependencyDepth {
		run.Notes = append(notes, fmt.Sprintf("%d dependencies not expanded: depth limit %d reached", len(deps), MaxDependencyDepth))
		return nil, run, nil
	}
	adapter, ok := s.Adapters[job.Ecosystem]
	if !ok {
		return nil, nil, fmt.Errorf("%w: %s", ErrUnsupportedEcosystem, job.Ecosystem)
	}

	results := make([]expanded, len(deps))
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		claimed   = map[string]int{} // resolved name@version → index of the dependency analyzing it
		semaphore = make(chan struct{}, expansionWorkers)
	)
	for i, dep := range deps {
		wg.Go(func() {
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			results[i] = s.expandOne(ctx, adapter, job, dep, func(label string) (int, bool) {
				mu.Lock()
				defer mu.Unlock()
				if first, taken := claimed[label]; taken {
					return first, false
				}
				claimed[label] = i
				return i, true
			})
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	var rolledUp []*driftv1.DriftFinding
	for _, r := range results {
		rolledUp = append(rolledUp, r.findings...)
		if r.note != "" {
			notes = append(notes, r.note)
		}
	}
	run.Notes = notes
	run.Findings = len(rolledUp)
	run.DurationMS = time.Since(started).Milliseconds()
	return rolledUp, run, nil
}

// expandOne resolves, analyzes (or reuses) and rolls up one dependency. claim deduplicates
// dependencies that resolve to the same version within one parent.
func (s *Service) expandOne(ctx context.Context, adapter ingest.Adapter, parent *db.Job, dep candidate,
	claim func(label string) (int, bool),
) expanded {
	version, err := adapter.ResolveDependency(ctx, dep.pkg, dep.spec)
	if err != nil {
		return expanded{note: fmt.Sprintf("%s: not expanded, %v", dep.declared, err)}
	}
	label := version.Name + "@" + version.Version
	if first, ok := claim(label); !ok {
		return expanded{note: fmt.Sprintf("%s: same version as dependency %d, rolled up once", dep.declared, first+1)}
	}

	child, cached, err := s.dependencyJob(ctx, adapter, parent, dep, version)
	if err != nil {
		if child != nil {
			return expanded{note: fmt.Sprintf("%s: sub-job %s failed: %v", label, child.ID, err)}
		}
		return expanded{note: fmt.Sprintf("%s: not expanded, %v", label, err)}
	}
	childFindings, err := s.DB.Findings(ctx, child.ID)
	if err != nil {
		return expanded{note: fmt.Sprintf("%s: findings of job %s unreadable: %v", label, child.ID, err)}
	}
	rolled := make([]*driftv1.DriftFinding, 0, len(childFindings))
	for _, f := range childFindings {
		f = proto.Clone(f).(*driftv1.DriftFinding)
		if f.GetViaDependency() == "" {
			f.ViaDependency = label
		} else {
			f.ViaDependency = label + viaSeparator + f.GetViaDependency()
		}
		rolled = append(rolled, f)
	}
	how := "sub-job " + child.ID
	if cached {
		how = "cached job " + child.ID
	}
	return expanded{findings: rolled, note: fmt.Sprintf("%s: %d findings rolled up from %s", label, len(rolled), how)}
}

// dependencyJob returns a finished new-package analysis of version: a cached one, or a new
// sub-job of parent. On failure the sub-job, if one was created, is returned with the error.
func (s *Service) dependencyJob(ctx context.Context, adapter ingest.Adapter, parent *db.Job, dep candidate,
	version ingest.Version,
) (*db.Job, bool, error) {
	cached, err := s.DB.CachedDependency(ctx, parent.Ecosystem, version.Name, version.Version, parent.Depth+1)
	if err == nil {
		return cached, true, nil
	}
	if !errors.Is(err, db.ErrNotFound) {
		return nil, false, err
	}

	resolution := ingest.Resolution{New: version}
	child, err := s.ingest(ctx, adapter, Request{
		ParentJobID: parent.ID,
		Ecosystem:   parent.Ecosystem,
		Package:     version.Name,
		To:          dep.spec,
	}, func(context.Context) (ingest.Resolution, error) { return resolution, nil })
	if err != nil {
		return child, false, err
	}
	slog.InfoContext(ctx, "analyzing new dependency", "parent", parent.ID, "job", child.ID,
		"package", version.Name, "version", version.Version, "depth", child.Depth)
	child, err = s.Analyze(ctx, child.ID)
	return child, false, err
}
