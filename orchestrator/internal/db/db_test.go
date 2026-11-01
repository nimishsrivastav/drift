package db

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	driftv1 "github.com/nimishsrivastav/drift/gen/go/drift/v1"
	"google.golang.org/protobuf/proto"
)

const npm = driftv1.Ecosystem_ECOSYSTEM_NPM

func openTest(t *testing.T) *DB {
	t.Helper()
	d, err := Open(t.Context(), filepath.Join(t.TempDir(), "nested", "drift.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func createJob(t *testing.T, d *DB, parent string) *Job {
	t.Helper()
	job, err := d.CreateJob(t.Context(), NewJob{ParentJobID: parent, Ecosystem: npm, Package: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func TestOpenIsIdempotentAndKeepsData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "drift.db")
	first, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	job := createJob(t, first, "")
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	if _, err := second.GetJob(t.Context(), job.ID); err != nil {
		t.Errorf("job did not survive reopening: %v", err)
	}
}

func TestOpenConcurrently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "drift.db")
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range cap(errs) {
		wg.Go(func() {
			d, err := Open(context.Background(), path)
			if err == nil {
				_ = d.Close()
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}

func TestOpenRefusesNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "drift.db")
	d, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.sql.ExecContext(t.Context(), "PRAGMA user_version = 9999"); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), path); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("err = %v, want a newer-schema refusal", err)
	}
}

// Foreign keys are per connection, so check connections that the pool opened later.
func TestForeignKeysOnEveryConnection(t *testing.T) {
	d := openTest(t)
	ctx := t.Context()
	var conns []interface{ Close() error }
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()
	for range 3 {
		conn, err := d.sql.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
		var enabled int
		if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&enabled); err != nil {
			t.Fatal(err)
		}
		if enabled != 1 {
			t.Error("a pooled connection has foreign keys off")
		}
	}
}

func TestCreateJob(t *testing.T) {
	d := openTest(t)
	fixed := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return fixed }

	job, err := d.CreateJob(t.Context(), NewJob{Ecosystem: npm, Package: "@acme/demo", RequestedFrom: "1.0.0", RequestedTo: "1.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if job.ID == "" || job.Status != StatusPending || job.Depth != 0 || job.ParentJobID != "" || job.Pair != nil {
		t.Errorf("job = %+v", job)
	}
	if job.Ecosystem != npm || job.Package != "@acme/demo" || job.RequestedFrom != "1.0.0" || job.RequestedTo != "1.0.1" {
		t.Errorf("job = %+v", job)
	}
	if !job.CreatedAt.Equal(fixed) || !job.UpdatedAt.Equal(fixed) {
		t.Errorf("times = %v, %v", job.CreatedAt, job.UpdatedAt)
	}
	other := createJob(t, d, "")
	if other.ID == job.ID {
		t.Error("job ids repeat")
	}
}

func TestCreateJobRejects(t *testing.T) {
	d := openTest(t)
	tests := []struct {
		name    string
		job     NewJob
		wantErr error
	}{
		{name: "no package", job: NewJob{Ecosystem: npm}},
		{name: "no ecosystem", job: NewJob{Package: "demo"}},
		{name: "unknown parent", job: NewJob{Ecosystem: npm, Package: "demo", ParentJobID: "nope"}, wantErr: ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := d.CreateJob(t.Context(), tt.job)
			if err == nil {
				t.Fatal("expected an error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestSubJobDepthAndCascade(t *testing.T) {
	d := openTest(t)
	root := createJob(t, d, "")
	child := createJob(t, d, root.ID)
	grandchild := createJob(t, d, child.ID)
	if child.Depth != 1 || child.ParentJobID != root.ID {
		t.Errorf("child = %+v", child)
	}
	if grandchild.Depth != 2 || grandchild.ParentJobID != child.ID {
		t.Errorf("grandchild = %+v", grandchild)
	}
	if err := d.AddFindings(t.Context(), grandchild.ID, []*driftv1.DriftFinding{{Analyzer: "static-rs", Kind: "k"}}); err != nil {
		t.Fatal(err)
	}

	if _, err := d.sql.ExecContext(t.Context(), "DELETE FROM jobs WHERE id = ?", root.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetJob(t.Context(), grandchild.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("grandchild survived its root: %v", err)
	}
	var left int
	if err := d.sql.QueryRowContext(t.Context(), "SELECT count(*) FROM findings").Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Errorf("%d findings survived their job", left)
	}
}

// The schema itself should refuse bad rows, whichever code path writes them.
func TestSchemaConstraints(t *testing.T) {
	d := openTest(t)
	parent := createJob(t, d, "")
	const insertJob = `INSERT INTO jobs (id, parent_job_id, depth, ecosystem, package, status, created_at, updated_at)
		VALUES ('x', ?, ?, 'ECOSYSTEM_NPM', 'demo', ?, 't', 't')`
	const insertFinding = `INSERT INTO findings (job_id, analyzer, kind, capability, context, confidence, finding)
		VALUES (?, 'a', 'k', 'c', 'x', ?, '{}')`
	const insertReport = `INSERT INTO reports (job_id, score, verdict, explanation, report, created_at)
		VALUES (?, 1, ?, 'e', '{}', 't')`

	// Controls: without these, a typo in the SQL above would make every rejection below pass.
	controls := []struct {
		name  string
		query string
		args  []any
	}{
		{"root job", insertJob, []any{nil, 0, "pending"}},
		{"sub-job", insertJob, []any{parent.ID, 1, "pending"}},
		{"finding", insertFinding, []any{parent.ID, 0.5}},
		{"report", insertReport, []any{parent.ID, "VERDICT_BENIGN"}},
	}
	for _, tt := range controls {
		t.Run("control "+tt.name, func(t *testing.T) {
			tx, err := d.sql.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback() }()
			if _, err := tx.ExecContext(t.Context(), tt.query, tt.args...); err != nil {
				t.Errorf("a valid row was rejected: %v", err)
			}
		})
	}

	tests := []struct {
		name  string
		query string
		args  []any
	}{
		{"sub-job with depth 0", insertJob, []any{parent.ID, 0, "pending"}},
		{"root job with depth", insertJob, []any{nil, 1, "pending"}},
		{"negative depth", insertJob, []any{nil, -1, "pending"}},
		{"unknown parent", insertJob, []any{"nope", 1, "pending"}},
		{"unknown status", insertJob, []any{nil, 0, "bogus"}},
		{"depth of the wrong type", insertJob, []any{nil, "zero", "pending"}},
		{"finding for unknown job", insertFinding, []any{"nope", 0.5}},
		{"confidence too high", insertFinding, []any{parent.ID, 1.5}},
		{"confidence too low", insertFinding, []any{parent.ID, -0.1}},
		{"report for unknown job", insertReport, []any{"nope", "VERDICT_BENIGN"}},
		{"unspecified verdict", insertReport, []any{parent.ID, "VERDICT_UNSPECIFIED"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := d.sql.ExecContext(t.Context(), tt.query, tt.args...); err == nil {
				t.Error("the schema accepted it")
			}
		})
	}
}

func TestCompleteIngest(t *testing.T) {
	version := func(v string) *driftv1.PackageVersion {
		return &driftv1.PackageVersion{
			Ecosystem: npm, Name: "demo", Version: v,
			TarballPath: "/artifacts/x", TarballSha256: "abc", RepoPath: "/repos/y", RepoRef: "v" + v,
		}
	}
	tests := []struct {
		name    string
		old     *driftv1.PackageVersion
		wantOld string
	}{
		{name: "update", old: version("1.0.0"), wantOld: "1.0.0"},
		{name: "new-package mode leaves old unset", old: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := openTest(t)
			job := createJob(t, d, "")
			pair := &driftv1.ArtifactPair{JobId: job.ID, Old: tt.old, New: version("1.0.1")}
			if err := d.CompleteIngest(t.Context(), job.ID, pair); err != nil {
				t.Fatal(err)
			}
			got, err := d.GetJob(t.Context(), job.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != StatusIngested {
				t.Errorf("status = %s", got.Status)
			}
			if !proto.Equal(got.Pair, pair) {
				t.Errorf("pair = %v, want %v", got.Pair, pair)
			}
			// Analyzers tell new-package mode from a diff by whether old is set at all.
			if (got.Pair.GetOld() == nil) != (tt.old == nil) {
				t.Errorf("old = %v", got.Pair.GetOld())
			}
			var oldColumn, newColumn *string
			row := d.sql.QueryRowContext(t.Context(), "SELECT old_version, new_version FROM jobs WHERE id = ?", job.ID)
			if err := row.Scan(&oldColumn, &newColumn); err != nil {
				t.Fatal(err)
			}
			if newColumn == nil || *newColumn != "1.0.1" {
				t.Errorf("new_version = %v", newColumn)
			}
			if tt.wantOld == "" && oldColumn != nil {
				t.Errorf("old_version = %q, want NULL", *oldColumn)
			}
			if tt.wantOld != "" && (oldColumn == nil || *oldColumn != tt.wantOld) {
				t.Errorf("old_version = %v, want %s", oldColumn, tt.wantOld)
			}
		})
	}
}

func TestCompleteIngestRejects(t *testing.T) {
	d := openTest(t)
	job := createJob(t, d, "")
	newVersion := &driftv1.PackageVersion{Version: "1.0.0"}
	tests := []struct {
		name    string
		id      string
		pair    *driftv1.ArtifactPair
		wantErr error
	}{
		{name: "pair for another job", id: job.ID, pair: &driftv1.ArtifactPair{JobId: "other", New: newVersion}},
		{name: "no new version", id: job.ID, pair: &driftv1.ArtifactPair{JobId: job.ID}},
		{name: "unknown job", id: "nope", pair: &driftv1.ArtifactPair{JobId: "nope", New: newVersion}, wantErr: ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := d.CompleteIngest(t.Context(), tt.id, tt.pair)
			if err == nil {
				t.Fatal("expected an error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestStatusUpdates(t *testing.T) {
	d := openTest(t)
	start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return start }
	job := createJob(t, d, "")
	d.now = func() time.Time { return start.Add(time.Minute) }

	if err := d.SetStatus(t.Context(), job.ID, StatusIngesting); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetJob(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusIngesting || !got.UpdatedAt.Equal(start.Add(time.Minute)) || !got.CreatedAt.Equal(start) {
		t.Errorf("job = %+v", got)
	}

	if err := d.SetStatus(t.Context(), job.ID, Status("bogus")); err == nil {
		t.Error("an unknown status was stored")
	}
	if err := d.SetStatus(t.Context(), "nope", StatusDone); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v", err)
	}
	if err := d.FailJob(t.Context(), "nope", "why"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v", err)
	}
	if _, err := d.GetJob(t.Context(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v", err)
	}
}

func TestFailJob(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		check  func(string) bool
	}{
		{"kept as is", "version not found", func(s string) bool { return s == "version not found" }},
		{"long reason is capped", strings.Repeat("x", 10_000), func(s string) bool {
			return len(s) < maxErrorBytes+100 && strings.HasSuffix(s, "(truncated)")
		}},
		{"invalid UTF-8 is cleaned", "bad \xff bytes", utf8.ValidString},
		{"cut inside a rune stays valid", strings.Repeat("x", maxErrorBytes-1) + "é", utf8.ValidString},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := openTest(t)
			job := createJob(t, d, "")
			if err := d.FailJob(t.Context(), job.ID, tt.reason); err != nil {
				t.Fatal(err)
			}
			got, err := d.GetJob(t.Context(), job.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != StatusFailed || !tt.check(got.Error) {
				t.Errorf("status = %s, error = %q", got.Status, got.Error)
			}
		})
	}
}

func TestFindings(t *testing.T) {
	d := openTest(t)
	job := createJob(t, d, "")
	findings := []*driftv1.DriftFinding{
		{
			Analyzer: "static-rs", Kind: "capability_added",
			Capability: driftv1.Capability_CAPABILITY_NETWORK, Context: driftv1.ExecContext_EXEC_CONTEXT_INSTALL,
			Confidence: 0.9, Attrs: map[string]string{"spec": "^1.0.0"},
			Evidence: []*driftv1.Evidence{{File: "install.js", Line: 3, Snippet: "x"}},
		},
		{Analyzer: "trace-rs", Kind: "new_dns_query", Confidence: 1, ViaDependency: "plain-crypto-js@4.2.1"},
	}
	if err := d.AddFindings(t.Context(), job.ID, findings); err != nil {
		t.Fatal(err)
	}
	got, err := d.Findings(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(findings) {
		t.Fatalf("got %d findings", len(got))
	}
	for i := range findings {
		if !proto.Equal(got[i], findings[i]) {
			t.Errorf("finding %d = %v, want %v", i, got[i], findings[i])
		}
	}
	var via string
	row := d.sql.QueryRowContext(t.Context(), "SELECT via_dependency FROM findings WHERE kind = 'new_dns_query'")
	if err := row.Scan(&via); err != nil {
		t.Fatal(err)
	}
	if via != "plain-crypto-js@4.2.1" {
		t.Errorf("via_dependency = %q", via)
	}
}

func TestAddFindingsIsAllOrNothing(t *testing.T) {
	d := openTest(t)
	job := createJob(t, d, "")
	err := d.AddFindings(t.Context(), job.ID, []*driftv1.DriftFinding{
		{Analyzer: "a", Kind: "good", Confidence: 0.5},
		{Analyzer: "a", Kind: "bad", Confidence: 7},
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	got, err := d.Findings(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("%d findings stored from a failed batch", len(got))
	}
}

func TestReports(t *testing.T) {
	d := openTest(t)
	job := createJob(t, d, "")
	if _, err := d.Report(t.Context(), job.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v before any report", err)
	}
	report := &driftv1.DriftReport{
		Pair:       &driftv1.ArtifactPair{JobId: job.ID, New: &driftv1.PackageVersion{Version: "1.0.0"}},
		Findings:   []*driftv1.DriftFinding{{Analyzer: "static-rs", Kind: "k"}},
		Score:      8.5,
		Verdict:    driftv1.Verdict_VERDICT_SUSPICIOUS,
		FiredRules: []string{"new_install_hook"},
	}
	if err := d.SaveReport(t.Context(), job.ID, report); err != nil {
		t.Fatal(err)
	}
	got, err := d.Report(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got, report) {
		t.Errorf("report = %v, want %v", got, report)
	}
	if err := d.SaveReport(t.Context(), job.ID, report); err == nil {
		t.Error("a verdict was replaced")
	}
	if err := d.SaveReport(t.Context(), job.ID+"x", report); err == nil {
		t.Error("a report was stored for an unknown job")
	}
}

func TestConcurrentWrites(t *testing.T) {
	d := openTest(t)
	job := createJob(t, d, "")
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range cap(errs) {
		wg.Go(func() {
			errs <- d.AddFindings(context.Background(), job.ID, []*driftv1.DriftFinding{{Analyzer: "a", Kind: "k"}})
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	got, err := d.Findings(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != cap(errs) {
		t.Errorf("got %d findings", len(got))
	}
}
