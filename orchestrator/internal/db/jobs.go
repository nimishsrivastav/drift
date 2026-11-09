package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	driftv1 "github.com/nimishsrivastav/drift/gen/go/drift/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Status is where a job is in its lifecycle.
type Status string

const (
	StatusPending   Status = "pending"
	StatusIngesting Status = "ingesting"
	StatusIngested  Status = "ingested"
	StatusAnalyzing Status = "analyzing"
	StatusDone      Status = "done"
	StatusFailed    Status = "failed"
)

// maxErrorBytes caps a stored error, which can quote remote or registry output.
const maxErrorBytes = 4096

const timeFormat = time.RFC3339Nano

// NewJob is what a caller asks for. Depth is not part of it: it follows from the parent.
type NewJob struct {
	ParentJobID   string
	Ecosystem     driftv1.Ecosystem
	Package       string
	RequestedFrom string
	RequestedTo   string
}

// Job is a stored job. Pair is nil until ingest completes.
type Job struct {
	ID            string
	ParentJobID   string
	Depth         uint32
	Ecosystem     driftv1.Ecosystem
	Package       string
	RequestedFrom string
	RequestedTo   string
	Status        Status
	Pair          *driftv1.ArtifactPair
	Error         string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// CreateJob stores a pending job. A sub-job's depth is its parent's plus one.
func (d *DB) CreateJob(ctx context.Context, job NewJob) (*Job, error) {
	if job.Package == "" || job.Ecosystem == driftv1.Ecosystem_ECOSYSTEM_UNSPECIFIED {
		return nil, errors.New("job needs an ecosystem and a package")
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	now := d.now().UTC().Format(timeFormat)

	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var depth uint32
	parent := sql.NullString{}
	if job.ParentJobID != "" {
		parent = sql.NullString{String: job.ParentJobID, Valid: true}
		err := tx.QueryRowContext(ctx, "SELECT depth FROM jobs WHERE id = ?", job.ParentJobID).Scan(&depth)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("parent job %s: %w", job.ParentJobID, ErrNotFound)
		}
		if err != nil {
			return nil, fmt.Errorf("read parent job: %w", err)
		}
		depth++
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO jobs (id, parent_job_id, depth, ecosystem, package, requested_from, requested_to, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, parent, depth, job.Ecosystem.String(), job.Package, job.RequestedFrom, job.RequestedTo, now, now)
	if err != nil {
		return nil, fmt.Errorf("insert job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return d.GetJob(ctx, id)
}

// GetJob reads one job.
func (d *DB) GetJob(ctx context.Context, id string) (*Job, error) {
	var (
		job                  = Job{ID: id}
		parent, pair         sql.NullString
		ecosystem, status    string
		createdAt, updatedAt string
	)
	err := d.sql.QueryRowContext(ctx, `
		SELECT parent_job_id, depth, ecosystem, package, requested_from, requested_to,
		       status, artifact_pair, error, created_at, updated_at
		FROM jobs WHERE id = ?`, id).Scan(
		&parent, &job.Depth, &ecosystem, &job.Package, &job.RequestedFrom, &job.RequestedTo,
		&status, &pair, &job.Error, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("job %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("read job %s: %w", id, err)
	}
	job.ParentJobID = parent.String
	job.Status = Status(status)
	job.Ecosystem = driftv1.Ecosystem(driftv1.Ecosystem_value[ecosystem])
	if job.CreatedAt, err = time.Parse(timeFormat, createdAt); err != nil {
		return nil, fmt.Errorf("job %s created_at: %w", id, err)
	}
	if job.UpdatedAt, err = time.Parse(timeFormat, updatedAt); err != nil {
		return nil, fmt.Errorf("job %s updated_at: %w", id, err)
	}
	if pair.Valid {
		job.Pair = &driftv1.ArtifactPair{}
		if err := unmarshal(pair.String, job.Pair); err != nil {
			return nil, fmt.Errorf("job %s artifact pair: %w", id, err)
		}
	}
	return &job, nil
}

// CachedDependency finds the latest finished new-package analysis of one version, for reuse
// by dependency expansion. Only jobs at maxDepth or shallower qualify, because a deeper job
// expanded fewer levels of its own dependencies.
func (d *DB) CachedDependency(ctx context.Context, ecosystem driftv1.Ecosystem, name, version string, maxDepth uint32) (*Job, error) {
	var id string
	err := d.sql.QueryRowContext(ctx, `
		SELECT id FROM jobs
		WHERE ecosystem = ? AND package = ? AND new_version = ? AND old_version IS NULL
		  AND status = ? AND depth <= ?
		ORDER BY updated_at DESC LIMIT 1`,
		ecosystem.String(), name, version, string(StatusDone), maxDepth).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("cached analysis of %s@%s: %w", name, version, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("find cached analysis: %w", err)
	}
	return d.GetJob(ctx, id)
}

// SubJobs lists the IDs of a job's dependency sub-jobs, oldest first.
func (d *DB) SubJobs(ctx context.Context, parentID string) ([]string, error) {
	rows, err := d.sql.QueryContext(ctx,
		"SELECT id FROM jobs WHERE parent_job_id = ? ORDER BY created_at, id", parentID)
	if err != nil {
		return nil, fmt.Errorf("read sub-jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("read sub-job: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read sub-jobs: %w", err)
	}
	return ids, nil
}

// SetStatus moves a job to a new status.
func (d *DB) SetStatus(ctx context.Context, id string, status Status) error {
	return d.updateJob(ctx, id, "UPDATE jobs SET status = ?, updated_at = ? WHERE id = ?", string(status))
}

// CompleteIngest stores the resolved pair and marks the job ingested.
func (d *DB) CompleteIngest(ctx context.Context, id string, pair *driftv1.ArtifactPair) error {
	if pair.GetJobId() != id {
		return fmt.Errorf("artifact pair belongs to job %q, not %q", pair.GetJobId(), id)
	}
	if pair.GetNew().GetVersion() == "" {
		return errors.New("artifact pair has no new version")
	}
	encoded, err := marshal(pair)
	if err != nil {
		return fmt.Errorf("encode artifact pair: %w", err)
	}
	oldVersion := sql.NullString{}
	if pair.GetOld() != nil {
		oldVersion = sql.NullString{String: pair.GetOld().GetVersion(), Valid: true}
	}
	return d.updateJob(ctx, id,
		"UPDATE jobs SET status = ?, artifact_pair = ?, old_version = ?, new_version = ?, updated_at = ? WHERE id = ?",
		string(StatusIngested), encoded, oldVersion, pair.GetNew().GetVersion())
}

// FailJob marks a job failed and records why.
func (d *DB) FailJob(ctx context.Context, id, reason string) error {
	if len(reason) > maxErrorBytes {
		reason = reason[:maxErrorBytes] + "... (truncated)"
	}
	return d.updateJob(ctx, id, "UPDATE jobs SET status = ?, error = ?, updated_at = ? WHERE id = ?",
		string(StatusFailed), strings.ToValidUTF8(reason, "?"))
}

// updateJob runs an UPDATE whose last two parameters are updated_at and id.
func (d *DB) updateJob(ctx context.Context, id, query string, values ...any) error {
	args := append(values, d.now().UTC().Format(timeFormat), id)
	result, err := d.sql.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update job %s: %w", id, err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update job %s: %w", id, err)
	}
	if updated == 0 {
		return fmt.Errorf("job %s: %w", id, ErrNotFound)
	}
	return nil
}

// AddFindings stores a job's findings, all or none.
func (d *DB) AddFindings(ctx context.Context, jobID string, findings []*driftv1.DriftFinding) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := insertFindings(ctx, tx, jobID, findings); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func insertFindings(ctx context.Context, tx *sql.Tx, jobID string, findings []*driftv1.DriftFinding) error {
	for _, finding := range findings {
		encoded, err := marshal(finding)
		if err != nil {
			return fmt.Errorf("encode finding: %w", err)
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO findings (job_id, analyzer, kind, capability, context, confidence, via_dependency, finding)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			jobID, finding.GetAnalyzer(), finding.GetKind(), finding.GetCapability().String(),
			finding.GetContext().String(), finding.GetConfidence(), finding.GetViaDependency(), encoded)
		if err != nil {
			return fmt.Errorf("insert finding: %w", err)
		}
	}
	return nil
}

// Findings reads a job's findings in the order they were added.
func (d *DB) Findings(ctx context.Context, jobID string) ([]*driftv1.DriftFinding, error) {
	rows, err := d.sql.QueryContext(ctx, "SELECT finding FROM findings WHERE job_id = ? ORDER BY id", jobID)
	if err != nil {
		return nil, fmt.Errorf("read findings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var findings []*driftv1.DriftFinding
	for rows.Next() {
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			return nil, fmt.Errorf("read finding: %w", err)
		}
		finding := &driftv1.DriftFinding{}
		if err := unmarshal(encoded, finding); err != nil {
			return nil, fmt.Errorf("decode finding: %w", err)
		}
		findings = append(findings, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read findings: %w", err)
	}
	return findings, nil
}

// SaveReport stores a job's report. A job has one: tuning runs create new jobs, so that an
// earlier verdict is never silently replaced.
func (d *DB) SaveReport(ctx context.Context, jobID string, report *driftv1.DriftReport) error {
	encoded, err := marshal(report)
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	_, err = d.sql.ExecContext(ctx, `
		INSERT INTO reports (job_id, score, verdict, explanation, report, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		jobID, report.GetScore(), report.GetVerdict().String(), report.GetExplanation(), encoded,
		d.now().UTC().Format(timeFormat))
	if err != nil {
		return fmt.Errorf("insert report: %w", err)
	}
	return nil
}

// Report reads a job's report.
func (d *DB) Report(ctx context.Context, jobID string) (*driftv1.DriftReport, error) {
	var encoded string
	err := d.sql.QueryRowContext(ctx, "SELECT report FROM reports WHERE job_id = ?", jobID).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("report for job %s: %w", jobID, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("read report: %w", err)
	}
	report := &driftv1.DriftReport{}
	if err := unmarshal(encoded, report); err != nil {
		return nil, fmt.Errorf("decode report: %w", err)
	}
	return report, nil
}

func newID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate job id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func marshal(message proto.Message) (string, error) {
	encoded, err := protojson.Marshal(message)
	return string(encoded), err
}

// unmarshal tolerates unknown fields, so that rows written by a newer build stay readable.
func unmarshal(encoded string, message proto.Message) error {
	return protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal([]byte(encoded), message)
}
