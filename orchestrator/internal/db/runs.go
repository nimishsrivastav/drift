package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	driftv1 "github.com/nimishsrivastav/drift/gen/go/drift/v1"
)

// RunStatus is how one analyzer's Analyze call ended.
type RunStatus string

const (
	RunOK            RunStatus = "ok"
	RunUnimplemented RunStatus = "unimplemented"
	RunFailed        RunStatus = "failed"
)

// AnalyzerRun records one analyzer's part in a job.
type AnalyzerRun struct {
	Analyzer   string    `json:"analyzer"`
	Status     RunStatus `json:"status"`
	Error      string    `json:"error,omitempty"`
	Notes      []string  `json:"notes,omitempty"`
	Findings   int       `json:"findings"`
	DurationMS int64     `json:"duration_ms"`
}

// CompleteAnalysis stores a job's findings and analyzer runs and marks it done, all or none.
func (d *DB) CompleteAnalysis(ctx context.Context, jobID string, findings []*driftv1.DriftFinding, runs []AnalyzerRun) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := insertFindings(ctx, tx, jobID, findings); err != nil {
		return err
	}
	for _, run := range runs {
		notes, err := json.Marshal(cleanAll(run.Notes))
		if err != nil {
			return fmt.Errorf("encode notes: %w", err)
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO analyzer_runs (job_id, analyzer, status, error, notes, findings, duration_ms)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			jobID, run.Analyzer, string(run.Status), clean(run.Error), string(notes), run.Findings, max(run.DurationMS, 0))
		if err != nil {
			return fmt.Errorf("insert analyzer run: %w", err)
		}
	}
	result, err := tx.ExecContext(ctx, "UPDATE jobs SET status = ?, updated_at = ? WHERE id = ?",
		string(StatusDone), d.now().UTC().Format(timeFormat), jobID)
	if err != nil {
		return fmt.Errorf("update job %s: %w", jobID, err)
	}
	if updated, err := result.RowsAffected(); err != nil || updated == 0 {
		return fmt.Errorf("job %s: %w", jobID, ErrNotFound)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// AnalyzerRuns reads a job's analyzer runs, by analyzer name.
func (d *DB) AnalyzerRuns(ctx context.Context, jobID string) ([]AnalyzerRun, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT analyzer, status, error, notes, findings, duration_ms
		FROM analyzer_runs WHERE job_id = ? ORDER BY analyzer`, jobID)
	if err != nil {
		return nil, fmt.Errorf("read analyzer runs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var runs []AnalyzerRun
	for rows.Next() {
		var run AnalyzerRun
		var status, notes string
		if err := rows.Scan(&run.Analyzer, &status, &run.Error, &notes, &run.Findings, &run.DurationMS); err != nil {
			return nil, fmt.Errorf("read analyzer run: %w", err)
		}
		run.Status = RunStatus(status)
		if err := json.Unmarshal([]byte(notes), &run.Notes); err != nil {
			return nil, fmt.Errorf("decode notes: %w", err)
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read analyzer runs: %w", err)
	}
	return runs, nil
}

// clean caps text from an analyzer, which can quote package contents.
func clean(text string) string {
	if len(text) > maxErrorBytes {
		text = text[:maxErrorBytes] + "... (truncated)"
	}
	return strings.ToValidUTF8(text, "?")
}

func cleanAll(texts []string) []string {
	out := make([]string, 0, len(texts))
	for _, t := range texts {
		out = append(out, clean(t))
	}
	return out
}
