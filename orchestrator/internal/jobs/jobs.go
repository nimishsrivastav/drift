// Package jobs runs the orchestrator's job flow. So far that is ingest: resolve the versions,
// fetch their artifacts and source, and store the resulting ArtifactPair.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	driftv1 "github.com/nimishsrivastav/drift/gen/go/drift/v1"
	"github.com/nimishsrivastav/drift/orchestrator/internal/db"
	"github.com/nimishsrivastav/drift/orchestrator/internal/ingest"
	"github.com/nimishsrivastav/drift/orchestrator/internal/repo"
	"github.com/nimishsrivastav/drift/orchestrator/internal/store"
)

// ErrUnsupportedEcosystem means no adapter is registered for the requested ecosystem.
var ErrUnsupportedEcosystem = errors.New("unsupported ecosystem")

// RepoResolver finds a version's source. repo.Resolver implements it.
type RepoResolver interface {
	Resolve(ctx context.Context, rawURL, name, version string) (repo.Checkout, error)
}

// Service runs jobs.
type Service struct {
	DB       *db.DB
	Store    *store.Store
	Repos    RepoResolver
	Adapters map[driftv1.Ecosystem]ingest.Adapter
}

// Request asks for one package to be ingested. Empty From and To mean the adapter's defaults.
type Request struct {
	ParentJobID string
	Ecosystem   driftv1.Ecosystem
	Package     string
	From        string
	To          string
}

// Ingest creates a job and ingests it. Once the job exists it is always returned, even on
// error, and a failed job holds the reason.
func (s *Service) Ingest(ctx context.Context, req Request) (*db.Job, error) {
	adapter, ok := s.Adapters[req.Ecosystem]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedEcosystem, req.Ecosystem)
	}
	job, err := s.DB.CreateJob(ctx, db.NewJob{
		ParentJobID:   req.ParentJobID,
		Ecosystem:     req.Ecosystem,
		Package:       req.Package,
		RequestedFrom: req.From,
		RequestedTo:   req.To,
	})
	if err != nil {
		return nil, err
	}

	if err := s.run(ctx, adapter, job, req); err != nil {
		// The reason must be recorded even if ctx is why the job failed.
		recordCtx := context.WithoutCancel(ctx)
		if failErr := s.DB.FailJob(recordCtx, job.ID, err.Error()); failErr != nil {
			return job, errors.Join(err, failErr)
		}
		if stored, getErr := s.DB.GetJob(recordCtx, job.ID); getErr == nil {
			job = stored
		}
		return job, err
	}
	return s.DB.GetJob(ctx, job.ID)
}

func (s *Service) run(ctx context.Context, adapter ingest.Adapter, job *db.Job, req Request) error {
	if err := s.DB.SetStatus(ctx, job.ID, db.StatusIngesting); err != nil {
		return err
	}
	resolution, err := adapter.Resolve(ctx, req.Package, req.From, req.To)
	if err != nil {
		return err
	}

	pair := &driftv1.ArtifactPair{JobId: job.ID, ParentJobId: job.ParentJobID, Depth: job.Depth}
	if resolution.Old != nil {
		if pair.Old, err = s.fetch(ctx, adapter, *resolution.Old); err != nil {
			return err
		}
	}
	if pair.New, err = s.fetch(ctx, adapter, resolution.New); err != nil {
		return err
	}
	return s.DB.CompleteIngest(ctx, job.ID, pair)
}

// fetch gets one version's tarball and source. A missing tarball is fatal, because there is
// nothing to analyze. Missing source is not: many releases have no tag, and analyzers are told
// by repo_ref that the comparison isn't available.
func (s *Service) fetch(ctx context.Context, adapter ingest.Adapter, v ingest.Version) (*driftv1.PackageVersion, error) {
	blob, err := adapter.Download(ctx, v, s.Store)
	if err != nil {
		return nil, err
	}
	result := &driftv1.PackageVersion{
		Ecosystem:     adapter.Ecosystem(),
		Name:          v.Name,
		Version:       v.Version,
		TarballPath:   blob.Path,
		TarballSha256: blob.SHA256,
		RepoRef:       repo.Unresolved,
	}
	if v.RepositoryURL == "" {
		slog.WarnContext(ctx, "repository unresolved", "package", v.Name, "version", v.Version, "reason", "none declared")
		return result, nil
	}
	checkout, err := s.Repos.Resolve(ctx, v.RepositoryURL, v.Name, v.Version)
	if err != nil {
		// Being cancelled says nothing about the repository, so it must not read as "no tag".
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		slog.WarnContext(ctx, "repository unresolved", "package", v.Name, "version", v.Version, "reason", err.Error())
		return result, nil
	}
	result.RepoPath = checkout.Path
	result.RepoRef = checkout.Ref
	slog.InfoContext(ctx, "repository resolved", "package", v.Name, "version", v.Version, "ref", checkout.Ref, "commit", checkout.Commit)
	return result, nil
}
