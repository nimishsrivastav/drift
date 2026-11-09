// Package ingest defines what an ecosystem adapter provides to the orchestrator core.
// Adding an ecosystem means adding an adapter, with no change to the job flow.
package ingest

import (
	"context"
	"errors"

	driftv1 "github.com/nimishsrivastav/drift/gen/go/drift/v1"
	"github.com/nimishsrivastav/drift/orchestrator/internal/store"
)

var (
	// ErrPackageNotFound means the registry does not know the package.
	ErrPackageNotFound = errors.New("package not found")
	// ErrVersionNotFound means the package exists but the version does not. Registries remove
	// malicious versions, so this is expected when replaying an old incident.
	ErrVersionNotFound = errors.New("version not found")
	// ErrIntegrity means a download did not match the hash the registry published.
	ErrIntegrity = errors.New("integrity check failed")
)

// Version is one resolved version of a package. Every field came from the registry, so treat
// them all as untrusted.
type Version struct {
	Name          string
	Version       string
	TarballURL    string
	Integrity     string // Subresource Integrity string
	Shasum        string // legacy SHA-1, hex
	RepositoryURL string // as declared; see the repo package for how it is checked
}

// Resolution is the pair of versions to compare. Old is nil in new-package mode.
type Resolution struct {
	Old *Version
	New Version
}

// Adapter talks to one package registry.
type Adapter interface {
	Ecosystem() driftv1.Ecosystem
	// Resolve picks the versions to compare. Empty to means the latest release, and empty
	// from means the release before to.
	Resolve(ctx context.Context, name, from, to string) (Resolution, error)
	// ResolveDependency picks the version a package manager would install for a dependency
	// declared as name with spec (a range or tag in the registry's own syntax).
	ResolveDependency(ctx context.Context, name, spec string) (Version, error)
	// Download fetches a version's artifact into the store, verifying its integrity.
	Download(ctx context.Context, v Version, s *store.Store) (store.Blob, error)
}
