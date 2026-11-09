// Package registry loads the configured analyzers and asks each one what it is.
package registry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	driftv1 "github.com/nimishsrivastav/drift/gen/go/drift/v1"
	"go.yaml.in/yaml/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Roles. A scorer answers Info like an analyzer but is never sent Analyze.
const (
	RoleAnalyzer = "analyzer"
	RoleScorer   = "scorer"
)

// Analyzer is one configured analyzer endpoint.
type Analyzer struct {
	Name     string `yaml:"name"`
	Endpoint string `yaml:"endpoint"`
	// Role is RoleAnalyzer (the default) or RoleScorer.
	Role string `yaml:"role"`
}

// Analyzers returns the entries that should be sent Analyze.
func Analyzers(all []Analyzer) []Analyzer {
	var out []Analyzer
	for _, a := range all {
		if a.Role == RoleAnalyzer {
			out = append(out, a)
		}
	}
	return out
}

type config struct {
	Analyzers []Analyzer `yaml:"analyzers"`
}

// Load reads and validates the analyzer config file.
func Load(path string) ([]Analyzer, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is operator configuration
	if err != nil {
		return nil, fmt.Errorf("read analyzer config: %w", err)
	}
	return parse(data)
}

func parse(data []byte) ([]Analyzer, error) {
	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse analyzer config: %w", err)
	}
	if len(cfg.Analyzers) == 0 {
		return nil, errors.New("analyzer config lists no analyzers")
	}
	seen := make(map[string]bool, len(cfg.Analyzers))
	for i, a := range cfg.Analyzers {
		if a.Name == "" || a.Endpoint == "" {
			return nil, fmt.Errorf("analyzer %d: name and endpoint are required", i)
		}
		if seen[a.Name] {
			return nil, fmt.Errorf("analyzer %q is listed twice", a.Name)
		}
		seen[a.Name] = true
		switch a.Role {
		case "":
			cfg.Analyzers[i].Role = RoleAnalyzer
		case RoleAnalyzer, RoleScorer:
		default:
			return nil, fmt.Errorf("analyzer %q: unknown role %q", a.Name, a.Role)
		}
	}
	return cfg.Analyzers, nil
}

// Discover calls Info on every analyzer, retrying each until it answers or ctx ends,
// and logs each response. It returns an error naming every analyzer that never answered.
func Discover(ctx context.Context, analyzers []Analyzer, retryEvery time.Duration) error {
	errs := make(chan error, len(analyzers))
	for _, a := range analyzers {
		go func() { errs <- discoverOne(ctx, a, retryEvery) }()
	}
	var all []error
	for range analyzers {
		if err := <-errs; err != nil {
			all = append(all, err)
		}
	}
	return errors.Join(all...)
}

func discoverOne(ctx context.Context, a Analyzer, retryEvery time.Duration) error {
	// Analyzers talk over the private compose network; see docs/DECISIONS.md.
	conn, err := grpc.NewClient(a.Endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("analyzer %s: %w", a.Name, err)
	}
	defer func() { _ = conn.Close() }()
	client := driftv1.NewAnalyzerClient(conn)

	for {
		info, err := client.Info(ctx, &driftv1.InfoRequest{})
		if err == nil {
			ecosystems := make([]string, 0, len(info.GetEcosystems()))
			for _, e := range info.GetEcosystems() {
				ecosystems = append(ecosystems, e.String())
			}
			slog.InfoContext(ctx, "analyzer info",
				"analyzer", a.Name,
				"endpoint", a.Endpoint,
				"name", info.GetName(),
				"version", info.GetVersion(),
				"ecosystems", ecosystems,
			)
			return nil
		}
		slog.DebugContext(ctx, "analyzer not ready", "analyzer", a.Name, "err", err)

		select {
		case <-ctx.Done():
			return fmt.Errorf("analyzer %s never answered Info: %w", a.Name, err)
		case <-time.After(retryEvery):
		}
	}
}
