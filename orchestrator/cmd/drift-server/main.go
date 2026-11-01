// Command drift-server runs the orchestrator. M1 only discovers the configured
// analyzers and logs each one's Info; jobs and the API arrive in later milestones.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nimishsrivastav/drift/orchestrator/internal/registry"
)

const (
	defaultConfig = "orchestrator/config/analyzers.yaml"
	startupBudget = 60 * time.Second
	retryEvery    = time.Second
)

func run(ctx context.Context, configPath string) error {
	analyzers, err := registry.Load(configPath)
	if err != nil {
		return err
	}

	discoverCtx, cancel := context.WithTimeout(ctx, startupBudget)
	defer cancel()
	if err := registry.Discover(discoverCtx, analyzers, retryEvery); err != nil {
		return err
	}
	slog.InfoContext(ctx, "all analyzers ready", "count", len(analyzers))

	<-ctx.Done()
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	configPath := os.Getenv("DRIFT_ANALYZERS_CONFIG")
	if configPath == "" {
		configPath = defaultConfig
	}
	if err := run(ctx, configPath); err != nil {
		slog.ErrorContext(ctx, "orchestrator failed", "err", err)
		os.Exit(1)
	}
}
