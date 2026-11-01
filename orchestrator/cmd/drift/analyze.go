package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	driftv1 "github.com/nimishsrivastav/drift/gen/go/drift/v1"
	"github.com/nimishsrivastav/drift/orchestrator/internal/db"
	"github.com/nimishsrivastav/drift/orchestrator/internal/ingest"
	"github.com/nimishsrivastav/drift/orchestrator/internal/ingest/npm"
	"github.com/nimishsrivastav/drift/orchestrator/internal/jobs"
	"github.com/nimishsrivastav/drift/orchestrator/internal/repo"
	"github.com/nimishsrivastav/drift/orchestrator/internal/store"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	exitOK       = 0
	exitFailed   = 1
	exitUsage    = 2
	usageAnalyze = "usage: drift analyze <ecosystem> <package> [--from X] [--to Y] [--registry URL] [--data-dir DIR]"
	usageJob     = "usage: drift job <id> [--data-dir DIR]"
)

// paths is where one data directory keeps things. Analyzers get the tarballs and repos
// read-only, while the database stays private to the orchestrator, so it can move elsewhere.
type paths struct {
	tarballs, repos, database string
}

func resolvePaths(dataDir string) (paths, error) {
	if dataDir == "" {
		dataDir = os.Getenv("DRIFT_DATA_DIR")
	}
	if dataDir == "" {
		dataDir = os.Getenv("XDG_DATA_HOME")
		if dataDir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return paths{}, fmt.Errorf("find a data directory: %w", err)
			}
			dataDir = filepath.Join(home, ".local", "share")
		}
		dataDir = filepath.Join(dataDir, "drift")
	}
	database := os.Getenv("DRIFT_DB")
	if database == "" {
		database = filepath.Join(dataDir, "drift.db")
	}
	return paths{
		tarballs: filepath.Join(dataDir, "tarballs"),
		repos:    filepath.Join(dataDir, "repos"),
		database: database,
	}, nil
}

// parseInterleaved lets flags come before or after positional arguments, which the flag
// package doesn't do by itself.
func parseInterleaved(flags *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := flags.Parse(args); err != nil {
			return nil, err
		}
		args = flags.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

func parseEcosystem(name string) driftv1.Ecosystem {
	if name == "npm" {
		return driftv1.Ecosystem_ECOSYSTEM_NPM
	}
	return driftv1.Ecosystem_ECOSYSTEM_UNSPECIFIED
}

func analyze(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("analyze", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { _, _ = fmt.Fprintln(stderr, usageAnalyze) }
	from := flags.String("from", "", "old version or dist-tag (default: the release before --to)")
	to := flags.String("to", "", "new version or dist-tag (default: latest)")
	registry := flags.String("registry", npm.DefaultRegistry, "npm registry URL")
	dataDir := flags.String("data-dir", "", "data directory (default: $DRIFT_DATA_DIR or ~/.local/share/drift)")

	positional, err := parseInterleaved(flags, args)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		return exitUsage
	}
	if len(positional) != 2 {
		flags.Usage()
		return exitUsage
	}
	ecosystem := parseEcosystem(positional[0])
	if ecosystem == driftv1.Ecosystem_ECOSYSTEM_UNSPECIFIED {
		_, _ = fmt.Fprintf(stderr, "drift: unsupported ecosystem %q (supported: npm)\n", positional[0])
		return exitUsage
	}

	service, closeService, err := newService(ctx, *dataDir, *registry)
	if err != nil {
		printError(stderr, err)
		return exitFailed
	}
	defer closeService()

	job, err := service.Ingest(ctx, jobs.Request{Ecosystem: ecosystem, Package: positional[1], From: *from, To: *to})
	if err != nil {
		if job != nil {
			printError(stderr, fmt.Errorf("job %s failed: %w", job.ID, err))
		} else {
			printError(stderr, err)
		}
		return exitFailed
	}
	if err := printJob(stdout, job); err != nil {
		printError(stderr, err)
		return exitFailed
	}
	return exitOK
}

func showJob(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("job", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { _, _ = fmt.Fprintln(stderr, usageJob) }
	dataDir := flags.String("data-dir", "", "data directory")

	positional, err := parseInterleaved(flags, args)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		return exitUsage
	}
	if len(positional) != 1 {
		flags.Usage()
		return exitUsage
	}

	locations, err := resolvePaths(*dataDir)
	if err != nil {
		printError(stderr, err)
		return exitFailed
	}
	database, err := db.Open(ctx, locations.database)
	if err != nil {
		printError(stderr, err)
		return exitFailed
	}
	defer func() { _ = database.Close() }()

	job, err := database.GetJob(ctx, positional[0])
	if err != nil {
		printError(stderr, err)
		return exitFailed
	}
	if err := printJob(stdout, job); err != nil {
		printError(stderr, err)
		return exitFailed
	}
	return exitOK
}

func newService(ctx context.Context, dataDir, registry string) (*jobs.Service, func(), error) {
	locations, err := resolvePaths(dataDir)
	if err != nil {
		return nil, nil, err
	}
	adapter, err := npm.New(registry)
	if err != nil {
		return nil, nil, err
	}
	blobs, err := store.New(locations.tarballs)
	if err != nil {
		return nil, nil, err
	}
	repos, err := repo.New(locations.repos)
	if err != nil {
		return nil, nil, err
	}
	database, err := db.Open(ctx, locations.database)
	if err != nil {
		return nil, nil, err
	}
	service := &jobs.Service{
		DB:       database,
		Store:    blobs,
		Repos:    repos,
		Adapters: map[driftv1.Ecosystem]ingest.Adapter{adapter.Ecosystem(): adapter},
	}
	return service, func() { _ = database.Close() }, nil
}

type jobOutput struct {
	JobID       string          `json:"job_id"`
	ParentJobID string          `json:"parent_job_id,omitempty"`
	Depth       uint32          `json:"depth"`
	Ecosystem   string          `json:"ecosystem"`
	Package     string          `json:"package"`
	Status      db.Status       `json:"status"`
	Error       string          `json:"error,omitempty"`
	Pair        json.RawMessage `json:"pair,omitempty"`
}

// printJob writes one job as JSON. Unusual characters in registry data arrive escaped, so
// they can't act on a terminal.
func printJob(w io.Writer, job *db.Job) error {
	output := jobOutput{
		JobID:       job.ID,
		ParentJobID: job.ParentJobID,
		Depth:       job.Depth,
		Ecosystem:   job.Ecosystem.String(),
		Package:     job.Package,
		Status:      job.Status,
		Error:       job.Error,
	}
	if job.Pair != nil {
		encoded, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(job.Pair)
		if err != nil {
			return fmt.Errorf("encode artifact pair: %w", err)
		}
		output.Pair = encoded
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		return fmt.Errorf("write job: %w", err)
	}
	return nil
}

// printError writes an error for a person to read. Errors can quote registry and git output,
// which could otherwise carry escape sequences to the terminal.
func printError(w io.Writer, err error) {
	clean := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, err.Error())
	_, _ = fmt.Fprintln(w, "drift:", clean)
}
