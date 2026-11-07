// Command drift is the local CLI.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

const (
	version = "0.1.0"
	usage   = usageAnalyze + "\n" + usageJob + "\nusage: drift version"
)

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "version":
			_, _ = fmt.Fprintln(stdout, version)
			return exitOK
		case "analyze":
			return analyze(ctx, args[1:], stdout, stderr)
		case "job":
			return showJob(ctx, args[1:], stdout, stderr)
		}
	}
	_, _ = fmt.Fprintln(stderr, usage)
	return exitUsage
}

func realMain() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The text handler quotes values, and logs can include registry and git output.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	return run(ctx, os.Args[1:], os.Stdout, os.Stderr)
}

func main() {
	os.Exit(realMain())
}
