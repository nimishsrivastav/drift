// Command meta-go serves the metadata-signals analyzer over gRPC.
// M1 implements Info only; the signals themselves arrive in M7.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	driftv1 "github.com/nimishsrivastav/drift/gen/go/drift/v1"
	"google.golang.org/grpc"
)

const (
	analyzerName    = "meta-go"
	analyzerVersion = "0.1.0"
	defaultListen   = "0.0.0.0:50051"
)

type server struct {
	driftv1.UnimplementedAnalyzerServer
}

func (server) Info(context.Context, *driftv1.InfoRequest) (*driftv1.InfoResponse, error) {
	return &driftv1.InfoResponse{
		Name:       analyzerName,
		Version:    analyzerVersion,
		Ecosystems: []driftv1.Ecosystem{driftv1.Ecosystem_ECOSYSTEM_NPM},
	}, nil
}

func run(ctx context.Context, addr string) error {
	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	srv := grpc.NewServer()
	driftv1.RegisterAnalyzerServer(srv, server{})

	go func() {
		<-ctx.Done()
		srv.GracefulStop()
	}()

	slog.InfoContext(ctx, "serving", "analyzer", analyzerName, "addr", lis.Addr().String())
	if err := srv.Serve(lis); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	addr := os.Getenv("DRIFT_LISTEN")
	if addr == "" {
		addr = defaultListen
	}
	if err := run(ctx, addr); err != nil {
		slog.ErrorContext(ctx, "analyzer failed", "err", err)
		os.Exit(1)
	}
}
