package registry

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	driftv1 "github.com/nimishsrivastav/drift/gen/go/drift/v1"
	"google.golang.org/grpc"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr string
	}{
		{name: "valid", input: "analyzers:\n  - {name: a, endpoint: 'a:1'}\n  - {name: b, endpoint: 'b:1'}\n", want: 2},
		{name: "empty", input: "analyzers: []\n", wantErr: "no analyzers"},
		{name: "missing endpoint", input: "analyzers:\n  - {name: a}\n", wantErr: "required"},
		{name: "duplicate", input: "analyzers:\n  - {name: a, endpoint: 'a:1'}\n  - {name: a, endpoint: 'b:1'}\n", wantErr: "twice"},
		{name: "not yaml", input: "analyzers: [", wantErr: "parse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parse([]byte(tt.input))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(got) != tt.want {
				t.Errorf("got %d analyzers, want %d", len(got), tt.want)
			}
		})
	}
}

type fakeAnalyzer struct {
	driftv1.UnimplementedAnalyzerServer
}

func (fakeAnalyzer) Info(context.Context, *driftv1.InfoRequest) (*driftv1.InfoResponse, error) {
	return &driftv1.InfoResponse{
		Name:       "fake",
		Version:    "9.9.9",
		Ecosystems: []driftv1.Ecosystem{driftv1.Ecosystem_ECOSYSTEM_NPM},
	}, nil
}

func startFake(t *testing.T) string {
	t.Helper()
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	driftv1.RegisterAnalyzerServer(srv, fakeAnalyzer{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

// Not parallel: it swaps the default slog logger.
func TestDiscoverLogsInfoResponse(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := Discover(ctx, []Analyzer{{Name: "fake", Endpoint: startFake(t)}}, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	for _, want := range []string{"analyzer info", "version=9.9.9", "ECOSYSTEM_NPM"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("log %q does not contain %q", buf.String(), want)
		}
	}
}

func TestDiscoverReportsAnalyzerThatNeverAnswers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Port 1 on localhost refuses connections.
	err := Discover(ctx, []Analyzer{{Name: "gone", Endpoint: "127.0.0.1:1"}}, 10*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "gone") {
		t.Fatalf("err = %v, want it to name the analyzer", err)
	}
}
