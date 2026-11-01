package main

import (
	"context"
	"slices"
	"testing"

	driftv1 "github.com/nimishsrivastav/drift/gen/go/drift/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestInfo(t *testing.T) {
	got, err := server{}.Info(context.Background(), &driftv1.InfoRequest{})
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if got.GetName() != "meta-go" {
		t.Errorf("name = %q, want meta-go", got.GetName())
	}
	if got.GetVersion() == "" {
		t.Error("version is empty")
	}
	if !slices.Contains(got.GetEcosystems(), driftv1.Ecosystem_ECOSYSTEM_NPM) {
		t.Errorf("ecosystems = %v, want npm", got.GetEcosystems())
	}
}

func TestAnalyzeNotImplementedYet(t *testing.T) {
	_, err := server{}.Analyze(context.Background(), &driftv1.ArtifactPair{})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("code = %v, want Unimplemented", status.Code(err))
	}
}
