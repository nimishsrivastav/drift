package main

import (
	"bytes"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantOut  string
	}{
		{name: "version", args: []string{"version"}, wantCode: exitOK, wantOut: version + "\n"},
		{name: "no args", args: nil, wantCode: exitUsage},
		{name: "unknown command", args: []string{"nope"}, wantCode: exitUsage},
		{name: "analyze without arguments", args: []string{"analyze"}, wantCode: exitUsage},
		{name: "job without arguments", args: []string{"job"}, wantCode: exitUsage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(t.Context(), tt.args, &stdout, &stderr); got != tt.wantCode {
				t.Errorf("code = %d, want %d", got, tt.wantCode)
			}
			if stdout.String() != tt.wantOut {
				t.Errorf("stdout = %q, want %q", stdout.String(), tt.wantOut)
			}
		})
	}
}
