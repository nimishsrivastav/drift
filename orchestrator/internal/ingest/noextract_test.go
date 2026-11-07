package ingest

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The orchestrator stores artifacts as opaque blobs. Unpacking them belongs to the Rust
// analyzers (CLAUDE.md), and this keeps a convenient import from quietly changing that.
func TestOrchestratorCannotUnpackArchives(t *testing.T) {
	root := filepath.Join("..", "..") // the orchestrator module
	forbidden := []string{"archive/", "compress/"}
	checked := 0

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		checked++
		for _, spec := range file.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			for _, prefix := range forbidden {
				if strings.HasPrefix(imported, prefix) {
					t.Errorf("%s imports %s", path, imported)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Guards against a wrong root, which would otherwise pass by checking nothing.
	if checked < 5 {
		t.Fatalf("only checked %d files", checked)
	}
}
