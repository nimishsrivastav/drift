package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tmpEntries(t *testing.T, root string) []fs.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "tmp"))
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func TestPut(t *testing.T) {
	const content = "tarball bytes"
	sum := sha256.Sum256([]byte(content))
	want := hex.EncodeToString(sum[:])
	errRejected := errors.New("rejected")

	tests := []struct {
		name     string
		maxBytes int64
		verify   func(Digests) error
		wantErr  error
	}{
		{name: "stored", maxBytes: 1024},
		{name: "exactly at the limit", maxBytes: int64(len(content))},
		{name: "over the limit", maxBytes: int64(len(content)) - 1, wantErr: ErrTooLarge},
		{
			name:     "verify sees the real digest",
			maxBytes: 1024,
			verify: func(d Digests) error {
				if hex.EncodeToString(d.SHA256) != want {
					return errRejected
				}
				return nil
			},
		},
		{
			name:     "verify rejects",
			maxBytes: 1024,
			verify:   func(Digests) error { return errRejected },
			wantErr:  errRejected,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			s, err := New(root)
			if err != nil {
				t.Fatal(err)
			}
			blob, err := s.Put(strings.NewReader(content), tt.maxBytes, tt.verify)

			if len(tmpEntries(t, root)) != 0 {
				t.Error("temp file left behind")
			}
			finalPath := filepath.Join(root, "sha256", want[:2], want[2:])
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				if _, statErr := os.Stat(finalPath); !errors.Is(statErr, fs.ErrNotExist) {
					t.Errorf("rejected blob was published: %v", statErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if blob.SHA256 != want || blob.Path != finalPath || blob.Size != int64(len(content)) {
				t.Errorf("blob = %+v", blob)
			}
			info, err := os.Stat(blob.Path)
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); perm != 0o444 {
				t.Errorf("mode = %o, want 444", perm)
			}
		})
	}
}

func TestPutIsIdempotent(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.Put(strings.NewReader("same"), 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Put(strings.NewReader("same"), 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("first = %+v, second = %+v", first, second)
	}
}
