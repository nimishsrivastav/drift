// Package store keeps downloaded artifacts in a content-addressed directory.
//
// Blobs are opaque here. Nothing in this package, or anywhere in the orchestrator, unpacks
// them: parsing attacker-controlled archives belongs to the Rust analyzers (CLAUDE.md).
package store

import (
	"crypto/sha1" //nolint:gosec // legacy npm shasum support, checked alongside stronger hashes
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ErrTooLarge means a blob went over the size limit passed to Put.
var ErrTooLarge = errors.New("blob exceeds size limit")

// Digests are the hashes of a blob, computed while it is written.
type Digests struct {
	SHA1   []byte
	SHA256 []byte
	SHA512 []byte
}

// Blob is a stored artifact.
type Blob struct {
	Path   string
	SHA256 string
	Size   int64
}

// Store is a content-addressed directory, laid out as <root>/sha256/<aa>/<rest of hash>.
type Store struct {
	root string
}

// New creates the store's directories if needed.
func New(root string) (*Store, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve store root: %w", err)
	}
	for _, dir := range []string{filepath.Join(abs, "sha256"), filepath.Join(abs, "tmp")} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("create store directory: %w", err)
		}
	}
	return &Store{root: abs}, nil
}

// Put streams r into the store. The blob only becomes visible under its hash after it fits
// within maxBytes and verify accepts its digests, so a failed download leaves nothing behind.
func (s *Store) Put(r io.Reader, maxBytes int64, verify func(Digests) error) (Blob, error) {
	tmp, err := os.CreateTemp(filepath.Join(s.root, "tmp"), "blob-*")
	if err != nil {
		return Blob{}, fmt.Errorf("create temp blob: %w", err)
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()

	sha1Hash := sha1.New() //nolint:gosec // see the import comment
	sha256Hash := sha256.New()
	sha512Hash := sha512.New()
	writer := io.MultiWriter(tmp, sha1Hash, sha256Hash, sha512Hash)

	// One extra byte tells "exactly at the limit" apart from "over it".
	size, err := io.Copy(writer, io.LimitReader(r, maxBytes+1))
	if err != nil {
		return Blob{}, fmt.Errorf("write blob: %w", err)
	}
	if size > maxBytes {
		return Blob{}, fmt.Errorf("%w of %d bytes", ErrTooLarge, maxBytes)
	}
	digests := Digests{SHA1: sha1Hash.Sum(nil), SHA256: sha256Hash.Sum(nil), SHA512: sha512Hash.Sum(nil)}
	if verify != nil {
		if err := verify(digests); err != nil {
			return Blob{}, err
		}
	}

	if err := tmp.Sync(); err != nil {
		return Blob{}, fmt.Errorf("sync blob: %w", err)
	}
	if err := tmp.Chmod(0o444); err != nil {
		return Blob{}, fmt.Errorf("mark blob read-only: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return Blob{}, fmt.Errorf("close blob: %w", err)
	}

	hash := hex.EncodeToString(digests.SHA256)
	path := s.path(hash)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return Blob{}, fmt.Errorf("create blob directory: %w", err)
	}
	// Same hash means same bytes, so replacing an existing blob is harmless.
	if err := os.Rename(tmp.Name(), path); err != nil {
		return Blob{}, fmt.Errorf("publish blob: %w", err)
	}
	return Blob{Path: path, SHA256: hash, Size: size}, nil
}

func (s *Store) path(hash string) string {
	return filepath.Join(s.root, "sha256", hash[:2], hash[2:])
}
