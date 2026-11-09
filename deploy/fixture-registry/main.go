// Command fixture-registry serves the synthetic fixtures in fixtures/npm as a minimal npm
// registry, so a fixture "incident" can be replayed end to end through drift analyze. It packs
// each fixture version into a tarball at startup and serves only GET requests for packuments
// and those tarballs. It never runs, installs or unpacks anything.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1" //nolint:gosec // npm's legacy shasum field is SHA-1
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

// versionDir is what a version directory must be called; anything else (like repo/) is skipped.
var versionDir = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// epoch dates the first fixture version; later versions are a day apart, in name order.
var epoch = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

type registry struct {
	packuments map[string][]byte
	tarballs   map[string][]byte // by URL path
}

// load packs every fixture package under dir. Tarball URLs point at baseURL.
func load(dir, baseURL string) (*registry, error) {
	reg := &registry{packuments: map[string][]byte{}, tarballs: map[string][]byte{}}
	packages, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, pkg := range packages {
		if !pkg.IsDir() {
			continue
		}
		if err := reg.addPackage(filepath.Join(dir, pkg.Name()), pkg.Name(), strings.TrimRight(baseURL, "/")); err != nil {
			return nil, fmt.Errorf("%s: %w", pkg.Name(), err)
		}
	}
	if len(reg.packuments) == 0 {
		return nil, errors.New("no fixture packages found")
	}
	return reg, nil
}

func (r *registry) addPackage(dir, name, baseURL string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var versions []string
	for _, e := range entries {
		if e.IsDir() && versionDir.MatchString(e.Name()) {
			versions = append(versions, e.Name())
		}
	}
	if len(versions) == 0 {
		return errors.New("no version directories")
	}
	sort.Strings(versions)

	docs := map[string]any{}
	times := map[string]string{}
	for i, v := range versions {
		tarball, err := pack(filepath.Join(dir, v))
		if err != nil {
			return fmt.Errorf("pack %s: %w", v, err)
		}
		urlPath := fmt.Sprintf("/%s/-/%s-%s.tgz", name, name, v)
		r.tarballs[urlPath] = tarball
		sha512Sum := sha512.Sum512(tarball)
		sha1Sum := sha1.Sum(tarball) //nolint:gosec // see import
		docs[v] = map[string]any{
			"name":    name,
			"version": v,
			"dist": map[string]string{
				"tarball":   baseURL + urlPath,
				"integrity": "sha512-" + base64.StdEncoding.EncodeToString(sha512Sum[:]),
				"shasum":    hex.EncodeToString(sha1Sum[:]),
			},
		}
		times[v] = epoch.AddDate(0, 0, i).Format(time.RFC3339)
	}
	packument, err := json.Marshal(map[string]any{
		"name":      name,
		"dist-tags": map[string]string{"latest": versions[len(versions)-1]},
		"versions":  docs,
		"time":      times,
	})
	if err != nil {
		return err
	}
	r.packuments["/"+name] = packument
	return nil
}

// pack builds a gzipped tarball of dir's regular files under package/, reproducibly: sorted
// names, fixed times, owners and modes. Links and other special files are skipped.
func pack(dir string) ([]byte, error) {
	var names []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return err
			}
			names = append(names, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(names)

	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(gz)
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name))) //nolint:gosec // names come from walking dir itself
		if err != nil {
			return nil, err
		}
		header := &tar.Header{
			Name:     path.Join("package", name),
			Mode:     0o644,
			Size:     int64(len(data)),
			ModTime:  epoch,
			Typeflag: tar.TypeReg,
			Format:   tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (r *registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if doc, ok := r.packuments[req.URL.Path]; ok {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
		return
	}
	if tarball, ok := r.tarballs[req.URL.Path]; ok {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(tarball)
		return
	}
	http.NotFound(w, req)
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func run(ctx context.Context) error {
	dir := env("FIXTURES_DIR", "/fixtures/npm")
	listen := env("LISTEN", "0.0.0.0:8080")
	baseURL := env("BASE_URL", "http://fixture-registry:8080")

	reg, err := load(dir, baseURL)
	if err != nil {
		return err
	}
	for name := range reg.packuments {
		slog.InfoContext(ctx, "serving fixture", "package", strings.TrimPrefix(name, "/"))
	}
	server := &http.Server{Addr: listen, Handler: reg, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	slog.InfoContext(ctx, "listening", "addr", listen, "base_url", baseURL)
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		slog.ErrorContext(ctx, "fixture registry failed", "err", err)
		os.Exit(1)
	}
}
