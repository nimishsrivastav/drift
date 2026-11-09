package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

const fixture = "drift-fixture-install-hook"

func fixturesDir() string {
	return filepath.Join("..", "..", "fixtures", "npm")
}

func get(t *testing.T, srv *httptest.Server, p string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+p, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

func TestServesPackumentsAndMatchingTarballs(t *testing.T) {
	reg, err := load(fixturesDir(), "http://fixtures.test")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(reg)
	t.Cleanup(srv.Close)

	resp, body := get(t, srv, "/"+fixture)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("packument: %s", resp.Status)
	}
	var doc struct {
		DistTags map[string]string `json:"dist-tags"`
		Versions map[string]struct {
			Dist struct {
				Tarball   string `json:"tarball"`
				Integrity string `json:"integrity"`
			} `json:"dist"`
		} `json:"versions"`
		Time map[string]string `json:"time"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.DistTags["latest"] != "1.0.1" || len(doc.Versions) != 2 || doc.Time["1.0.0"] >= doc.Time["1.0.1"] {
		t.Fatalf("packument = %s", body)
	}
	for v, meta := range doc.Versions {
		p := strings.TrimPrefix(meta.Dist.Tarball, "http://fixtures.test")
		resp, tarball := get(t, srv, p)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s tarball: %s", v, resp.Status)
		}
		sum := sha512.Sum512(tarball)
		if meta.Dist.Integrity != "sha512-"+base64.StdEncoding.EncodeToString(sum[:]) {
			t.Errorf("%s: integrity does not match the served tarball", v)
		}
	}
}

func TestPackIsReproducible(t *testing.T) {
	dir := filepath.Join(fixturesDir(), fixture, "1.0.1")
	a, err := pack(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := pack(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("packing twice gave different bytes")
	}
}

func TestOnlyServesWhatItHas(t *testing.T) {
	reg, err := load(fixturesDir(), "http://fixtures.test")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(reg)
	t.Cleanup(srv.Close)
	for _, p := range []string{"/", "/missing", "/" + fixture + "/repo", "/../../etc/passwd"} {
		if resp, _ := get(t, srv, p); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %s, want 404", p, resp.Status)
		}
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, srv.URL+"/"+fixture, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT: %s", resp.Status)
	}
}
