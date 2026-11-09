package npm

import (
	"errors"
	"testing"

	"github.com/nimishsrivastav/drift/orchestrator/internal/ingest"
)

// Cases follow node-semver's documented desugaring.
func TestRangeSatisfies(t *testing.T) {
	tests := []struct {
		spec string
		in   []string
		out  []string
	}{
		{"1.2.3", []string{"1.2.3"}, []string{"1.2.4", "1.2.3-beta"}},
		{"=v1.2.3", []string{"1.2.3"}, []string{"1.2.2"}},
		{"*", []string{"0.0.0", "9.9.9"}, []string{"1.0.0-rc.1"}},
		{"", []string{"1.0.0"}, nil},
		{"x", []string{"1.0.0"}, nil},
		{"1", []string{"1.0.0", "1.9.9"}, []string{"2.0.0", "0.9.9", "2.0.0-0"}},
		{"1.2", []string{"1.2.0", "1.2.9"}, []string{"1.3.0"}},
		{"1.x", []string{"1.0.0", "1.5.0"}, []string{"2.0.0"}},
		{"1.2.x", []string{"1.2.5"}, []string{"1.3.0"}},
		{"^1.2.3", []string{"1.2.3", "1.9.0"}, []string{"1.2.2", "2.0.0", "1.5.0-beta"}},
		{"^0.2.3", []string{"0.2.3", "0.2.9"}, []string{"0.3.0"}},
		{"^0.0.3", []string{"0.0.3"}, []string{"0.0.4"}},
		{"^0.0", []string{"0.0.0", "0.0.9"}, []string{"0.1.0"}},
		{"^0.x", []string{"0.0.0", "0.9.0"}, []string{"1.0.0"}},
		{"^1.x", []string{"1.0.0", "1.9.0"}, []string{"2.0.0"}},
		{"^1.2.3-beta.2", []string{"1.2.3-beta.2", "1.2.3-beta.4", "1.2.3", "1.9.0"}, []string{"1.2.4-beta.2", "1.2.3-beta.1"}},
		{"~1.2.3", []string{"1.2.3", "1.2.9"}, []string{"1.3.0"}},
		{"~1.2", []string{"1.2.0"}, []string{"1.3.0"}},
		{"~1", []string{"1.0.0", "1.9.0"}, []string{"2.0.0"}},
		{"~0.2.3", []string{"0.2.3"}, []string{"0.3.0"}},
		{">1.2.3", []string{"1.2.4"}, []string{"1.2.3"}},
		{">1.2", []string{"1.3.0"}, []string{"1.2.9"}},
		{">1", []string{"2.0.0"}, []string{"1.9.9"}},
		{">=1.2.3", []string{"1.2.3", "5.0.0"}, []string{"1.2.2"}},
		{">= 1.2.3 < 2", []string{"1.5.0"}, []string{"2.0.0"}},
		{"<1.2", []string{"1.1.9"}, []string{"1.2.0"}},
		{"<=1.2", []string{"1.2.9"}, []string{"1.3.0"}},
		{"<=1.2.3", []string{"1.2.3"}, []string{"1.2.4"}},
		{"1.2.3 - 2.3.4", []string{"1.2.3", "2.3.4"}, []string{"2.3.5", "1.2.2"}},
		{"1.2 - 2.3", []string{"1.2.0", "2.3.9"}, []string{"2.4.0"}},
		{"1 - 2", []string{"1.0.0", "2.9.9"}, []string{"3.0.0"}},
		{"1.x || >=2.5.0 || 5.0.0 - 7.2.3", []string{"1.2.3", "2.5.0", "6.0.0"}, []string{"2.4.0"}},
		{">=1.0.0-0", []string{"1.0.0-beta", "1.0.0"}, []string{"1.0.1-beta"}},
	}
	for _, tc := range tests {
		r, err := parseRange(tc.spec)
		if err != nil {
			t.Fatalf("parseRange(%q): %v", tc.spec, err)
		}
		for _, v := range tc.in {
			if !r.satisfies(v) {
				t.Errorf("%q should satisfy %q", v, tc.spec)
			}
		}
		for _, v := range tc.out {
			if r.satisfies(v) {
				t.Errorf("%q should not satisfy %q", v, tc.spec)
			}
		}
	}
}

func TestRangeErrors(t *testing.T) {
	for _, spec := range []string{"abc", "1.2.3.4", "^1.x-beta", "1.2.3 - x.y"} {
		if _, err := parseRange(spec); err == nil {
			t.Errorf("parseRange(%q) should fail", spec)
		}
	}
}

func TestResolveDependency(t *testing.T) {
	doc := &packument{
		Name:     "dep",
		DistTags: map[string]string{"latest": "1.2.0", "next": "2.0.0-rc.1"},
		Versions: map[string]versionDoc{
			"1.0.0": {}, "1.2.0": {}, "1.3.0": {}, "2.0.0-rc.1": {}, "0.9.0": {},
		},
	}
	tests := []struct {
		spec, want string
	}{
		{"^1.0.0", "1.2.0"}, // latest satisfies, so it wins over 1.3.0
		{"~1.3", "1.3.0"},
		{"next", "2.0.0-rc.1"},
		{"", "1.2.0"},
		{"<1", "0.9.0"},
		{"1.0.0", "1.0.0"},
	}
	for _, tc := range tests {
		got, err := doc.resolveDependency("dep", tc.spec)
		if err != nil {
			t.Fatalf("resolveDependency(%q): %v", tc.spec, err)
		}
		if got.Version != tc.want {
			t.Errorf("resolveDependency(%q) = %s, want %s", tc.spec, got.Version, tc.want)
		}
	}
	for _, spec := range []string{"^3", "not a range"} {
		if _, err := doc.resolveDependency("dep", spec); !errors.Is(err, ingest.ErrVersionNotFound) {
			t.Errorf("resolveDependency(%q) = %v, want ErrVersionNotFound", spec, err)
		}
	}
}
