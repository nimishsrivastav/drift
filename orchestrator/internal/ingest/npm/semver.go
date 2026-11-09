package npm

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

// npm version ranges, as node-semver reads them: a range set is ranges joined by "||", a range
// is comparators joined by spaces (all must hold), and tilde, caret, X and hyphen ranges are
// sugar for pairs of comparators. A prerelease only satisfies a range that names a prerelease
// of the same major.minor.patch.

type comparator struct {
	op      string // one of ">", ">=", "<", "<=", "="
	version string // canonical, with the "v" prefix x/mod/semver wants
}

type versionRange [][]comparator

// partial is a version that may stop early or use wildcards: "1", "1.2", "1.x", "*".
type partial struct {
	major, minor, patch int
	// parts is how many leading numbers were given before a wildcard or the end.
	parts      int
	prerelease string
}

func (p partial) String() string {
	v := fmt.Sprintf("v%d.%d.%d", p.major, p.minor, p.patch)
	if p.prerelease != "" {
		v += "-" + p.prerelease
	}
	return v
}

func version3(major, minor, patch int, prerelease string) string {
	return partial{major: major, minor: minor, patch: patch, prerelease: prerelease}.String()
}

func parsePartial(raw string) (partial, error) {
	raw = strings.TrimLeft(strings.TrimSpace(raw), "=vV")
	if raw == "" || raw == "*" || raw == "x" || raw == "X" {
		return partial{}, nil
	}
	if at := strings.IndexByte(raw, '+'); at >= 0 {
		raw = raw[:at] // build metadata never matters for ordering
	}
	core, prerelease, _ := strings.Cut(raw, "-")
	fields := strings.Split(core, ".")
	if len(fields) > 3 {
		return partial{}, fmt.Errorf("invalid version %q", raw)
	}
	var p partial
	wildcard := false
	for i, field := range fields {
		if field == "x" || field == "X" || field == "*" {
			wildcard = true
			continue
		}
		if wildcard {
			return partial{}, fmt.Errorf("invalid version %q: a number after a wildcard", raw)
		}
		n, err := strconv.Atoi(field)
		if err != nil || n < 0 {
			return partial{}, fmt.Errorf("invalid version %q", raw)
		}
		switch i {
		case 0:
			p.major = n
		case 1:
			p.minor = n
		case 2:
			p.patch = n
		}
		p.parts = i + 1
	}
	if prerelease != "" {
		if p.parts < 3 {
			return partial{}, fmt.Errorf("invalid version %q: prerelease on a partial version", raw)
		}
		p.prerelease = prerelease
	}
	if !semver.IsValid(p.String()) {
		return partial{}, fmt.Errorf("invalid version %q", raw)
	}
	return p, nil
}

// next returns the lowest version above everything p's wildcard covers, as an exclusive
// "-0" bound: 1.2 → 1.3.0-0, 1 → 2.0.0-0.
func (p partial) next() string {
	switch p.parts {
	case 1:
		return version3(p.major+1, 0, 0, "0")
	case 2:
		return version3(p.major, p.minor+1, 0, "0")
	default:
		return version3(p.major, p.minor, p.patch+1, "0")
	}
}

func parseRange(spec string) (versionRange, error) {
	var out versionRange
	for _, alternative := range strings.Split(spec, "||") {
		set, err := parseComparatorSet(strings.TrimSpace(alternative))
		if err != nil {
			return nil, err
		}
		out = append(out, set)
	}
	return out, nil
}

func parseComparatorSet(raw string) ([]comparator, error) {
	// Hyphen range: "1.2.3 - 2.3.4".
	if lower, upper, ok := strings.Cut(raw, " - "); ok {
		lo, err := parsePartial(lower)
		if err != nil {
			return nil, err
		}
		hi, err := parsePartial(upper)
		if err != nil {
			return nil, err
		}
		set := []comparator{{">=", lo.String()}}
		switch {
		case hi.parts == 0:
		case hi.parts < 3:
			set = append(set, comparator{"<", hi.next()})
		default:
			set = append(set, comparator{"<=", hi.String()})
		}
		return set, nil
	}

	// npm accepts a space between an operator and its version: ">= 1.2.3".
	tokens := strings.Fields(raw)
	var joined []string
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if strings.Trim(token, "<>=~^") == "" && i+1 < len(tokens) {
			token += tokens[i+1]
			i++
		}
		joined = append(joined, token)
	}
	if len(joined) == 0 {
		return []comparator{{">=", "v0.0.0"}}, nil
	}

	var set []comparator
	for _, token := range joined {
		comparators, err := desugar(token)
		if err != nil {
			return nil, err
		}
		set = append(set, comparators...)
	}
	return set, nil
}

func desugar(token string) ([]comparator, error) {
	op := ""
	for _, prefix := range []string{">=", "<=", ">", "<", "=", "~>", "~", "^"} {
		if strings.HasPrefix(token, prefix) {
			op, token = prefix, token[len(prefix):]
			break
		}
	}
	p, err := parsePartial(token)
	if err != nil {
		return nil, err
	}
	all := []comparator{{">=", "v0.0.0"}}
	none := []comparator{{"<", "v0.0.0-0"}}

	switch op {
	case "~", "~>":
		if p.parts == 0 {
			return all, nil
		}
		upper := version3(p.major+1, 0, 0, "0")
		if p.parts >= 2 {
			upper = version3(p.major, p.minor+1, 0, "0")
		}
		return []comparator{{">=", p.String()}, {"<", upper}}, nil
	case "^":
		if p.parts == 0 {
			return all, nil
		}
		var upper string
		switch {
		case p.major > 0 || p.parts == 1:
			upper = version3(p.major+1, 0, 0, "0")
		case p.minor > 0 || p.parts == 2:
			upper = version3(0, p.minor+1, 0, "0")
		default:
			upper = version3(0, 0, p.patch+1, "0")
		}
		return []comparator{{">=", p.String()}, {"<", upper}}, nil
	case "", "=":
		if p.parts == 0 {
			return all, nil
		}
		if p.parts < 3 {
			return []comparator{{">=", p.String()}, {"<", p.next()}}, nil
		}
		return []comparator{{"=", p.String()}}, nil
	case ">":
		if p.parts == 0 {
			return none, nil
		}
		if p.parts < 3 {
			// >1.2 is >=1.3.0: everything past the wildcard.
			return []comparator{{">=", strings.TrimSuffix(p.next(), "-0")}}, nil
		}
		return []comparator{{">", p.String()}}, nil
	case ">=":
		return []comparator{{">=", p.String()}}, nil
	case "<":
		if p.parts == 0 {
			return none, nil
		}
		if p.parts < 3 {
			return []comparator{{"<", version3(p.major, p.minor, p.patch, "0")}}, nil
		}
		return []comparator{{"<", p.String()}}, nil
	case "<=":
		if p.parts == 0 {
			return all, nil
		}
		if p.parts < 3 {
			return []comparator{{"<", p.next()}}, nil
		}
		return []comparator{{"<=", p.String()}}, nil
	}
	return nil, fmt.Errorf("invalid comparator %q", token)
}

func (c comparator) test(v string) bool {
	cmp := semver.Compare(v, c.version)
	switch c.op {
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	default:
		return cmp == 0
	}
}

// satisfies reports whether version (without a "v") is in the range.
func (r versionRange) satisfies(version string) bool {
	v := "v" + version
	if !semver.IsValid(v) {
		return false
	}
	for _, set := range r {
		if testSet(set, v) {
			return true
		}
	}
	return false
}

func testSet(set []comparator, v string) bool {
	for _, c := range set {
		if !c.test(v) {
			return false
		}
	}
	if semver.Prerelease(v) == "" {
		return true
	}
	// A prerelease needs a comparator naming a prerelease of the same release.
	release := strings.TrimSuffix(semver.Canonical(v), semver.Prerelease(v))
	for _, c := range set {
		pre := semver.Prerelease(c.version)
		if pre != "" && strings.TrimSuffix(c.version, pre) == release {
			return true
		}
	}
	return false
}
