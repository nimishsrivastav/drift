package npm

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nimishsrivastav/drift/orchestrator/internal/ingest"
	"golang.org/x/mod/semver"
)

// packument holds only the fields we use. Fields whose shape varies between old and new
// packages stay raw and are decoded leniently, so one odd release cannot fail the whole document.
type packument struct {
	Name       string                     `json:"name"`
	DistTags   map[string]string          `json:"dist-tags"`
	Versions   map[string]versionDoc      `json:"versions"`
	Time       map[string]json.RawMessage `json:"time"`
	Repository json.RawMessage            `json:"repository"`
}

type versionDoc struct {
	Dist       dist            `json:"dist"`
	Repository json.RawMessage `json:"repository"`
}

type dist struct {
	Tarball   string `json:"tarball"`
	Shasum    string `json:"shasum"`
	Integrity string `json:"integrity"`
}

func (p *packument) resolve(name, from, to string) (ingest.Resolution, error) {
	if len(p.Versions) == 0 {
		return ingest.Resolution{}, fmt.Errorf("%w: %s has no published versions", ingest.ErrVersionNotFound, name)
	}
	if to == "" {
		to = "latest"
	}
	newVersion, err := p.lookup(name, to)
	if err != nil {
		return ingest.Resolution{}, err
	}
	res := ingest.Resolution{New: newVersion}

	oldName := from
	if from == "" {
		oldName = p.predecessor(newVersion.Version)
		if oldName == "" {
			return res, nil // no earlier release: new-package mode
		}
	}
	oldVersion, err := p.lookup(name, oldName)
	if err != nil {
		return ingest.Resolution{}, err
	}
	res.Old = &oldVersion
	return res, nil
}

// lookup finds a version by exact number or dist-tag.
func (p *packument) lookup(name, spec string) (ingest.Version, error) {
	version := spec
	doc, ok := p.Versions[version]
	if !ok {
		tagged, isTag := p.DistTags[spec]
		if !isTag {
			return ingest.Version{}, fmt.Errorf("%w: %s@%s", ingest.ErrVersionNotFound, name, spec)
		}
		version = tagged
		if doc, ok = p.Versions[version]; !ok {
			return ingest.Version{}, fmt.Errorf("%w: %s@%s (dist-tag %s)", ingest.ErrVersionNotFound, name, version, spec)
		}
	}
	repository := repositoryURL(doc.Repository)
	if repository == "" {
		repository = repositoryURL(p.Repository)
	}
	return ingest.Version{
		Name:          name,
		Version:       version,
		TarballURL:    doc.Dist.Tarball,
		Integrity:     doc.Dist.Integrity,
		Shasum:        doc.Dist.Shasum,
		RepositoryURL: repository,
	}, nil
}

// predecessor returns the highest release below target that was published before it, or ""
// if there is none. Semver order, unlike publish order, keeps a backport compared against its
// own release line. A stable target skips prereleases, so 2.0.0 is compared with 1.9.0
// and not with 2.0.0-rc.3.
func (p *packument) predecessor(target string) string {
	targetSemver := "v" + target
	if !semver.IsValid(targetSemver) {
		return ""
	}
	targetPublished, targetDated := p.published(target)
	targetIsPrerelease := semver.Prerelease(targetSemver) != ""

	best, bestSemver := "", ""
	for candidate := range p.Versions {
		candidateSemver := "v" + candidate
		if !semver.IsValid(candidateSemver) || semver.Compare(candidateSemver, targetSemver) >= 0 {
			continue
		}
		if !targetIsPrerelease && semver.Prerelease(candidateSemver) != "" {
			continue
		}
		if published, dated := p.published(candidate); dated && targetDated && !published.Before(targetPublished) {
			continue // a later backport to an older line never preceded the target
		}
		if best == "" || semver.Compare(candidateSemver, bestSemver) > 0 {
			best, bestSemver = candidate, candidateSemver
		}
	}
	return best
}

func (p *packument) published(version string) (time.Time, bool) {
	raw, ok := p.Time[version]
	if !ok {
		return time.Time{}, false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return time.Time{}, false
	}
	published, err := time.Parse(time.RFC3339, value)
	return published, err == nil
}

// repositoryURL reads the repository field, which may be a string, an object with a url, or
// (in old packages) a list of either. Anything else counts as absent.
func repositoryURL(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var asString string
	if json.Unmarshal(raw, &asString) == nil {
		return strings.TrimSpace(asString)
	}
	var asObject struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(raw, &asObject) == nil && asObject.URL != "" {
		return strings.TrimSpace(asObject.URL)
	}
	var asList []json.RawMessage
	if json.Unmarshal(raw, &asList) == nil && len(asList) > 0 {
		return repositoryURL(asList[0])
	}
	return ""
}
