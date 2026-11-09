//! Dependency drift: dependencies a consumer would install with `new` but not with `old`, or
//! whose source moved. The orchestrator turns each expandable `dependency_added` into a sub-job
//! that analyzes the new dependency on its own (new-package mode).

use std::collections::BTreeMap;

use drift_proto::v1::{Capability, ExecContext};

use crate::findings::{Collector, Finding};
use crate::npm_manifest::Manifest;

/// Where a dependency spec fetches code from, following npm's own spec grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A version range or dist-tag on the registry.
    Registry { range: String },
    /// `npm:other@range`: installed under this name, fetched as `other`.
    Alias { package: String, range: String },
    /// A git repository, by URL or host shorthand.
    Git,
    /// A tarball URL.
    Tarball,
    /// A local path, which only resolves in the publisher's checkout.
    File,
    /// A protocol npm doesn't install from, such as `workspace:` or `link:`.
    Other,
}

impl Source {
    pub fn classify(spec: &str) -> Self {
        let spec = spec.trim();
        if let Some(rest) = spec.strip_prefix("npm:") {
            let (package, range) = split_alias(rest);
            return Self::Alias {
                package: package.to_owned(),
                range: range.to_owned(),
            };
        }
        let lower = spec.to_ascii_lowercase();
        const GIT: [&str; 9] = [
            "git+ssh:",
            "git+https:",
            "git+http:",
            "git+file:",
            "git:",
            "github:",
            "gitlab:",
            "bitbucket:",
            "gist:",
        ];
        if GIT.iter().any(|p| lower.starts_with(p)) {
            return Self::Git;
        }
        if lower.starts_with("http://") || lower.starts_with("https://") {
            return if is_hosted_git_url(&lower) {
                Self::Git
            } else {
                Self::Tarball
            };
        }
        // Local paths come before the `user/repo` shorthand, which `./a/b` would also match.
        if lower.starts_with("file:")
            || spec.starts_with('.')
            || spec.starts_with('/')
            || spec.starts_with('~')
            || [".tgz", ".tar.gz", ".tar"]
                .iter()
                .any(|e| lower.ends_with(e))
        {
            return Self::File;
        }
        if is_git_shorthand(spec) {
            return Self::Git;
        }
        if spec.contains(':') {
            return Self::Other;
        }
        Self::Registry {
            range: spec.to_owned(),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Registry { .. } => "registry",
            Self::Alias { .. } => "alias",
            Self::Git => "git",
            Self::Tarball => "tarball",
            Self::File => "file",
            Self::Other => "other",
        }
    }
}

/// `other@^1.0.0` or `@scope/other@^1.0.0` into the name and the range, `*` if none.
fn split_alias(rest: &str) -> (&str, &str) {
    let search_from = usize::from(rest.starts_with('@'));
    match rest[search_from..].find('@') {
        Some(at) => (&rest[..search_from + at], &rest[search_from + at + 1..]),
        None => (rest, "*"),
    }
}

/// npm reads `user/repo` and `user/repo#ref` as GitHub repositories.
fn is_git_shorthand(spec: &str) -> bool {
    let path = spec.split('#').next().unwrap_or_default();
    let Some((user, repo)) = path.split_once('/') else {
        return false;
    };
    let bad = |c: char| c.is_whitespace() || "@%:/".contains(c);
    !user.is_empty()
        && !repo.is_empty()
        && !user.starts_with(['.', '-'])
        && !user.chars().any(bad)
        && !repo.chars().any(bad)
}

/// An http(s) URL npm treats as a git repository rather than a tarball.
fn is_hosted_git_url(lower: &str) -> bool {
    let without_scheme = lower.split_once("://").map_or(lower, |(_, rest)| rest);
    let host = without_scheme.split('/').next().unwrap_or_default();
    let path = without_scheme.split('#').next().unwrap_or_default();
    ["github.com", "gitlab.com", "bitbucket.org"].contains(&host)
        && (path.ends_with(".git") || path.matches('/').count() == 2)
}

/// One dependency a consumer would install.
#[derive(Debug, Clone, PartialEq)]
pub struct Declared {
    pub name: String,
    pub spec: String,
    pub section: &'static str,
    pub source: Source,
    pub bundled: bool,
}

/// What a consumer installs, by name. npm moves `optionalDependencies` over `dependencies`
/// of the same name, a regular dependency outranks a peer, and an optional peer is not
/// installed by itself.
pub fn declared(manifest: &Manifest) -> BTreeMap<String, Declared> {
    let mut out = BTreeMap::new();
    // Lowest precedence first, so later sections replace earlier ones.
    for section in ["peerDependencies", "dependencies", "optionalDependencies"] {
        let Some(deps) = manifest.dependency_sections.get(section) else {
            continue;
        };
        for (name, spec) in deps {
            if section == "peerDependencies" && manifest.optional_peers.contains(name) {
                continue;
            }
            out.insert(
                name.clone(),
                Declared {
                    name: name.clone(),
                    spec: spec.clone(),
                    section,
                    source: Source::classify(spec),
                    bundled: manifest.bundled.contains(name),
                },
            );
        }
    }
    out
}

/// Base confidence that a newly added dependency matters, before its own analysis.
fn added_confidence(dep: &Declared) -> f64 {
    match dep.source {
        // Code from outside the registry escapes registry-side takedowns and provenance.
        Source::Git | Source::Tarball => 0.7,
        Source::File | Source::Other => 0.3,
        Source::Registry { .. } | Source::Alias { .. } if dep.section == "optionalDependencies" => {
            0.6
        }
        Source::Alias { .. } => 0.6,
        Source::Registry { .. } if dep.section == "peerDependencies" => 0.4,
        Source::Registry { .. } => 0.5,
    }
}

/// Reports dependencies added or repointed between `old` and `new`. With `new_package`
/// set there is no previous version: every dependency is listed, with low confidence, so
/// that the orchestrator can expand them.
pub fn diff(
    old: Option<&Manifest>,
    new: Option<&Manifest>,
    new_package: bool,
    collector: &mut Collector,
) {
    let Some(new) = new else { return };
    let old_deps = old.map(declared).unwrap_or_default();
    for (name, dep) in declared(new) {
        let line = new.key_line_in(dep.section, &name);
        let snippet = format!(
            "\"{name}\": {}",
            serde_json::Value::String(dep.spec.clone())
        );
        let finding = match old_deps.get(&name) {
            None => {
                let confidence = if new_package {
                    0.2
                } else {
                    added_confidence(&dep)
                };
                Finding::new(
                    "dependency_added",
                    Capability::Unspecified,
                    ExecContext::Install,
                    confidence,
                )
            }
            Some(previous) => {
                let Some(confidence) = repointed(&previous.source, &dep.source, previous, &dep)
                else {
                    continue;
                };
                Finding::new(
                    "dependency_repointed",
                    Capability::Unspecified,
                    ExecContext::Install,
                    confidence,
                )
                .attr("old_spec", &previous.spec)
                .attr("old_source", previous.source.label())
            }
        };
        let mut finding = finding
            .evidence("package.json", line, &snippet)
            .attr("dependency", &name)
            .attr("spec", &dep.spec)
            .attr("section", dep.section)
            .attr("source", dep.source.label())
            .attr("bundled", dep.bundled.to_string());
        match &dep.source {
            Source::Registry { range } => {
                finding = finding.attr("package", &name).attr("range", range);
            }
            Source::Alias { package, range } => {
                finding = finding.attr("package", package).attr("range", range);
            }
            _ => {}
        }
        collector.push(finding);
    }
}

/// Whether a dependency's source moved, and how much that says. A range change on the
/// registry is routine and not reported.
fn repointed(old: &Source, new: &Source, previous: &Declared, dep: &Declared) -> Option<f64> {
    match (old, new) {
        (Source::Registry { .. }, Source::Registry { .. }) => None,
        (Source::Alias { package: a, .. }, Source::Alias { package: b, .. }) => {
            (a != b).then_some(0.7)
        }
        (Source::Registry { .. } | Source::Alias { .. }, Source::Git | Source::Tarball) => {
            Some(0.8)
        }
        (Source::Registry { .. }, Source::Alias { package, .. }) => {
            (package != &dep.name).then_some(0.7)
        }
        _ if old.label() != new.label() => Some(0.6),
        _ => (previous.spec != dep.spec).then_some(0.6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_specs_like_npm() {
        let reg = |r: &str| Source::Registry { range: r.into() };
        assert_eq!(Source::classify("^1.2.3"), reg("^1.2.3"));
        assert_eq!(Source::classify("latest"), reg("latest"));
        assert_eq!(Source::classify(">=1 <2 || 3.x"), reg(">=1 <2 || 3.x"));
        assert_eq!(Source::classify(""), reg(""));
        assert_eq!(
            Source::classify("npm:@scope/other@^2"),
            Source::Alias {
                package: "@scope/other".into(),
                range: "^2".into()
            }
        );
        assert_eq!(
            Source::classify("npm:other"),
            Source::Alias {
                package: "other".into(),
                range: "*".into()
            }
        );
        for git in [
            "git+https://example.invalid/a/b.git",
            "github:user/repo",
            "user/repo",
            "user/repo#v1.0.0",
            "https://github.com/user/repo",
            "https://github.com/user/repo.git#abc",
        ] {
            assert_eq!(Source::classify(git), Source::Git, "{git}");
        }
        assert_eq!(
            Source::classify("https://example.invalid/x-1.0.0.tgz"),
            Source::Tarball
        );
        assert_eq!(
            Source::classify("https://github.com/user/repo/archive/v1.tar.gz"),
            Source::Tarball
        );
        for file in ["file:../x", "./x", "../x", "/abs/x", "~/x", "x.tgz"] {
            assert_eq!(Source::classify(file), Source::File, "{file}");
        }
        assert_eq!(Source::classify("workspace:*"), Source::Other);
    }

    fn manifest(json: &str) -> Manifest {
        Manifest::parse(json.to_owned()).unwrap()
    }

    fn run(old: Option<&str>, new: &str) -> Vec<drift_proto::v1::DriftFinding> {
        let old = old.map(manifest);
        let new = manifest(new);
        let mut c = Collector::new(100);
        diff(old.as_ref(), Some(&new), old.is_none(), &mut c);
        c.finish().0
    }

    #[test]
    fn precedence_between_sections() {
        let m = manifest(
            r#"{"dependencies":{"a":"^1","b":"^1"},"optionalDependencies":{"a":"^2"},
                "peerDependencies":{"b":"^9","c":"^1","d":"^1"},
                "peerDependenciesMeta":{"d":{"optional":true}},
                "devDependencies":{"e":"^1"},"bundleDependencies":["b"]}"#,
        );
        let d = declared(&m);
        assert_eq!(d.keys().collect::<Vec<_>>(), ["a", "b", "c"]);
        assert_eq!(d["a"].section, "optionalDependencies");
        assert_eq!(d["a"].spec, "^2");
        assert_eq!(d["b"].section, "dependencies");
        assert!(d["b"].bundled);
        assert_eq!(d["c"].section, "peerDependencies");
    }

    #[test]
    fn reports_added_and_repointed_dependencies() {
        let old = r#"{"dependencies":{"keep":"^1","bump":"^1","moved":"^1","alias":"npm:x@^1"},
                      "devDependencies":{"promoted":"^1"}}"#;
        let new = r#"{
  "dependencies": {
    "keep": "^1",
    "bump": "^2",
    "moved": "github:someone/moved",
    "alias": "npm:y@^1",
    "promoted": "^1",
    "fresh": "npm:@scope/real@~4.2.1"
  },
  "optionalDependencies": {
    "opt": "1.0.0"
  }
}"#;
        let findings = run(Some(old), new);
        let mut seen: Vec<(String, String, f64)> = findings
            .iter()
            .map(|f| (f.kind.clone(), f.attrs["dependency"].clone(), f.confidence))
            .collect();
        seen.sort_by(|a, b| a.1.cmp(&b.1));
        assert_eq!(
            seen,
            [
                ("dependency_repointed".into(), "alias".into(), 0.7),
                ("dependency_added".into(), "fresh".into(), 0.6),
                ("dependency_repointed".into(), "moved".into(), 0.8),
                ("dependency_added".into(), "opt".into(), 0.6),
                ("dependency_added".into(), "promoted".into(), 0.5),
            ]
        );
        let fresh = findings
            .iter()
            .find(|f| f.attrs["dependency"] == "fresh")
            .unwrap();
        assert_eq!(fresh.attrs["package"], "@scope/real");
        assert_eq!(fresh.attrs["range"], "~4.2.1");
        assert_eq!(fresh.attrs["source"], "alias");
        assert_eq!(fresh.evidence[0].line, 8);
        assert_eq!(fresh.context(), ExecContext::Install);
        let opt = findings
            .iter()
            .find(|f| f.attrs["dependency"] == "opt")
            .unwrap();
        assert_eq!(opt.evidence[0].line, 11);
        assert_eq!(opt.attrs["section"], "optionalDependencies");
    }

    #[test]
    fn new_package_mode_lists_every_dependency() {
        let findings = run(None, r#"{"dependencies":{"a":"^1","b":"^2"}}"#);
        assert_eq!(findings.len(), 2);
        assert!(
            findings
                .iter()
                .all(|f| f.kind == "dependency_added" && (f.confidence - 0.2).abs() < 1e-9)
        );
    }

    #[test]
    fn key_line_in_finds_the_dependency_in_its_section() {
        let m = manifest(
            "{\n \"name\": \"a\",\n \"scripts\": {\"a\": \"x\"},\n \"dependencies\": {\"a\": \"^1\",\n  \"b\": \"^1\"}\n}",
        );
        assert_eq!(m.key_line_in("dependencies", "a"), 4);
        assert_eq!(m.key_line_in("dependencies", "b"), 5);
        assert_eq!(m.key_line_in("optionalDependencies", "a"), 0);
    }

    #[test]
    fn dependencies_survive_an_unparseable_manifest() {
        let text =
            r#"{"description":"\ud800","dependencies":{"evil":"^1.0.0", "x" : "npm:y@2"}} junk"#;
        assert!(Manifest::parse(text.to_owned()).is_err());
        let m = Manifest::scan(text.to_owned());
        let d = declared(&m);
        assert_eq!(d["evil"].spec, "^1.0.0");
        assert_eq!(
            d["x"].source,
            Source::Alias {
                package: "y".into(),
                range: "2".into()
            }
        );
    }
}
