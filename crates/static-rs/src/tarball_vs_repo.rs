//! Tarball-vs-repo diff: files the registry serves that the source repository doesn't have,
//! or has with different contents.

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use drift_proto::v1::{Capability, ExecContext};

use crate::artifact::{Tree, read_bounded};
use crate::findings::{Collector, Finding};

/// Directories that commonly hold build output, so their files legitimately exist only in
/// the tarball. They are skipped only when the repo doesn't track the directory at all: a
/// repo that commits `lib/` gets `lib/` compared like anything else.
const BUILD_DIRS: [&str; 16] = [
    "dist", "build", "lib", "out", "esm", "cjs", "umd", "es", "types", "typings", "bundle",
    "bundles", "_cjs", "_esm", "_types", "fesm2022",
];

/// File suffixes produced by builds. Skipped when the repo lacks that file.
const BUILD_SUFFIXES: [&str; 11] = [
    ".min.js",
    ".min.mjs",
    ".min.cjs",
    ".min.css",
    ".map",
    ".d.ts",
    ".d.mts",
    ".d.cts",
    ".tsbuildinfo",
    ".d.ts.map",
    ".js.map",
];

/// Rewritten or generated at publish time by common tooling. `package.json` changes are
/// covered by the scripts diff.
const PUBLISH_REWRITTEN: [&str; 9] = [
    "package.json",
    "readme",
    "license",
    "licence",
    "changelog",
    "history",
    "authors",
    "notice",
    "contributors",
];

const MAX_COMPARE: u64 = 16 << 20;
const MAX_DIRS_SEARCHED: usize = 5000;
const MAX_SEARCH_DEPTH: usize = 4;

/// The repository side of the comparison.
pub struct Repo {
    pub root: PathBuf,
    /// The package's directory inside the repo; the root unless it is a monorepo.
    pub package_dir: PathBuf,
    /// Multiplies every finding's confidence.
    pub confidence: f64,
    pub repo_ref: String,
    /// Why confidence is reduced, if it is.
    pub caveats: Vec<String>,
}

impl Repo {
    /// Finds `package` inside a checkout. The shallowest directory whose `package.json` names
    /// the package wins; the root is used, with less confidence, if none does.
    pub fn locate(root: PathBuf, package: &str, repo_ref: &str, confidence: f64) -> Self {
        let mut caveats = Vec::new();
        let (package_dir, found) = match find_package_dir(&root, package) {
            Some(dir) => (dir, true),
            None => (root.clone(), false),
        };
        let mut confidence = confidence;
        if !found {
            confidence *= 0.6;
            caveats.push("no package.json in the repo names this package".to_owned());
        }
        Self {
            root,
            package_dir,
            confidence,
            repo_ref: repo_ref.to_owned(),
            caveats,
        }
    }
}

fn find_package_dir(root: &Path, package: &str) -> Option<PathBuf> {
    let mut queue = VecDeque::from([(root.to_owned(), 0usize)]);
    let mut searched = 0;
    while let Some((dir, depth)) = queue.pop_front() {
        searched += 1;
        if searched > MAX_DIRS_SEARCHED {
            return None;
        }
        let manifest = dir.join("package.json");
        if fs::symlink_metadata(&manifest).is_ok_and(|m| m.is_file())
            && let Ok(bytes) = read_bounded(&manifest, 1 << 20)
            && let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && json.get("name").and_then(|n| n.as_str()) == Some(package)
        {
            return Some(dir);
        }
        if depth >= MAX_SEARCH_DEPTH {
            continue;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        let mut children: Vec<PathBuf> = entries
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter(|e| {
                let name = e.file_name();
                let name = name.to_string_lossy();
                !name.starts_with('.') && name != "node_modules"
            })
            .map(|e| e.path())
            .collect();
        children.sort();
        queue.extend(children.into_iter().map(|c| (c, depth + 1)));
    }
    None
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Same,
    Missing,
    Differs,
}

struct Compared {
    path: String,
    outcome: Outcome,
    build_output: bool,
}

/// Compares the files added or changed in `new` (all files, in new-package mode) with the repo.
pub fn diff(
    old: Option<&Tree>,
    new: &Tree,
    repo: &Repo,
    install_files: &BTreeSet<String>,
    collector: &mut Collector,
) {
    let mut results = Vec::new();
    for (path, info) in &new.files {
        if old
            .and_then(|o| o.files.get(path))
            .is_some_and(|p| p.sha256 == info.sha256)
        {
            continue; // Published like this before, so not new drift.
        }
        if is_publish_rewritten(path) {
            continue;
        }
        let build_output = is_build_output(path);
        let repo_file = repo.package_dir.join(path);
        if build_output && !tracked_by_repo(repo, path) {
            continue;
        }
        let outcome = match fs::symlink_metadata(&repo_file) {
            Err(_) => Outcome::Missing,
            Ok(meta) if !meta.is_file() => Outcome::Differs,
            Ok(_) if !inside(&repo.root, &repo_file) => Outcome::Differs,
            Ok(_) => compare(&info.disk, &repo_file),
        };
        results.push(Compared {
            path: path.clone(),
            outcome,
            build_output,
        });
    }

    let compared = results.len();
    let differing = results
        .iter()
        .filter(|r| r.outcome != Outcome::Same)
        .count();
    let mut scale = repo.confidence;
    let mut caveats = repo.caveats.clone();
    // When most files differ, the checkout is probably the wrong commit or not this package.
    if compared >= 10 && differing * 2 > compared {
        scale *= 0.5;
        caveats.push(format!(
            "{differing} of {compared} compared files differ; the repo ref may not match"
        ));
    }
    for caveat in &caveats {
        collector.note(format!("tarball-vs-repo: {caveat}"));
    }

    for r in results {
        let (kind, base) = match (&r.outcome, r.build_output) {
            (Outcome::Same, _) => continue,
            (Outcome::Missing, _) => ("tarball_only_file", 0.6),
            (Outcome::Differs, false) => ("tarball_modified_file", 0.5),
            (Outcome::Differs, true) => ("tarball_modified_file", 0.3),
        };
        let at_install = install_files.contains(&r.path);
        let (context, base) = if at_install {
            (ExecContext::Install, (base + 0.3_f64).min(0.95))
        } else {
            (ExecContext::Unspecified, base)
        };
        let package_dir = r_rel(&repo.root, &repo.package_dir);
        collector.push(
            Finding::new(kind, Capability::Unspecified, context, base * scale)
                .evidence(&r.path, 0, "")
                .attr("repo_ref", &repo.repo_ref)
                .attr("repo_dir", package_dir)
                .attr("sha256", &new.files[&r.path].sha256)
                .attr("run_by_install_hook", at_install.to_string()),
        );
    }
}

fn r_rel(root: &Path, dir: &Path) -> String {
    match dir.strip_prefix(root) {
        Ok(rel) if rel.as_os_str().is_empty() => ".".to_owned(),
        Ok(rel) => rel.to_string_lossy().into_owned(),
        Err(_) => "?".to_owned(),
    }
}

fn is_publish_rewritten(path: &str) -> bool {
    if path.contains('/') {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    let stem = lower.split('.').next().unwrap_or("");
    PUBLISH_REWRITTEN
        .iter()
        .any(|name| lower == *name || stem == *name)
}

fn is_build_output(path: &str) -> bool {
    let top = path.split('/').next().unwrap_or("");
    let lower = path.to_ascii_lowercase();
    (path.contains('/') && BUILD_DIRS.contains(&top))
        || BUILD_SUFFIXES.iter().any(|s| lower.ends_with(s))
}

/// Whether the repo has the build directory (for a file under one) or the file itself.
fn tracked_by_repo(repo: &Repo, path: &str) -> bool {
    let top = path.split('/').next().unwrap_or("");
    if path.contains('/') && BUILD_DIRS.contains(&top) {
        return fs::symlink_metadata(repo.package_dir.join(top)).is_ok_and(|m| m.is_dir());
    }
    fs::symlink_metadata(repo.package_dir.join(path)).is_ok()
}

/// Resolved, the repo file must stay inside the checkout.
fn inside(root: &Path, file: &Path) -> bool {
    match (root.canonicalize(), file.canonicalize()) {
        (Ok(root), Ok(file)) => file.starts_with(root),
        _ => false,
    }
}

/// Byte-equal, or equal once carriage returns are dropped: git may check out text with
/// different line endings than the publisher had.
fn compare(tarball: &Path, repo: &Path) -> Outcome {
    let (Ok(a), Ok(b)) = (
        read_bounded(tarball, MAX_COMPARE),
        read_bounded(repo, MAX_COMPARE),
    ) else {
        return Outcome::Differs;
    };
    if a == b || strip_cr(&a) == strip_cr(&b) {
        Outcome::Same
    } else {
        Outcome::Differs
    }
}

fn strip_cr(data: &[u8]) -> Vec<u8> {
    data.iter().copied().filter(|&b| b != b'\r').collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_paths() {
        assert!(is_build_output("dist/index.js"));
        assert!(is_build_output("index.min.js"));
        assert!(is_build_output("types/index.d.ts"));
        assert!(!is_build_output("dist"));
        assert!(!is_build_output("src/index.js"));
        assert!(!is_build_output("install.js"));
        assert!(is_publish_rewritten("README.md"));
        assert!(is_publish_rewritten("LICENSE"));
        assert!(is_publish_rewritten("package.json"));
        assert!(!is_publish_rewritten("docs/README.md"));
        assert!(!is_publish_rewritten("licensecheck.js"));
    }

    #[test]
    fn finds_monorepo_packages() {
        let repo = tempfile::tempdir().unwrap();
        let pkg = repo.path().join("packages/core");
        fs::create_dir_all(&pkg).unwrap();
        fs::write(
            repo.path().join("package.json"),
            r#"{"name":"monorepo-root"}"#,
        )
        .unwrap();
        fs::write(pkg.join("package.json"), r#"{"name":"@scope/core"}"#).unwrap();
        fs::create_dir_all(repo.path().join("node_modules/@scope/core")).unwrap();
        fs::write(
            repo.path().join("node_modules/@scope/core/package.json"),
            r#"{"name":"@scope/core"}"#,
        )
        .unwrap();
        assert_eq!(find_package_dir(repo.path(), "@scope/core"), Some(pkg));
        assert_eq!(
            find_package_dir(repo.path(), "monorepo-root"),
            Some(repo.path().to_owned())
        );
        assert_eq!(find_package_dir(repo.path(), "missing"), None);
    }

    #[test]
    fn line_endings_do_not_count_as_changes() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b, c) = (
            dir.path().join("a"),
            dir.path().join("b"),
            dir.path().join("c"),
        );
        fs::write(&a, "x\r\ny\r\n").unwrap();
        fs::write(&b, "x\ny\n").unwrap();
        fs::write(&c, "x\nz\n").unwrap();
        assert_eq!(compare(&a, &b), Outcome::Same);
        assert_eq!(compare(&a, &c), Outcome::Differs);
    }
}
