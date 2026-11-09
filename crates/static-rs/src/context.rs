//! Execution context: which files run at install, which run when the package is imported, and
//! which only when something calls into them. Built from a static import graph rooted at the
//! install hooks and the package's entry points.
//!
//! Module resolution here is lexical and works only on the tree's own file map: no path is
//! looked up on disk and no link is followed (links are not part of the tree at all), so
//! nothing a package declares can make the analyzer read outside its unpacked files.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use drift_proto::v1::ExecContext;

use crate::artifact::Tree;
use crate::capabilities::FileFacts;
use crate::npm_manifest::{self, Hook, Manifest};

/// Extensions Node (and TypeScript-aware bundlers) try, in order, for an extensionless import.
const EXTENSIONS: [&str; 10] = [
    ".js", ".cjs", ".mjs", ".json", ".node", ".ts", ".tsx", ".mts", ".cts", ".jsx",
];
const INDEXES: [&str; 5] = [
    "/index.js",
    "/index.cjs",
    "/index.mjs",
    "/index.json",
    "/index.ts",
];
/// The largest nested `package.json` read to find a directory's `main`.
const MAX_NESTED_MANIFEST: u64 = 1 << 20;

/// Normalizes `a/./b/../c` to `a/c`. `None` if `..` climbs above the package root.
pub fn normalize(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            p => parts.push(p),
        }
    }
    Some(parts.join("/"))
}

fn dirname(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// Resolves a module specifier imported by `from` to a file in the tree, the way Node would
/// for a path or a bundled dependency. Builtins and external dependencies resolve to `None`.
pub fn resolve(tree: &Tree, package: Option<&str>, from: &str, specifier: &str) -> Option<String> {
    let specifier = specifier.split(['?', '#']).next().unwrap_or(specifier);
    if specifier.starts_with("./")
        || specifier.starts_with("../")
        || specifier == "."
        || specifier == ".."
    {
        let joined = format!("{}/{specifier}", dirname(from));
        return resolve_path(tree, &normalize(&joined)?, 0);
    }
    if specifier.starts_with('/') || specifier.contains(':') {
        return None;
    }
    // A bare name: the package itself, or a dependency bundled under node_modules.
    let (name, rest) = split_bare(specifier);
    if package == Some(name) {
        return resolve_path(tree, &normalize(rest)?, 0);
    }
    let mut dir = dirname(from).to_owned();
    loop {
        let base = if dir.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{dir}/node_modules/{name}")
        };
        let target = if rest.is_empty() {
            base
        } else {
            format!("{base}/{rest}")
        };
        if let Some(found) = normalize(&target).and_then(|t| resolve_path(tree, &t, 0)) {
            return Some(found);
        }
        if dir.is_empty() {
            return None;
        }
        dir = dirname(&dir).to_owned();
    }
}

fn split_bare(specifier: &str) -> (&str, &str) {
    let mut cut = specifier.match_indices('/');
    let end = if specifier.starts_with('@') {
        cut.nth(1)
    } else {
        cut.next()
    };
    match end {
        Some((at, _)) => (&specifier[..at], &specifier[at + 1..]),
        None => (specifier, ""),
    }
}

/// A path as a file, with an added extension, or as a directory.
fn resolve_path(tree: &Tree, path: &str, depth: u8) -> Option<String> {
    if !path.is_empty() && tree.files.contains_key(path) {
        return Some(path.to_owned());
    }
    for ext in EXTENSIONS {
        let candidate = format!("{path}{ext}");
        if tree.files.contains_key(&candidate) {
            return Some(candidate);
        }
    }
    // TypeScript sources import their compiled names: "./a.js" is a.ts.
    if let Some(stem) = path.strip_suffix(".js") {
        for ext in [".ts", ".tsx"] {
            let candidate = format!("{stem}{ext}");
            if tree.files.contains_key(&candidate) {
                return Some(candidate);
            }
        }
    }
    let dir = path.trim_end_matches('/');
    let manifest = if dir.is_empty() {
        "package.json".to_owned()
    } else {
        format!("{dir}/package.json")
    };
    if depth == 0
        && let Some(main) = tree
            .read(&manifest, MAX_NESTED_MANIFEST)
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|m| m.get("main")?.as_str().map(str::to_owned))
        && let Some(target) = normalize(&format!("{dir}/{main}"))
        && let Some(found) = resolve_path(tree, &target, depth + 1)
    {
        return Some(found);
    }
    INDEXES.iter().find_map(|index| {
        let candidate = if dir.is_empty() {
            index[1..].to_owned()
        } else {
            format!("{dir}{index}")
        };
        tree.files.contains_key(&candidate).then_some(candidate)
    })
}

/// Which files run when, and from which root.
#[derive(Debug, Default)]
pub struct Reach {
    /// Files an install hook runs, directly or through imports, with the hook.
    pub install: BTreeMap<String, String>,
    /// Files loaded at import time through top-level imports from an entry point, with it.
    pub import: BTreeMap<String, String>,
    /// Entry points named in the manifest that are not in the tarball.
    pub missing_entries: Vec<String>,
}

impl Reach {
    /// The context of code in `path`. Install-time files run all their code, since the
    /// script's own functions are what it calls; import-time files run their top level.
    pub fn context(&self, path: &str, top_level: bool) -> (ExecContext, Option<&str>) {
        if let Some(root) = self.install.get(path) {
            return (ExecContext::Install, Some(root));
        }
        if top_level && let Some(root) = self.import.get(path) {
            return (ExecContext::Import, Some(root));
        }
        (ExecContext::Call, None)
    }
}

/// The files each install hook names, with the hook as their label.
pub fn install_roots(hooks: &BTreeMap<String, Hook>, tree: &Tree) -> Vec<(String, String)> {
    let mut roots = Vec::new();
    for (name, hook) in hooks {
        let one = BTreeMap::from([(name.clone(), hook.clone())]);
        for file in npm_manifest::referenced_files(&one, tree) {
            roots.push((file, format!("scripts.{name}")));
        }
    }
    roots
}

/// Entry points: `main` (or `index.js`) and every path in `exports` and `module`.
pub fn import_roots(
    manifest: Option<&Manifest>,
    tree: &Tree,
) -> (Vec<(String, String)>, Vec<String>) {
    let mut roots = Vec::new();
    let mut missing = Vec::new();
    let entries = manifest.map(|m| m.entries.clone()).unwrap_or_default();
    let main = entries.main.clone().unwrap_or_else(|| "index".into());
    let mut wanted = vec![(main, "main".to_owned())];
    for path in entries.exports {
        // Subpath patterns ("./*") name many files; their targets are reached when imported.
        if !path.contains('*') {
            wanted.push((path, "exports".to_owned()));
        }
    }
    for (path, label) in wanted {
        let relative = if path.starts_with("./") || path.starts_with("../") {
            path.clone()
        } else {
            format!("./{path}")
        };
        match resolve(tree, None, "package.json", &relative) {
            Some(file) => roots.push((file, label)),
            None if label != "main" || entries.main.is_some() => missing.push(path),
            None => {}
        }
    }
    (roots, missing)
}

/// Walks the import graph from the roots. `facts` supplies each file's imports, parsing it on
/// demand.
pub fn reach(
    tree: &Tree,
    package: Option<&str>,
    install_roots: &[(String, String)],
    import_roots: &[(String, String)],
    missing_entries: Vec<String>,
    facts: &mut dyn FnMut(&str) -> Option<std::sync::Arc<FileFacts>>,
) -> Reach {
    let mut out = Reach {
        missing_entries,
        ..Reach::default()
    };
    out.install = walk(tree, package, install_roots, false, facts);
    out.import = walk(tree, package, import_roots, true, facts);
    out
}

/// Breadth-first from the roots, following every import or only top-level ones.
fn walk(
    tree: &Tree,
    package: Option<&str>,
    roots: &[(String, String)],
    top_level_only: bool,
    facts: &mut dyn FnMut(&str) -> Option<std::sync::Arc<FileFacts>>,
) -> BTreeMap<String, String> {
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    for (file, label) in roots {
        if !seen.contains_key(file) {
            seen.insert(file.clone(), label.clone());
            queue.push_back(file.clone());
        }
    }
    while let Some(file) = queue.pop_front() {
        let Some(f) = facts(&file) else { continue };
        let label = seen[&file].clone();
        let mut targets = BTreeSet::new();
        for import in &f.imports {
            if top_level_only && !import.top_level {
                continue;
            }
            if let Some(target) = resolve(tree, package, &file, &import.specifier) {
                targets.insert(target);
            }
        }
        for target in targets {
            if !seen.contains_key(&target) {
                seen.insert(target.clone(), label.clone());
                queue.push_back(target);
            }
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_lexically() {
        assert_eq!(normalize("a/./b/../c").as_deref(), Some("a/c"));
        assert_eq!(normalize("./x.js").as_deref(), Some("x.js"));
        assert_eq!(normalize("../x"), None);
        assert_eq!(normalize("a/../../x"), None);
    }

    #[test]
    fn splits_bare_specifiers() {
        assert_eq!(split_bare("lodash"), ("lodash", ""));
        assert_eq!(split_bare("lodash/fp/map"), ("lodash", "fp/map"));
        assert_eq!(split_bare("@scope/pkg"), ("@scope/pkg", ""));
        assert_eq!(split_bare("@scope/pkg/sub"), ("@scope/pkg", "sub"));
    }
}
