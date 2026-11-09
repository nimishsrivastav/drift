//! What each version's code can do, in which context, and what `new` can do that `old`
//! couldn't.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use drift_proto::v1::{Capability, ExecContext};

use crate::artifact::Tree;
use crate::capabilities::{self, FileFacts, Grammar, Use};
use crate::context::{self, Reach};
use crate::findings::{Collector, Finding};
use crate::npm_manifest::{Hook, Manifest};

/// Most source bytes parsed per analysis, both versions together.
pub const PARSE_BUDGET: u64 = 64 << 20;

/// Parsed files by content hash, shared between the versions: unchanged files parse once.
pub struct FactCache {
    by_sha: HashMap<String, Arc<FileFacts>>,
    remaining: u64,
}

impl FactCache {
    pub fn new(budget: u64) -> Self {
        Self {
            by_sha: HashMap::new(),
            remaining: budget,
        }
    }

    /// The facts for one file, or why there are none.
    fn get(&mut self, tree: &Tree, path: &str, grammar: Grammar) -> Result<Arc<FileFacts>, String> {
        let info = tree.files.get(path).ok_or("not in the package")?;
        if let Some(facts) = self.by_sha.get(&info.sha256) {
            return Ok(Arc::clone(facts));
        }
        if info.size > capabilities::MAX_FILE_BYTES {
            return Err(format!(
                "{} bytes, over the {}-byte parse limit",
                info.size,
                capabilities::MAX_FILE_BYTES
            ));
        }
        if info.size > self.remaining {
            return Err("over the analysis's parse budget".into());
        }
        let source = tree
            .read(path, capabilities::MAX_FILE_BYTES)
            .ok_or("unreadable")?;
        self.remaining -= info.size;
        let facts = Arc::new(capabilities::extract(grammar, &source));
        self.by_sha.insert(info.sha256.clone(), Arc::clone(&facts));
        Ok(facts)
    }
}

/// One version's code: per-file facts and what reaches each file.
#[derive(Default)]
pub struct VersionCode {
    pub facts: BTreeMap<String, Arc<FileFacts>>,
    /// Code files that could not be analyzed, with the reason.
    pub skipped: BTreeMap<String, String>,
    pub reach: Reach,
}

/// Analyzes one version. `first` lists files to parse before anything else (the ones that
/// changed), so that padding a package can't push its payload out of the parse budget.
pub fn analyze_version(
    tree: &Tree,
    manifest: Option<&Manifest>,
    hooks: &BTreeMap<String, Hook>,
    first: &BTreeSet<String>,
    cache: &mut FactCache,
) -> VersionCode {
    let install_roots = context::install_roots(hooks, tree);
    let (import_roots, missing) = context::import_roots(manifest, tree);
    // Scripts with no extension still run as JavaScript when a hook or bin names them.
    let mut forced: BTreeSet<String> = install_roots.iter().map(|(f, _)| f.clone()).collect();
    if let Some(m) = manifest {
        for bin in &m.entries.bin {
            if let Some(path) = context::normalize(bin) {
                forced.insert(path);
            }
        }
    }
    let grammar = |path: &str| {
        capabilities::grammar_for(path)
            .or_else(|| forced.contains(path).then_some(Grammar::JavaScript))
    };

    let mut code = VersionCode::default();
    let mut load = |path: &str, code: &mut VersionCode| -> Option<Arc<FileFacts>> {
        if let Some(f) = code.facts.get(path) {
            return Some(Arc::clone(f));
        }
        if code.skipped.contains_key(path) {
            return None;
        }
        let g = grammar(path)?;
        match cache.get(tree, path, g) {
            Ok(f) => {
                code.facts.insert(path.to_owned(), Arc::clone(&f));
                Some(f)
            }
            Err(reason) => {
                code.skipped.insert(path.to_owned(), reason);
                None
            }
        }
    };

    for path in first {
        if tree.files.contains_key(path) {
            load(path, &mut code);
        }
    }
    let package = manifest.and_then(|m| m.name.clone());
    let reach = context::reach(
        tree,
        package.as_deref(),
        &install_roots,
        &import_roots,
        missing,
        &mut |path| load(path, &mut code),
    );
    let paths: Vec<String> = tree.files.keys().cloned().collect();
    for path in paths {
        load(&path, &mut code);
    }
    code.reach = reach;
    code
}

/// The strongest use of one capability (or obfuscation signal) in one file.
#[derive(Debug, Clone)]
struct Best {
    context: ExecContext,
    root: Option<String>,
    used: Use,
    count: usize,
}

/// Lower is stronger: install beats import beats call.
fn rank(context: ExecContext) -> u8 {
    match context {
        ExecContext::Install => 0,
        ExecContext::Import => 1,
        ExecContext::Call => 2,
        ExecContext::Unspecified => 3,
    }
}

type Key = (Capability, &'static str);

fn summarize(code: &VersionCode) -> BTreeMap<String, BTreeMap<Key, Best>> {
    let mut out: BTreeMap<String, BTreeMap<Key, Best>> = BTreeMap::new();
    for (path, facts) in &code.facts {
        let per_file = out.entry(path.clone()).or_default();
        for used in &facts.uses {
            let (context, root) = code.reach.context(path, used.top_level);
            let key = (used.capability, used.signal);
            match per_file.get_mut(&key) {
                Some(best) => {
                    best.count += 1;
                    // Strongest context, then code that runs over a bare require, then earliest.
                    let order = |c: ExecContext, u: &Use| (rank(c), !u.top_level, u.line);
                    let better = order(context, used) < order(best.context, &best.used);
                    if better {
                        best.context = context;
                        best.root = root.map(str::to_owned);
                        best.used = used.clone();
                    }
                }
                None => {
                    per_file.insert(
                        key,
                        Best {
                            context,
                            root: root.map(str::to_owned),
                            used: used.clone(),
                            count: 1,
                        },
                    );
                }
            }
        }
    }
    out
}

/// How much one capability's appearance says on its own, before context, which the scorer
/// weighs.
fn base_confidence(capability: Capability, signal: &str, detail: &str) -> f64 {
    match (capability, signal) {
        (Capability::Obfuscation, "decode_exec") => 0.9,
        (Capability::Obfuscation, "obfuscator_identifiers") => 0.7,
        (Capability::Obfuscation, "encoded_blob" | "escaped_string") => 0.5,
        (Capability::Obfuscation, "newly_minified") => 0.4,
        (Capability::Obfuscation, _) => 0.3,
        (Capability::DynamicCode, _) if detail.starts_with("require of") => 0.3,
        (Capability::FsSensitiveRead | Capability::CryptoWallet, _) => 0.7,
        (Capability::ProcessSpawn | Capability::DynamicCode | Capability::NativeBinary, _) => 0.6,
        (Capability::Network, _) => 0.5,
        (Capability::EnvAccess, _) => 0.3,
        _ => 0.3,
    }
}

fn finding(kind: &str, path: &str, key: Key, best: &Best, confidence: f64) -> Finding {
    let mut f = Finding::new(kind, key.0, best.context, confidence)
        .evidence(path, best.used.line, &best.used.snippet)
        .attr("detail", &best.used.detail)
        .attr("uses_in_file", best.count.to_string());
    if !key.1.is_empty() {
        f = f.attr("signal", key.1);
    }
    if let Some(root) = &best.root {
        f = f.attr("reached_from", root);
    }
    f
}

/// Reports capabilities `new` has that `old` didn't, per file, and capabilities that moved
/// to a stronger context. With no `old`, every capability is reported.
pub fn diff(
    old_tree: Option<&Tree>,
    old: Option<&VersionCode>,
    new_tree: &Tree,
    new: &VersionCode,
    collector: &mut Collector,
) {
    let new_summary = summarize(new);
    let old_summary = old.map(summarize).unwrap_or_default();
    // The strongest context each capability had anywhere in the old package.
    let mut old_package: HashMap<Key, u8> = HashMap::new();
    for per_file in old_summary.values() {
        for (key, best) in per_file {
            let r = old_package.entry(*key).or_insert(u8::MAX);
            *r = (*r).min(rank(best.context));
        }
    }

    for (path, per_file) in &new_summary {
        let before = old_summary.get(path);
        for (key, best) in per_file {
            let base = base_confidence(key.0, key.1, &best.used.detail);
            match before.and_then(|b| b.get(key)) {
                None => {
                    // Already in the package at this strength elsewhere: likely moved code.
                    let moved = old_package
                        .get(key)
                        .is_some_and(|&r| r <= rank(best.context));
                    let confidence = if moved { base * 0.5 } else { base };
                    let mut f = finding("capability_added", path, *key, best, confidence);
                    if old.is_some() {
                        f = f.attr("package_had_capability", moved.to_string());
                    }
                    collector.push(f);
                }
                Some(previous) if rank(best.context) < rank(previous.context) => {
                    collector.push(
                        finding("capability_context_escalated", path, *key, best, base * 0.8)
                            .attr("old_context", previous.context.as_str_name()),
                    );
                }
                Some(_) => {}
            }
        }
    }

    if let (Some(old), Some(old_tree)) = (old, old_tree) {
        newly_minified(old, new, collector);
        incomplete(Some(old_tree), new_tree, new, collector);
    } else {
        incomplete(None, new_tree, new, collector);
    }
}

/// Files minified in `new` that weren't in `old`.
fn newly_minified(old: &VersionCode, new: &VersionCode, collector: &mut Collector) {
    for (path, facts) in &new.facts {
        if !facts.minified || !old.facts.get(path).is_some_and(|f| !f.minified) {
            continue;
        }
        let (context, root) = new.reach.context(path, true);
        let key = (Capability::Obfuscation, "newly_minified");
        let mut f = Finding::new(
            "capability_added",
            key.0,
            context,
            base_confidence(key.0, key.1, ""),
        )
        .evidence(path, 0, "")
        .attr("signal", key.1)
        .attr("detail", "minified now, not in the previous version");
        if let Some(root) = root {
            f = f.attr("reached_from", root);
        }
        collector.push(f);
    }
}

/// Changed code that couldn't be analyzed must not look clean.
fn incomplete(
    old_tree: Option<&Tree>,
    new_tree: &Tree,
    new: &VersionCode,
    collector: &mut Collector,
) {
    let problems = new.skipped.iter().map(|(p, r)| (p, r.as_str())).chain(
        new.facts
            .iter()
            .filter_map(|(p, f)| Some((p, f.problem.as_deref()?))),
    );
    for (path, reason) in problems {
        let unchanged = old_tree
            .and_then(|o| o.files.get(path))
            .zip(new_tree.files.get(path))
            .is_some_and(|(a, b)| a.sha256 == b.sha256);
        if unchanged {
            collector.note(format!("{path}: not analyzed in either version: {reason}"));
            continue;
        }
        let (context, _) = new.reach.context(path, true);
        collector.push(
            Finding::new("analysis_incomplete", Capability::Unspecified, context, 0.5)
                .evidence(path, 0, "")
                .attr("reason", reason),
        );
    }
    for entry in &new.reach.missing_entries {
        collector.note(format!("entry point {entry} is not in the package"));
    }
}
