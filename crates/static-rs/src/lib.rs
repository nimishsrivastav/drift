//! Static capability-drift analysis. Package contents are parsed, never run.
//!
//! Per pair: the file-tree diff, the `package.json` install-hook and dependency diffs, the
//! tarball-vs-repo diff, and the capability diff, with each capability placed in the context
//! (install, import or call) that reaches it.

pub mod artifact;
pub mod capabilities;
pub mod capability_diff;
pub mod context;
pub mod depgraph;
pub mod findings;
pub mod npm_manifest;
pub mod obfuscation;
pub mod tarball_vs_repo;
pub mod tree_diff;

use std::collections::BTreeSet;
use std::time::Instant;

use capability_diff::FactCache;

use drift_proto::v1::{
    AnalyzeResponse, ArtifactPair, Capability, Ecosystem, ExecContext, PackageVersion,
};

pub use artifact::Config;
use artifact::{ArtifactError, Tree, checked_path};
use findings::{Collector, Finding};
use tarball_vs_repo::Repo;

/// `repo_ref` when the orchestrator found no source; see orchestrator/internal/repo.
const UNRESOLVED: &str = "unresolved";

/// Analyzes one pair. Problems with the request or one version become notes in `errors`; an
/// archive the unpacker rejects becomes a finding, because a package that can't be inspected
/// must not look clean.
pub fn analyze(pair: &ArtifactPair, config: &Config) -> AnalyzeResponse {
    let started = Instant::now();
    let mut collector = Collector::new(config.finding_cap);
    run(pair, config, &mut collector);
    let (findings, errors) = collector.finish();
    AnalyzeResponse {
        findings,
        errors,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn run(pair: &ArtifactPair, config: &Config, collector: &mut Collector) {
    let Some(new) = &pair.new else {
        collector.note("request has no new version");
        return;
    };
    if new.ecosystem() != Ecosystem::Npm {
        collector.note(format!(
            "ecosystem {:?} is not supported yet",
            new.ecosystem()
        ));
        return;
    }

    let old_tree = match pair.old.as_ref().map(|old| load(old, config)) {
        None => None,
        Some(Ok(tree)) => Some(tree),
        Some(Err(err)) => {
            collector.note(format!(
                "old version unusable, analyzing the new one on its own: {err}"
            ));
            None
        }
    };
    let old_rejected = pair.old.is_some() && old_tree.is_none();
    let new_tree = match load(new, config) {
        Ok(tree) => tree,
        Err(ArtifactError::Rejected(err)) => {
            // If the old version was unusable too, this says less about the update.
            let confidence = if old_rejected { 0.3 } else { 0.7 };
            collector.push(
                Finding::new(
                    "archive_rejected",
                    Capability::Unspecified,
                    ExecContext::Install,
                    confidence,
                )
                .attr("error", err.to_string()),
            );
            return;
        }
        Err(err) => {
            collector.note(format!("new version unusable: {err}"));
            return;
        }
    };

    let old_manifest = old_tree
        .as_ref()
        .and_then(|t| manifest(t, "old", collector));
    let new_manifest = manifest(&new_tree, "new", collector);
    let old_hooks = old_tree
        .as_ref()
        .map(|t| npm_manifest::install_hooks(old_manifest.as_ref(), t));
    let new_hooks = npm_manifest::install_hooks(new_manifest.as_ref(), &new_tree);
    npm_manifest::diff_hooks(
        old_hooks.as_ref(),
        &new_hooks,
        new_manifest.as_ref(),
        collector,
    );
    depgraph::diff(
        old_manifest.as_ref(),
        new_manifest.as_ref(),
        pair.old.is_none(),
        collector,
    );
    // Files that changed are parsed first, so padding can't push them out of the budget.
    let changed: BTreeSet<String> = new_tree
        .files
        .iter()
        .filter(|(path, info)| {
            old_tree
                .as_ref()
                .and_then(|o| o.files.get(*path))
                .is_none_or(|o| o.sha256 != info.sha256)
        })
        .map(|(path, _)| path.clone())
        .collect();
    let mut cache = FactCache::new(capability_diff::PARSE_BUDGET);
    let new_code = capability_diff::analyze_version(
        &new_tree,
        new_manifest.as_ref(),
        &new_hooks,
        &changed,
        &mut cache,
    );
    let old_code = old_tree
        .as_ref()
        .zip(old_hooks.as_ref())
        .map(|(tree, hooks)| {
            capability_diff::analyze_version(
                tree,
                old_manifest.as_ref(),
                hooks,
                &changed,
                &mut cache,
            )
        });
    // Every file an install hook runs, directly or through what it imports.
    let install_files: BTreeSet<String> = new_code.reach.install.keys().cloned().collect();

    tree_diff::diff(old_tree.as_ref(), &new_tree, &install_files, collector);
    capability_diff::diff(
        old_tree.as_ref(),
        old_code.as_ref(),
        &new_tree,
        &new_code,
        collector,
    );

    match repo_for(pair, config, collector) {
        Some(repo) => tarball_vs_repo::diff(
            old_tree.as_ref(),
            &new_tree,
            &repo,
            &install_files,
            collector,
        ),
        None => {
            collector.note("tarball-vs-repo diff skipped: no source checkout for either version")
        }
    }
}

fn load(version: &PackageVersion, config: &Config) -> Result<Tree, ArtifactError> {
    let path = checked_path(&config.artifacts_root, &version.tarball_path)?;
    Tree::from_npm_tarball(&path, config)
}

fn manifest(tree: &Tree, which: &str, collector: &mut Collector) -> Option<npm_manifest::Manifest> {
    let loaded = npm_manifest::load(tree);
    if let Some(problem) = loaded.problem {
        if which == "new" {
            // npm may well accept what we couldn't parse, so this is a finding, not a note.
            collector.push(
                Finding::new(
                    "manifest_unparseable",
                    Capability::Unspecified,
                    ExecContext::Install,
                    0.7,
                )
                .evidence("package.json", 0, "")
                .attr("error", problem),
            );
        } else {
            collector.note(format!("{which} version: {problem}"));
        }
    }
    loaded.manifest
}

/// The new version's checkout, or the old version's with less confidence: files missing from
/// last release's source are weaker evidence than files missing from this release's.
fn repo_for(pair: &ArtifactPair, config: &Config, collector: &mut Collector) -> Option<Repo> {
    let new = pair.new.as_ref()?;
    let candidates = [(Some(new), 1.0, "new"), (pair.old.as_ref(), 0.5, "old")];
    for (version, confidence, which) in candidates {
        let Some(version) = version else { continue };
        if version.repo_ref == UNRESOLVED
            || version.repo_ref.is_empty()
            || version.repo_path.is_empty()
        {
            continue;
        }
        match checked_path(&config.artifacts_root, &version.repo_path) {
            Ok(root) => {
                let mut repo = Repo::locate(root, &new.name, &version.repo_ref, confidence);
                if which == "old" {
                    repo.caveats.push(format!(
                        "new version's source unresolved; compared with {}",
                        version.repo_ref
                    ));
                }
                return Some(repo);
            }
            Err(err) => collector.note(format!("{which} version's checkout unusable: {err}")),
        }
    }
    None
}
