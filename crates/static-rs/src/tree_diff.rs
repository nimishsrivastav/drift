//! File-tree diff between two versions as npm installs them.

use std::collections::BTreeSet;

use drift_proto::v1::{Capability, ExecContext};

use crate::artifact::{FileInfo, Tree};
use crate::findings::{Collector, Finding};

/// Reports added and modified files and new native binaries. Removed files are not drift.
///
/// With no `old` (new-package mode) only what matters on its own is reported: native binaries,
/// files that install hooks run, and an unusual archive layout. Listing every file of a new
/// package would say nothing.
pub fn diff(
    old: Option<&Tree>,
    new: &Tree,
    install_files: &BTreeSet<String>,
    collector: &mut Collector,
) {
    for (path, info) in &new.files {
        let at_install = install_files.contains(path);
        let context = if at_install {
            ExecContext::Install
        } else {
            ExecContext::Unspecified
        };
        let previous = old.map(|o| o.files.get(path));

        let changed = match previous {
            Some(Some(p)) if p.sha256 == info.sha256 => continue,
            Some(Some(p)) => Some(p),
            Some(None) | None => None,
        };
        if info.native.is_some() && changed.is_none_or(|p| p.native.is_none()) {
            collector.push(native(path, info, context, changed.is_some()));
            continue;
        }
        if old.is_none() && !at_install {
            continue;
        }
        let finding = match changed {
            None => Finding::new(
                "file_added",
                Capability::Unspecified,
                context,
                if at_install { 0.8 } else { 0.3 },
            ),
            Some(p) => Finding::new(
                "file_modified",
                Capability::Unspecified,
                context,
                if at_install { 0.7 } else { 0.2 },
            )
            .attr("old_sha256", &p.sha256),
        };
        collector.push(
            finding
                .evidence(path, 0, "")
                .attr("sha256", &info.sha256)
                .attr("size", info.size.to_string())
                .attr("run_by_install_hook", at_install.to_string()),
        );
    }

    let had_extra_roots = old.is_some_and(|o| o.roots.len() > 1);
    if new.roots.len() > 1 && !had_extra_roots {
        let roots: Vec<&str> = new.roots.iter().map(String::as_str).collect();
        // npm strips the top directory whatever its name, so these merge on install, and a
        // later entry silently replaces an earlier one at the same installed path.
        collector.push(
            Finding::new(
                "tarball_multiple_roots",
                Capability::Unspecified,
                ExecContext::Install,
                0.6,
            )
            .attr("roots", roots.join(", ")),
        );
    }
}

fn native(path: &str, info: &FileInfo, context: ExecContext, replaced: bool) -> Finding {
    let kind = info.native.unwrap_or_default();
    let confidence = if kind == "by-extension" { 0.5 } else { 0.8 };
    Finding::new(
        "native_binary_added",
        Capability::NativeBinary,
        context,
        confidence,
    )
    .evidence(path, 0, "")
    .attr("binary", kind)
    .attr("sha256", &info.sha256)
    .attr("size", info.size.to_string())
    .attr("replaced_non_binary", replaced.to_string())
}
