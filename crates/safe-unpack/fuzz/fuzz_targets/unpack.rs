//! Feeds arbitrary bytes to the unpacker and checks what it accepts. A crash, a hang, an
//! out-of-memory or a broken invariant is a finding.
//!
//! Run: `just fuzz` (or `cargo +nightly fuzz run unpack` in `crates/safe-unpack`).

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use safe_unpack::{EntryKind, Limits, MemSink, unpack_to_sink};

/// Small limits keep each run fast; the limit logic is the same at any scale.
fn limits() -> Limits {
    Limits {
        max_archive_bytes: 1 << 20,
        max_total_bytes: 2 << 20,
        max_file_bytes: 1 << 20,
        max_entries: 512,
        max_depth: 16,
        max_path_bytes: 512,
        max_ratio: 50,
        ratio_grace_bytes: 256 << 10,
        max_extension_bytes: 4 << 10,
    }
}

fn assert_normalized(path: &str) {
    assert!(!path.is_empty(), "empty path accepted");
    assert!(!path.starts_with('/'), "absolute path accepted: {path:?}");
    assert!(!path.contains('\\'), "backslash accepted: {path:?}");
    assert!(
        !path.chars().any(char::is_control),
        "control character accepted: {path:?}"
    );
    for part in path.split('/') {
        assert!(
            !part.is_empty() && part != "." && part != "..",
            "unnormalized path accepted: {path:?}"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let limits = limits();
    let mut sink = MemSink::default();
    let Ok(manifest) = unpack_to_sink(Cursor::new(data), &limits, &mut sink) else {
        return;
    };

    assert!(manifest.entries.len() as u64 <= limits.max_entries);
    assert!(manifest.total_bytes <= limits.max_total_bytes);
    let written: u64 = sink.files.values().map(|f| f.len() as u64).sum();
    assert_eq!(written, manifest.total_bytes);

    for entry in &manifest.entries {
        assert_normalized(&entry.path);
        assert!(entry.path.split('/').count() <= limits.max_depth);
        match &entry.kind {
            EntryKind::File => {
                assert!(entry.size <= limits.max_file_bytes);
                assert_eq!(sink.files[&entry.path].len() as u64, entry.size);
            }
            EntryKind::Dir => assert!(sink.dirs.contains(&entry.path)),
            EntryKind::Symlink { target } => {
                // Empty means the root, which is inside it.
                if !target.is_empty() {
                    assert_normalized(target);
                }
                assert!(!sink.files.contains_key(&entry.path) && !sink.dirs.contains(&entry.path));
            }
            EntryKind::Hardlink { target } => {
                assert_normalized(target);
                assert!(!sink.files.contains_key(&entry.path) && !sink.dirs.contains(&entry.path));
            }
        }
    }
    // Nothing reached the sink that the manifest doesn't account for.
    for path in sink.files.keys() {
        assert!(
            manifest
                .entries
                .iter()
                .any(|e| &e.path == path && e.kind == EntryKind::File)
        );
    }
});
