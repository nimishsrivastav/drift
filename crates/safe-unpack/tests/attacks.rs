//! One crafted archive per attack, each rejected with a specific error. The archives live in
//! `tests/attacks/` and are produced by `support::all()`.

mod support;

use std::fs;
use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use safe_unpack::{
    EntryKind, Error, Format, Limits, MemSink, PathError, Sink, unpack_file, unpack_to_sink,
    unpack_to_sink_as,
};

fn attack_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/attacks")
}

fn load(name: &str) -> Vec<u8> {
    fs::read(attack_dir().join(name))
        .unwrap_or_else(|e| panic!("{name}: {e}; run the regenerate test"))
}

fn unpack(name: &str, limits: &Limits) -> Result<(safe_unpack::Manifest, MemSink), Error> {
    let mut sink = MemSink::default();
    let manifest = unpack_to_sink(Cursor::new(load(name)), limits, &mut sink)?;
    Ok((manifest, sink))
}

fn reject(name: &str) -> Error {
    reject_with(name, &Limits::default())
}

fn reject_with(name: &str, limits: &Limits) -> Error {
    match unpack(name, limits) {
        Ok((manifest, _)) => panic!("{name} was accepted: {manifest:?}"),
        Err(err) => err,
    }
}

#[test]
#[ignore = "writes tests/attacks; run explicitly to regenerate"]
fn regenerate() {
    fs::create_dir_all(attack_dir()).unwrap();
    for (name, bytes) in support::all() {
        fs::write(attack_dir().join(name), bytes).unwrap();
    }
}

#[test]
fn every_generated_archive_is_committed() {
    for (name, _) in support::all() {
        assert!(
            attack_dir().join(name).is_file(),
            "{name} missing; run the regenerate test"
        );
    }
}

#[test]
fn path_traversal_is_rejected() {
    for name in [
        "tar_traversal.tgz",
        "tar_long_name_traversal.tgz",
        "tar_pax_path_traversal.tgz",
        "zip_slip.zip",
    ] {
        assert!(
            matches!(
                reject(name),
                Error::BadPath {
                    reason: PathError::Traversal,
                    ..
                }
            ),
            "{name}: {:?}",
            reject(name)
        );
    }
}

#[test]
fn absolute_paths_are_rejected() {
    for name in ["tar_absolute.tgz", "zip_absolute.zip"] {
        assert!(
            matches!(
                reject(name),
                Error::BadPath {
                    reason: PathError::Absolute,
                    ..
                }
            ),
            "{name}"
        );
    }
}

#[test]
fn backslashes_and_control_characters_are_rejected() {
    for name in ["zip_backslash.zip", "tar_control_char.tgz"] {
        let err = reject(name);
        assert!(
            matches!(
                err,
                Error::BadPath {
                    reason: PathError::BadChar,
                    ..
                }
            ),
            "{name}: {err:?}"
        );
        // The error quotes the name with control characters escaped.
        assert!(
            !err.to_string().chars().any(char::is_control),
            "{name}: {err}"
        );
    }
}

#[test]
fn escaping_links_are_rejected() {
    for name in [
        "tar_symlink_escape.tgz",
        "tar_symlink_absolute.tgz",
        "tar_hardlink_escape.tgz",
        "zip_symlink_escape.zip",
    ] {
        let err = reject(name);
        assert!(matches!(err, Error::LinkEscape { .. }), "{name}: {err:?}");
    }
}

#[test]
fn writing_through_a_link_is_rejected() {
    assert!(matches!(
        reject("tar_symlink_write_through.tgz"),
        Error::ThroughLink { .. }
    ));
}

#[test]
fn special_files_are_rejected() {
    for name in ["tar_char_device.tgz", "tar_fifo.tgz", "zip_char_device.zip"] {
        let err = reject(name);
        assert!(matches!(err, Error::SpecialFile { .. }), "{name}: {err:?}");
    }
}

#[test]
fn decompression_bombs_are_rejected() {
    for name in ["tar_gzip_bomb.tgz", "zip_bomb.zip"] {
        let err = reject(name);
        assert!(
            matches!(err, Error::RatioExceeded { limit: 200 }),
            "{name}: {err:?}"
        );
    }
}

#[test]
fn size_limits_hold_without_the_ratio_check() {
    // With the ratio check out of the way, the per-file and total limits still stop a bomb.
    let lenient = Limits {
        max_ratio: u64::MAX,
        ..Limits::default()
    };
    let per_file = Limits {
        max_file_bytes: support::MIB as u64,
        ..lenient.clone()
    };
    for name in ["tar_gzip_bomb.tgz", "zip_bomb.zip"] {
        let err = reject_with(name, &per_file);
        assert!(matches!(err, Error::FileTooLarge { .. }), "{name}: {err:?}");
    }
    let total = Limits {
        max_total_bytes: support::MIB as u64,
        ..lenient
    };
    for name in ["tar_gzip_bomb.tgz", "zip_bomb.zip"] {
        let err = reject_with(name, &total);
        assert!(
            matches!(
                err,
                Error::TotalTooLarge { .. } | Error::StreamTooLarge { .. }
            ),
            "{name}: {err:?}"
        );
    }
}

#[test]
fn entry_count_and_depth_limits_hold() {
    let few = Limits {
        max_entries: 10,
        ..Limits::default()
    };
    assert!(matches!(
        reject_with("tar_many_entries.tgz", &few),
        Error::TooManyEntries { limit: 10 }
    ));
    assert!(unpack("tar_many_entries.tgz", &Limits::default()).is_ok());
    assert!(matches!(
        reject("tar_deep_path.tgz"),
        Error::BadPath {
            reason: PathError::TooDeep,
            ..
        }
    ));
}

#[test]
fn hostile_tar_extensions_are_rejected() {
    assert!(matches!(
        reject("tar_huge_extension.tgz"),
        Error::ExtensionTooLarge { .. }
    ));
    assert!(matches!(
        reject("tar_pax_size_override.tgz"),
        Error::Unsupported { .. }
    ));
    assert!(matches!(
        reject("tar_pax_global_path.tgz"),
        Error::Unsupported { .. }
    ));
    assert!(matches!(
        reject("tar_sparse.tgz"),
        Error::Unsupported { .. }
    ));
}

#[test]
fn duplicates_and_conflicts_are_rejected() {
    assert!(matches!(
        reject("tar_duplicate.tgz"),
        Error::Duplicate { .. }
    ));
    assert!(matches!(
        reject("tar_file_dir_conflict.tgz"),
        Error::Conflict { .. }
    ));
}

#[test]
fn benign_tarball_extracts_with_links_recorded_only() {
    let (manifest, sink) = unpack("benign.tgz", &Limits::default()).unwrap();
    assert_eq!(manifest.format, Format::TarGz);
    let long = format!("package/{}.js", "n".repeat(120));
    let files: Vec<&str> = sink.files.keys().map(String::as_str).collect();
    assert_eq!(
        files,
        [
            "package/bin.js",
            "package/lib/a.js",
            long.as_str(),
            "package/package.json",
            "package/pax name ✓.js"
        ]
    );
    let link = manifest
        .entries
        .iter()
        .find(|e| e.path == "package/alias.js")
        .unwrap();
    assert_eq!(
        link.kind,
        EntryKind::Symlink {
            target: "package/lib/a.js".into()
        }
    );
    let bin = manifest
        .entries
        .iter()
        .find(|e| e.path == "package/bin.js")
        .unwrap();
    assert!(bin.is_executable());
    assert_eq!(
        manifest.total_bytes,
        sink.files.values().map(|v| v.len() as u64).sum::<u64>()
    );
}

#[test]
fn benign_zip_extracts() {
    let (manifest, sink) = unpack("benign.zip", &Limits::default()).unwrap();
    assert_eq!(manifest.format, Format::Zip);
    assert_eq!(sink.files["pkg/__init__.py"], b"# synthetic fixture\n");
}

#[test]
fn extraction_to_disk_never_creates_links_or_executables() {
    let parent = tempfile::tempdir().unwrap();
    let unpacked = unpack_file(
        &attack_dir().join("benign.tgz"),
        Some(parent.path()),
        &Limits::default(),
    )
    .unwrap();
    let root = unpacked.root();
    assert!(
        fs::symlink_metadata(root.join("package/alias.js")).is_err(),
        "link was created"
    );
    let mode = fs::metadata(root.join("package/bin.js"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o644);
    assert_eq!(
        fs::read(root.join("package/lib/a.js")).unwrap(),
        b"module.exports = 1;\n"
    );
}

#[test]
fn failed_extraction_leaves_nothing_behind() {
    let parent = tempfile::tempdir().unwrap();
    for (name, _) in support::all() {
        if name.starts_with("benign") || name == "tar_many_entries.tgz" {
            continue;
        }
        let err = unpack_file(
            &attack_dir().join(name),
            Some(parent.path()),
            &Limits::default(),
        );
        assert!(err.is_err(), "{name} was accepted");
        let left: Vec<_> = fs::read_dir(parent.path()).unwrap().collect();
        assert!(left.is_empty(), "{name} left {left:?}");
    }
    assert!(!Path::new("/tmp/drift-safe-unpack-evil.txt").exists());
}

#[test]
fn data_after_one_zero_block_is_rejected() {
    let err = reject("tar_zero_block_smuggle.tgz");
    assert!(
        matches!(err, Error::Malformed(ref m) if m.contains("after the end-of-archive")),
        "{err:?}"
    );
}

#[test]
fn non_canonical_paths_are_rejected() {
    for name in ["tar_dot_prefix.tgz", "tar_empty_component.tgz"] {
        let err = reject(name);
        assert!(
            matches!(
                err,
                Error::BadPath {
                    reason: PathError::NotCanonical,
                    ..
                }
            ),
            "{name}: {err:?}"
        );
    }
    let err = reject("tar_file_with_trailing_slash.tgz");
    assert!(
        matches!(
            err,
            Error::BadPath {
                reason: PathError::TrailingSlash,
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn competing_extension_headers_are_rejected() {
    assert!(matches!(
        reject("tar_pax_and_long_name.tgz"),
        Error::Malformed(_)
    ));
}

#[test]
fn ambiguous_zips_are_rejected() {
    for name in ["zip_trailing_data.zip", "zip_two_eocd.zip"] {
        let err = reject(name);
        assert!(matches!(err, Error::Malformed(_)), "{name}: {err:?}");
    }
}

#[test]
fn callers_can_require_a_format() {
    // npm reads every tarball as tar, so a file that parses as a zip must not be analyzed as one.
    let tar_only = [Format::TarGz, Format::Tar];
    let mut sink = MemSink::default();
    let err = unpack_to_sink_as(
        Cursor::new(load("benign.zip")),
        &Limits::default(),
        &mut sink,
        &tar_only,
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            Error::UnexpectedFormat {
                found: Format::Zip,
                ..
            }
        ),
        "{err:?}"
    );
    assert!(sink.files.is_empty());
    let sink: &mut dyn Sink = &mut MemSink::default();
    assert!(
        unpack_to_sink_as(
            Cursor::new(load("benign.tgz")),
            &Limits::default(),
            sink,
            &tar_only
        )
        .is_ok()
    );
}

#[test]
fn path_memory_is_bounded() {
    let small = Limits {
        max_path_bytes_total: 256,
        ..Limits::default()
    };
    assert!(matches!(
        reject_with("tar_many_entries.tgz", &small),
        Error::PathBytesExceeded { limit: 256 }
    ));
}

#[test]
fn errors_never_carry_raw_control_characters() {
    for (name, _) in support::all() {
        if let Err(err) = unpack(name, &Limits::default()) {
            let shown = err.to_string();
            assert!(!shown.chars().any(char::is_control), "{name}: {shown:?}");
        }
    }
}
