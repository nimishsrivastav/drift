//! Locating, unpacking and indexing a version's artifacts.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use safe_unpack::{EntryKind, Limits, Unpacked};
use sha2::{Digest, Sha256};

/// Where the analyzer may read and write.
#[derive(Debug, Clone)]
pub struct Config {
    /// Every tarball and checkout path in a request must resolve under this directory.
    pub artifacts_root: PathBuf,
    /// Parent for extraction directories; the system temporary directory if unset.
    pub tmp_dir: Option<PathBuf>,
    pub limits: Limits,
    /// Most findings of one kind listed per analysis.
    pub finding_cap: usize,
}

impl Config {
    pub fn new(artifacts_root: impl Into<PathBuf>) -> Self {
        Self {
            artifacts_root: artifacts_root.into(),
            tmp_dir: None,
            limits: Limits {
                max_total_bytes: 512 << 20,
                ..Limits::default()
            },
            finding_cap: 200,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("{0} is not under the artifacts root")]
    OutsideRoot(String),
    #[error("{path}: {err}")]
    Unreadable { path: String, err: io::Error },
    #[error("archive rejected: {0}")]
    Rejected(#[from] safe_unpack::Error),
}

/// Resolves a path from a request and checks it stays under the artifacts root. The request
/// comes from the orchestrator, but a bug there must not let a package read arbitrary files.
pub fn checked_path(root: &Path, raw: &str) -> Result<PathBuf, ArtifactError> {
    let shown = crate::findings::clean(raw, 200);
    let unreadable = |err| ArtifactError::Unreadable {
        path: shown.clone(),
        err,
    };
    let root = root.canonicalize().map_err(unreadable)?;
    let path = Path::new(raw).canonicalize().map_err(unreadable)?;
    if path.starts_with(&root) && path != root {
        Ok(path)
    } else {
        Err(ArtifactError::OutsideRoot(shown))
    }
}

/// One file as npm would install it.
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub disk: PathBuf,
    pub size: u64,
    pub sha256: String,
    pub executable: bool,
    /// The kind of native code, if the file is a binary.
    pub native: Option<&'static str>,
}

/// An unpacked npm tarball, viewed the way npm installs it: the first path component is
/// stripped (npm extracts with `strip: 1`, whatever the directory is called), files directly at
/// the top are dropped, a later entry for the same installed path replaces an earlier one, and
/// links are left out, because npm doesn't extract them.
pub struct Tree {
    _unpacked: Unpacked,
    pub files: BTreeMap<String, FileInfo>,
    /// Top-level directory names. npm's own packer writes only `package`.
    pub roots: BTreeSet<String>,
    /// Links in the archive, which npm skips.
    pub links: usize,
}

impl Tree {
    pub fn from_npm_tarball(path: &Path, config: &Config) -> Result<Self, ArtifactError> {
        // npm reads every tarball as tar, whatever else the bytes might also parse as.
        let unpacked = safe_unpack::unpack_file_as(
            path,
            config.tmp_dir.as_deref(),
            &config.limits,
            &[safe_unpack::Format::TarGz, safe_unpack::Format::Tar],
        )?;
        let mut files = BTreeMap::new();
        let mut roots = BTreeSet::new();
        let mut links = 0;
        for entry in &unpacked.manifest.entries {
            match entry.kind {
                EntryKind::File => {}
                EntryKind::Symlink { .. } | EntryKind::Hardlink { .. } => {
                    links += 1;
                    continue;
                }
                EntryKind::Dir => continue,
            }
            let Some((top, installed)) = entry.path.split_once('/') else {
                continue;
            };
            roots.insert(top.to_owned());
            let disk = unpacked.root().join(&entry.path);
            let info = index_file(&disk, entry.is_executable(), installed).map_err(|err| {
                ArtifactError::Unreadable {
                    path: entry.path.clone(),
                    err,
                }
            })?;
            files.insert(installed.to_owned(), info);
        }
        Ok(Self {
            _unpacked: unpacked,
            files,
            roots,
            links,
        })
    }

    /// Reads at most `max` bytes, and says whether the file was longer.
    pub fn read_prefix(&self, path: &str, max: u64) -> Option<(Vec<u8>, bool)> {
        let info = self.files.get(path)?;
        let mut data = Vec::new();
        File::open(&info.disk)
            .ok()?
            .take(max)
            .read_to_end(&mut data)
            .ok()?;
        Some((data, info.size > max))
    }

    pub fn read(&self, path: &str, max: u64) -> Option<Vec<u8>> {
        let info = self.files.get(path)?;
        read_bounded(&info.disk, max).ok()
    }
}

/// Reads at most `max` bytes; files over that are an error rather than truncated.
pub fn read_bounded(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    File::open(path)?.take(max + 1).read_to_end(&mut data)?;
    if data.len() as u64 > max {
        return Err(io::Error::other("file too large to compare"));
    }
    Ok(data)
}

pub fn index_file(disk: &Path, executable: bool, name: &str) -> io::Result<FileInfo> {
    let mut file = File::open(disk)?;
    let mut hasher = Sha256::new();
    let mut head = Vec::with_capacity(4096);
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if head.len() < 4096 {
            let take = n.min(4096 - head.len());
            head.extend_from_slice(&buf[..take]);
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    Ok(FileInfo {
        disk: disk.to_owned(),
        size,
        sha256: hex(&hasher.finalize()),
        executable,
        native: native_kind(&head, name),
    })
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Identifies native code by magic number, or by an extension Node loads as native code.
pub fn native_kind(head: &[u8], name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    if head.starts_with(b"\x7fELF") {
        return Some("elf");
    }
    if head.starts_with(b"MZ") && head.len() >= 0x40 {
        let offset = u32::from_le_bytes([head[0x3c], head[0x3d], head[0x3e], head[0x3f]]) as usize;
        if head.get(offset..offset + 4) == Some(b"PE\0\0") {
            return Some("pe");
        }
    }
    const MACHO: [[u8; 4]; 4] = [
        [0xfe, 0xed, 0xfa, 0xce],
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xcf, 0xfa, 0xed, 0xfe],
    ];
    if MACHO.iter().any(|m| head.starts_with(m)) {
        return Some("macho");
    }
    // Also the Java class magic, so only counted with a non-class name.
    if head.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) && !lower.ends_with(".class") {
        return Some("macho-universal");
    }
    if head.starts_with(b"\0asm") {
        return Some("wasm");
    }
    if [".node", ".so", ".dylib", ".dll", ".exe"]
        .iter()
        .any(|ext| lower.ends_with(ext))
    {
        return Some("by-extension");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_native_code() {
        assert_eq!(native_kind(b"\x7fELF\x02\x01", "a"), Some("elf"));
        let mut pe = vec![0u8; 0x80];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c] = 0x40;
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        assert_eq!(native_kind(&pe, "x"), Some("pe"));
        assert_eq!(
            native_kind(b"MZ is how this text starts", "notes.txt"),
            None
        );
        assert_eq!(native_kind(&[0xcf, 0xfa, 0xed, 0xfe], "x"), Some("macho"));
        assert_eq!(native_kind(&[0xca, 0xfe, 0xba, 0xbe], "A.class"), None);
        assert_eq!(native_kind(b"\0asm\x01", "x.wasm"), Some("wasm"));
        assert_eq!(
            native_kind(b"anything", "build/Release/addon.node"),
            Some("by-extension")
        );
        assert_eq!(native_kind(b"module.exports = 1", "index.js"), None);
    }

    #[test]
    fn checked_path_stays_under_root() {
        let root = tempfile::tempdir().unwrap();
        let inside = root.path().join("a.tgz");
        std::fs::write(&inside, b"x").unwrap();
        assert!(checked_path(root.path(), inside.to_str().unwrap()).is_ok());

        let outside = tempfile::NamedTempFile::new().unwrap();
        let err = checked_path(root.path(), outside.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ArtifactError::OutsideRoot(_)));

        let sneaky = format!(
            "{}/../{}",
            root.path().display(),
            outside.path().file_name().unwrap().to_str().unwrap()
        );
        assert!(checked_path(root.path(), &sneaky).is_err());
        assert!(checked_path(root.path(), root.path().to_str().unwrap()).is_err());

        std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
        let link = root.path().join("link");
        assert!(matches!(
            checked_path(root.path(), link.to_str().unwrap()),
            Err(ArtifactError::OutsideRoot(_))
        ));
    }
}
