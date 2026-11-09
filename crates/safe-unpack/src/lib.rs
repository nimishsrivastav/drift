//! Hardened archive extraction for untrusted packages.
//!
//! Supports gzipped tar (npm tarballs, sdists), plain tar, and zip (wheels). Defends against
//! path traversal and zip-slip, absolute paths, links that escape the root or are written
//! through, device files, duplicate and conflicting entries, and decompression bombs. Limits
//! ([`Limits`]) are enforced while the archive streams, on bytes actually produced.
//!
//! Links are never created on disk. They are recorded in the [`Manifest`] with their resolved
//! target, and an archive whose link points outside the root is rejected. Extracted files are
//! never executable; each entry's original mode is kept in the manifest.
//!
//! Nothing here interprets file contents, and nothing extracted is ever run.

mod error;
mod limits;
mod meter;
mod path;
mod sink;
mod tar_fmt;
mod walker;
mod zip_fmt;

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub use error::{Error, PathError};
pub use limits::Limits;
pub use sink::{DirSink, MemSink, NullSink, Sink};

use meter::Meter;
use walker::Walker;

/// Archive formats, detected from content, never from a file name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    TarGz,
    Tar,
    Zip,
}

/// What an entry is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    /// Not created on disk. `target` is resolved to a root-relative path; empty means the root.
    Symlink {
        target: String,
    },
    /// Not created on disk. `target` is root-relative.
    Hardlink {
        target: String,
    },
}

/// One extracted entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Normalized, root-relative, `/`-separated.
    pub path: String,
    pub kind: EntryKind,
    /// Bytes written, for files.
    pub size: u64,
    /// Permission bits from the archive (`0o7777` at most), or 0 if it records none.
    pub mode: u32,
}

impl Entry {
    /// Whether the archive marked this file executable by anyone.
    pub fn is_executable(&self) -> bool {
        self.kind == EntryKind::File && self.mode & 0o111 != 0
    }
}

/// Everything an archive contained, in archive order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub format: Format,
    pub entries: Vec<Entry>,
    /// Sum of file sizes.
    pub total_bytes: u64,
}

/// Identifies a format from the first bytes of an archive.
pub fn detect(header: &[u8]) -> Option<Format> {
    if header.starts_with(&[0x1f, 0x8b]) {
        Some(Format::TarGz)
    } else if header.starts_with(b"PK\x03\x04") || header.starts_with(b"PK\x05\x06") {
        Some(Format::Zip)
    } else if header.len() >= 262 && &header[257..262] == b"ustar" {
        Some(Format::Tar)
    } else {
        None
    }
}

/// Extracts an archive into `sink`, enforcing `limits`.
pub fn unpack_to_sink<R: Read + Seek>(
    mut input: R,
    limits: &Limits,
    sink: &mut dyn Sink,
) -> Result<Manifest, Error> {
    let size = input.seek(SeekFrom::End(0)).map_err(Error::Io)?;
    if size > limits.max_archive_bytes {
        return Err(Error::ArchiveTooLarge {
            size,
            limit: limits.max_archive_bytes,
        });
    }
    input.seek(SeekFrom::Start(0)).map_err(Error::Io)?;
    let mut header = Vec::with_capacity(512);
    (&mut input)
        .take(512)
        .read_to_end(&mut header)
        .map_err(Error::Io)?;
    input.seek(SeekFrom::Start(0)).map_err(Error::Io)?;
    let format = detect(&header).ok_or(Error::UnknownFormat)?;

    let meter = Meter::new(limits);
    let mut walker = Walker::new(limits, &meter, sink);
    match format {
        Format::TarGz => tar_fmt::walk_gz(input, &mut walker)?,
        Format::Tar => tar_fmt::walk_plain(input, &mut walker)?,
        Format::Zip => zip_fmt::walk(input, size, &mut walker)?,
    }
    let entries = walker.entries;
    Ok(Manifest {
        format,
        entries,
        total_bytes: meter.total_written(),
    })
}

/// Extracts an archive into `dest`, which must be an existing, empty directory. On error,
/// `dest` may hold a partial extraction; the caller should discard it.
pub fn unpack_into<R: Read + Seek>(
    input: R,
    dest: &Path,
    limits: &Limits,
) -> Result<Manifest, Error> {
    let mut sink = DirSink::new(dest)?;
    unpack_to_sink(input, limits, &mut sink)
}

/// An archive extracted into a fresh temporary directory, deleted when this is dropped.
#[derive(Debug)]
pub struct Unpacked {
    dir: tempfile::TempDir,
    pub manifest: Manifest,
}

impl Unpacked {
    pub fn root(&self) -> &Path {
        self.dir.path()
    }
}

/// Extracts the archive at `archive` into a fresh temporary directory under `parent`, or under
/// the system temporary directory if `parent` is `None`. A failed extraction leaves nothing behind.
pub fn unpack_file(
    archive: &Path,
    parent: Option<&Path>,
    limits: &Limits,
) -> Result<Unpacked, Error> {
    let file = File::open(archive).map_err(Error::Io)?;
    if !file.metadata().map_err(Error::Io)?.is_file() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "archive is not a regular file",
        )));
    }
    let mut builder = tempfile::Builder::new();
    builder.prefix("safe-unpack-");
    let dir = match parent {
        Some(parent) => builder.tempdir_in(parent),
        None => builder.tempdir(),
    }
    .map_err(Error::Io)?;
    let manifest = unpack_into(std::io::BufReader::new(file), dir.path(), limits)?;
    Ok(Unpacked { dir, manifest })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_formats_by_content() {
        assert_eq!(detect(&[0x1f, 0x8b, 8, 0]), Some(Format::TarGz));
        assert_eq!(detect(b"PK\x03\x04rest"), Some(Format::Zip));
        assert_eq!(detect(b"PK\x05\x06"), Some(Format::Zip));
        let mut tar = vec![0u8; 512];
        tar[257..262].copy_from_slice(b"ustar");
        assert_eq!(detect(&tar), Some(Format::Tar));
        assert_eq!(detect(b"#!/bin/sh\n"), None);
        assert_eq!(detect(b""), None);
    }

    #[test]
    fn rejects_oversized_input_before_reading_it() {
        let limits = Limits {
            max_archive_bytes: 4,
            ..Limits::default()
        };
        let err = unpack_to_sink(
            std::io::Cursor::new(vec![0x1f, 0x8b, 0, 0, 0]),
            &limits,
            &mut NullSink,
        )
        .unwrap_err();
        assert!(matches!(err, Error::ArchiveTooLarge { size: 5, limit: 4 }));
    }

    #[test]
    fn rejects_unknown_formats() {
        let err = unpack_to_sink(
            std::io::Cursor::new(b"not an archive".to_vec()),
            &Limits::default(),
            &mut NullSink,
        )
        .unwrap_err();
        assert!(matches!(err, Error::UnknownFormat));
    }
}
