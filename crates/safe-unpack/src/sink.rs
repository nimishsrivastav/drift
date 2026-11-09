//! Where extracted entries go. The walker has already validated every path a sink sees: it is
//! relative, normalized, free of `..`, and no ancestor of it is a file or a link.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::Error;

/// Receives validated entries. Links are never passed to a sink: they are only recorded in the
/// [`crate::Manifest`], so nothing on disk can redirect a later write.
pub trait Sink {
    /// Creates a directory, and any missing parents.
    fn dir(&mut self, path: &str) -> io::Result<()>;
    /// Creates a new file from `content`, reading it to the end, and creating missing parents.
    /// Returns the number of bytes written.
    fn file(&mut self, path: &str, content: &mut dyn Read) -> io::Result<u64>;
}

/// Writes entries under a directory. Files are created with `O_EXCL`, so an existing file or
/// link is never overwritten or followed, and with mode 0644: nothing extracted is executable.
pub struct DirSink {
    root: PathBuf,
}

impl DirSink {
    /// `root` must be an existing, empty directory.
    pub fn new(root: &Path) -> Result<Self, Error> {
        let bad = || Error::BadDestination(root.to_owned());
        let root = fs::canonicalize(root).map_err(|_| bad())?;
        if !root.is_dir() || fs::read_dir(&root).map_err(|_| bad())?.next().is_some() {
            return Err(bad());
        }
        Ok(Self { root })
    }

    fn make_parents(&self, path: &Path) -> io::Result<()> {
        match path.parent() {
            Some(parent) if parent != self.root => {
                DirBuilder::new().recursive(true).mode(0o755).create(parent)
            }
            _ => Ok(()),
        }
    }
}

impl Sink for DirSink {
    fn dir(&mut self, path: &str) -> io::Result<()> {
        DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(self.root.join(path))
    }

    fn file(&mut self, path: &str, content: &mut dyn Read) -> io::Result<u64> {
        let target = self.root.join(path);
        self.make_parents(&target)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&target)?;
        let mut out = BufWriter::new(file);
        let written = io::copy(content, &mut out)?;
        out.flush()?;
        Ok(written)
    }
}

/// Keeps entries in memory. Used by the fuzz target and tests; memory use is bounded by the
/// same limits as extraction to disk.
#[derive(Debug, Default)]
pub struct MemSink {
    pub dirs: BTreeSet<String>,
    pub files: BTreeMap<String, Vec<u8>>,
}

impl Sink for MemSink {
    fn dir(&mut self, path: &str) -> io::Result<()> {
        self.dirs.insert(path.to_owned());
        Ok(())
    }

    fn file(&mut self, path: &str, content: &mut dyn Read) -> io::Result<u64> {
        let mut data = Vec::new();
        content.read_to_end(&mut data)?;
        let written = data.len() as u64;
        if self.files.insert(path.to_owned(), data).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "file written twice",
            ));
        }
        Ok(written)
    }
}

/// Reads and discards contents, still enforcing every limit. For callers that only want the
/// manifest.
#[derive(Debug, Default)]
pub struct NullSink;

impl Sink for NullSink {
    fn dir(&mut self, _: &str) -> io::Result<()> {
        Ok(())
    }

    fn file(&mut self, _: &str, content: &mut dyn Read) -> io::Result<u64> {
        io::copy(content, &mut io::sink())
    }
}
