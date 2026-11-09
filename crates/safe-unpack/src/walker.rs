//! Format-independent entry checks: counting, duplicates, conflicts and links.

use std::collections::HashMap;
use std::io::{self, Read};

use crate::error::quote;
use crate::meter::{FileBudget, Meter};
use crate::path::{resolve_symlink, sanitize};
use crate::{Entry, EntryKind, Error, Limits, Sink};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Occupant {
    Dir,
    File,
    Link,
}

pub(crate) struct Walker<'a> {
    pub(crate) limits: &'a Limits,
    pub(crate) meter: &'a Meter,
    sink: &'a mut dyn Sink,
    seen: HashMap<String, Occupant>,
    seen_bytes: u64,
    count: u64,
    pub(crate) entries: Vec<Entry>,
}

impl<'a> Walker<'a> {
    pub(crate) fn new(limits: &'a Limits, meter: &'a Meter, sink: &'a mut dyn Sink) -> Self {
        Self {
            limits,
            meter,
            sink,
            seen: HashMap::new(),
            seen_bytes: 0,
            count: 0,
            entries: Vec::new(),
        }
    }

    pub(crate) fn io(&self, err: io::Error) -> Error {
        self.meter.error(err)
    }

    /// Counts an entry and checks its path.
    fn admit(&mut self, raw: &[u8]) -> Result<String, Error> {
        self.count += 1;
        if self.count > self.limits.max_entries {
            return Err(Error::TooManyEntries {
                limit: self.limits.max_entries,
            });
        }
        sanitize(raw, self.limits).map_err(|reason| Error::BadPath {
            path: quote(raw),
            reason,
        })
    }

    /// Remembers a path, bounding the memory that remembering every path and ancestor takes.
    fn remember(&mut self, path: &str, occupant: Occupant) -> Result<(), Error> {
        self.seen_bytes = self.seen_bytes.saturating_add(path.len() as u64);
        if self.seen_bytes > self.limits.max_path_bytes_total {
            return Err(Error::PathBytesExceeded {
                limit: self.limits.max_path_bytes_total,
            });
        }
        self.seen.insert(path.to_owned(), occupant);
        Ok(())
    }

    /// Checks that nothing above `path` is a file or a link, and records missing ancestors as
    /// directories, so a later file can't take their place.
    fn claim_ancestors(&mut self, path: &str) -> Result<(), Error> {
        let mut end = 0;
        while let Some(offset) = path[end..].find('/') {
            end += offset;
            let ancestor = &path[..end];
            match self.seen.get(ancestor) {
                Some(Occupant::Dir) => {}
                Some(Occupant::File) => {
                    return Err(Error::Conflict {
                        path: quote(path.as_bytes()),
                    });
                }
                Some(Occupant::Link) => {
                    return Err(Error::ThroughLink {
                        path: quote(path.as_bytes()),
                    });
                }
                None => self.remember(ancestor, Occupant::Dir)?,
            }
            end += 1;
        }
        Ok(())
    }

    /// Claims `path` itself for a new entry. Repeating a directory is allowed; anything else
    /// appearing twice is not, because extractors disagree on which copy wins.
    fn claim(&mut self, path: &str, occupant: Occupant) -> Result<bool, Error> {
        self.claim_ancestors(path)?;
        match self.seen.get(path) {
            None => {
                self.remember(path, occupant)?;
                Ok(true)
            }
            Some(Occupant::Dir) if occupant == Occupant::Dir => Ok(false),
            Some(existing) if *existing == occupant => Err(Error::Duplicate {
                path: quote(path.as_bytes()),
            }),
            Some(_) => Err(Error::Conflict {
                path: quote(path.as_bytes()),
            }),
        }
    }

    pub(crate) fn dir(&mut self, raw: &[u8], mode: u32) -> Result<(), Error> {
        let path = self.admit(raw)?;
        if self.claim(&path, Occupant::Dir)? {
            self.sink.dir(&path).map_err(Error::Io)?;
            self.entries.push(Entry {
                path,
                kind: EntryKind::Dir,
                size: 0,
                mode,
            });
        }
        Ok(())
    }

    /// Extracts a file. `declared` is the size the archive claims, checked up front so that an
    /// honest oversized file fails fast; the budget still counts the bytes actually read.
    pub(crate) fn file(
        &mut self,
        raw: &[u8],
        mode: u32,
        declared: u64,
        content: &mut dyn Read,
    ) -> Result<(), Error> {
        let path = self.admit(raw)?;
        // node-tar treats a regular entry named `dir/` as a directory.
        if raw.ends_with(b"/") {
            return Err(Error::BadPath {
                path: quote(raw),
                reason: crate::PathError::TrailingSlash,
            });
        }
        self.claim(&path, Occupant::File)?;
        if declared > self.limits.max_file_bytes {
            return Err(Error::FileTooLarge {
                path,
                limit: self.limits.max_file_bytes,
            });
        }
        if self.meter.total_written().saturating_add(declared) > self.limits.max_total_bytes {
            return Err(Error::TotalTooLarge {
                limit: self.limits.max_total_bytes,
            });
        }
        let meter = self.meter;
        let mut budget = FileBudget::new(content, meter, &path);
        let result = self.sink.file(&path, &mut budget);
        let read = budget.bytes_read();
        let written = result.map_err(|e| meter.error(e))?;
        debug_assert!(written <= read);
        self.entries.push(Entry {
            path,
            kind: EntryKind::File,
            size: written,
            mode,
        });
        Ok(())
    }

    pub(crate) fn symlink(&mut self, raw: &[u8], target: &[u8]) -> Result<(), Error> {
        let path = self.admit(raw)?;
        let Some(resolved) = resolve_symlink(&path, target, self.limits) else {
            return Err(Error::LinkEscape {
                path,
                target: quote(target),
            });
        };
        self.claim(&path, Occupant::Link)?;
        self.entries.push(Entry {
            path,
            kind: EntryKind::Symlink { target: resolved },
            size: 0,
            mode: 0,
        });
        Ok(())
    }

    pub(crate) fn hardlink(&mut self, raw: &[u8], target: &[u8]) -> Result<(), Error> {
        let path = self.admit(raw)?;
        // Hard link targets are relative to the archive root, not to the link.
        let resolved = match sanitize(target, self.limits) {
            Ok(resolved) => resolved,
            _ => {
                return Err(Error::LinkEscape {
                    path,
                    target: quote(target),
                });
            }
        };
        self.claim(&path, Occupant::Link)?;
        self.entries.push(Entry {
            path,
            kind: EntryKind::Hardlink { target: resolved },
            size: 0,
            mode: 0,
        });
        Ok(())
    }

    /// Rejects an entry type we never extract.
    pub(crate) fn refuse(&self, raw: &[u8], special: bool, what: &str) -> Error {
        let path = quote(raw);
        if special {
            Error::SpecialFile { path }
        } else {
            Error::Unsupported {
                path,
                what: what.to_owned(),
            }
        }
    }
}
