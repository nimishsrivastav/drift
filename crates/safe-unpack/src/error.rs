//! Errors. Paths quoted in errors come from the archive, so they are escaped and truncated.

use std::path::PathBuf;

/// Why a path from an archive was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    #[error("empty path")]
    Empty,
    #[error("absolute path")]
    Absolute,
    #[error("parent-directory component")]
    Traversal,
    #[error("not valid UTF-8")]
    NotUtf8,
    #[error("control character, NUL or backslash in path")]
    BadChar,
    #[error("path is too deep")]
    TooDeep,
    #[error("path is too long")]
    TooLong,
}

/// An archive that can't be extracted safely, or an I/O failure while extracting it.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("archive is {size} bytes, over the {limit}-byte limit")]
    ArchiveTooLarge { size: u64, limit: u64 },
    #[error("unrecognized archive format")]
    UnknownFormat,
    #[error("more than {limit} entries")]
    TooManyEntries { limit: u64 },
    #[error("{path}: file exceeds the {limit}-byte per-file limit")]
    FileTooLarge { path: String, limit: u64 },
    #[error("extracted files exceed the {limit}-byte total limit")]
    TotalTooLarge { limit: u64 },
    #[error("decompressed stream exceeds {limit} bytes")]
    StreamTooLarge { limit: u64 },
    #[error("compression ratio exceeds {limit}:1")]
    RatioExceeded { limit: u64 },
    #[error("{path}: {reason}")]
    BadPath { path: String, reason: PathError },
    #[error("{path}: link target {target} escapes the archive root")]
    LinkEscape { path: String, target: String },
    #[error("{path}: a parent directory is a link")]
    ThroughLink { path: String },
    #[error("{path}: device, fifo and socket entries are not allowed")]
    SpecialFile { path: String },
    #[error("{path}: unsupported entry ({what})")]
    Unsupported { path: String, what: String },
    #[error("{path}: appears more than once")]
    Duplicate { path: String },
    #[error("{path}: conflicts with an earlier entry of another kind")]
    Conflict { path: String },
    #[error("tar extension header of {size} bytes exceeds the {limit}-byte limit")]
    ExtensionTooLarge { size: u64, limit: u64 },
    #[error("malformed archive: {0}")]
    Malformed(String),
    #[error("destination {0} must be an existing, empty directory")]
    BadDestination(PathBuf),
    #[error("I/O error: {0}")]
    Io(std::io::Error),
}

const MAX_QUOTED: usize = 200;

/// Makes archive bytes safe to show: invalid UTF-8 is replaced, control characters are
/// escaped, and the result is truncated.
pub(crate) fn quote(raw: &[u8]) -> String {
    let lossy = String::from_utf8_lossy(raw);
    let mut out = String::new();
    for c in lossy.chars() {
        if out.len() >= MAX_QUOTED {
            out.push('…');
            break;
        }
        if c.is_control() || c == '\\' {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_escapes_control_characters_and_truncates() {
        assert_eq!(quote(b"a\x1b[31m\nb"), "a\\u{1b}[31m\\nb");
        assert_eq!(quote(b"a\\b"), "a\\\\b");
        let long = quote(&[b'x'; 1000]);
        assert!(long.len() <= MAX_QUOTED + '…'.len_utf8());
        assert!(long.ends_with('…'));
    }
}
