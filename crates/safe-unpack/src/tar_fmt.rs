//! Tar and gzipped tar.
//!
//! The `tar` crate is used in raw mode: it parses and checksums headers, and this module handles
//! GNU long names and pax extension headers itself. That lets it cap their size before reading
//! them into memory, and refuse the ones that change how the rest of the stream is read.

use std::io::Read;

use flate2::read::MultiGzDecoder;
use tar::{Archive, EntryType};

use crate::Error;
use crate::meter::{Compressed, Decompressed};
use crate::walker::Walker;

pub(crate) fn walk_gz<R: Read>(input: R, walker: &mut Walker<'_>) -> Result<(), Error> {
    let meter = walker.meter;
    // npm and gzip itself accept concatenated gzip members, so read all of them: a decoder that
    // stopped after the first would see different contents than the installer does.
    let decoder = MultiGzDecoder::new(Compressed {
        inner: input,
        meter,
    });
    walk(
        Decompressed {
            inner: decoder,
            meter,
        },
        walker,
    )
}

pub(crate) fn walk_plain<R: Read>(input: R, walker: &mut Walker<'_>) -> Result<(), Error> {
    let meter = walker.meter;
    // Uncompressed, so every decompressed byte is also a compressed one.
    walk(
        Decompressed {
            inner: Compressed {
                inner: input,
                meter,
            },
            meter,
        },
        walker,
    )
}

/// Extension headers waiting to be applied to the next real entry.
#[derive(Default)]
struct Pending {
    long_name: Option<Vec<u8>>,
    long_link: Option<Vec<u8>>,
    pax: Option<Pax>,
}

impl Pending {
    fn is_empty(&self) -> bool {
        self.long_name.is_none() && self.long_link.is_none() && self.pax.is_none()
    }
}

#[derive(Default)]
struct Pax {
    path: Option<Vec<u8>>,
    link: Option<Vec<u8>>,
    size: Option<u64>,
    sparse: bool,
}

fn walk<R: Read>(stream: R, walker: &mut Walker<'_>) -> Result<(), Error> {
    let mut archive = Archive::new(stream);
    let entries = archive.entries().map_err(|e| walker.io(e))?.raw(true);
    let mut pending = Pending::default();

    for entry in entries {
        let mut entry = entry.map_err(|e| walker.io(e))?;
        let kind = entry.header().entry_type();
        let size = entry.header().entry_size().map_err(|e| walker.io(e))?;

        match kind {
            EntryType::GNULongName | EntryType::GNULongLink | EntryType::XHeader => {
                let body = read_extension(&mut entry, size, walker)?;
                let slot_taken = match kind {
                    EntryType::GNULongName => pending.long_name.replace(gnu_name(body)?).is_some(),
                    EntryType::GNULongLink => pending.long_link.replace(gnu_name(body)?).is_some(),
                    _ => pending.pax.replace(parse_pax(&body)?).is_some(),
                };
                if slot_taken {
                    return Err(Error::Malformed(
                        "two extension headers of one kind for one entry".into(),
                    ));
                }
                continue;
            }
            EntryType::XGlobalHeader => {
                let body = read_extension(&mut entry, size, walker)?;
                let global = parse_pax(&body)?;
                // Global headers apply to every later entry in some extractors and are ignored by
                // others, so any that would change a path, link or size is refused.
                if global.path.is_some()
                    || global.link.is_some()
                    || global.size.is_some()
                    || global.sparse
                {
                    return Err(Error::Unsupported {
                        path: String::new(),
                        what: "pax global header that changes entries".into(),
                    });
                }
                continue;
            }
            _ => {}
        }

        let ext = std::mem::take(&mut pending);
        let pax = ext.pax.unwrap_or_default();
        // Extractors disagree on which wins when both say where an entry goes: node-tar takes
        // whichever header came last. Refuse instead of guessing.
        if (pax.path.is_some() && ext.long_name.is_some())
            || (pax.link.is_some() && ext.long_link.is_some())
        {
            return Err(Error::Malformed(
                "both a pax header and a GNU long name set one entry's path".into(),
            ));
        }
        let header_path = entry.path_bytes().into_owned();
        let path = pax.path.or(ext.long_name).unwrap_or(header_path);
        if pax.sparse {
            return Err(walker.refuse(&path, false, "pax sparse file"));
        }
        if let Some(pax_size) = pax.size
            && pax_size != size
        {
            // Raw mode follows the header size. Honouring a different pax size would need the
            // stream position to move, so refuse rather than read the stream differently from
            // an installer.
            return Err(walker.refuse(&path, false, "pax size override"));
        }
        let link = pax
            .link
            .or(ext.long_link)
            .or_else(|| entry.link_name_bytes().map(|l| l.into_owned()));
        let mode = entry.header().mode().unwrap_or(0) & 0o7777;

        match kind {
            EntryType::Regular | EntryType::Continuous => {
                walker.file(&path, mode, size, &mut entry)?
            }
            EntryType::Directory => walker.dir(&path, mode)?,
            EntryType::Symlink => walker.symlink(&path, &link.unwrap_or_default())?,
            EntryType::Link => walker.hardlink(&path, &link.unwrap_or_default())?,
            EntryType::Char | EntryType::Block | EntryType::Fifo => {
                return Err(walker.refuse(&path, true, "special file"));
            }
            EntryType::GNUSparse => return Err(walker.refuse(&path, false, "GNU sparse file")),
            other => {
                return Err(walker.refuse(
                    &path,
                    false,
                    &format!("tar entry type {:?}", other.as_byte() as char),
                ));
            }
        }
    }

    if !pending.is_empty() {
        return Err(Error::Malformed(
            "extension header with no entry after it".into(),
        ));
    }
    // The iterator stops at the first zero block, but node-tar only stops after two in a row and
    // keeps reading after one. Anything but zeros after the end marker is content the installer
    // may see and we would not.
    let mut rest = archive.into_inner();
    let mut buf = [0u8; 8192];
    loop {
        let n = rest.read(&mut buf).map_err(|e| walker.io(e))?;
        if n == 0 {
            return Ok(());
        }
        if buf[..n].iter().any(|&b| b != 0) {
            return Err(Error::Malformed(
                "data after the end-of-archive marker".into(),
            ));
        }
    }
}

fn read_extension(entry: &mut impl Read, size: u64, walker: &Walker<'_>) -> Result<Vec<u8>, Error> {
    let limit = walker.limits.max_extension_bytes;
    if size > limit {
        return Err(Error::ExtensionTooLarge { size, limit });
    }
    let mut body = Vec::with_capacity(size as usize);
    entry
        .take(limit)
        .read_to_end(&mut body)
        .map_err(|e| walker.io(e))?;
    if body.len() as u64 != size {
        return Err(Error::Malformed("truncated extension header".into()));
    }
    Ok(body)
}

/// A GNU long name is NUL-terminated. Trailing NULs are dropped; a NUL anywhere else is refused,
/// because extractors disagree about whether it ends the name.
fn gnu_name(mut body: Vec<u8>) -> Result<Vec<u8>, Error> {
    while body.last() == Some(&0) {
        body.pop();
    }
    if body.contains(&0) {
        return Err(Error::Malformed("NUL inside a GNU long name".into()));
    }
    Ok(body)
}

/// Parses pax records, `"<len> <key>=<value>\n"` where `<len>` counts the whole record.
fn parse_pax(body: &[u8]) -> Result<Pax, Error> {
    let bad = |what: &str| Error::Malformed(format!("pax header: {what}"));
    let mut pax = Pax::default();
    let mut rest = body;
    while !rest.is_empty() {
        let space = rest
            .iter()
            .position(|&b| b == b' ')
            .ok_or_else(|| bad("no length"))?;
        let len: usize = std::str::from_utf8(&rest[..space])
            .ok()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| bad("bad length"))?;
        if len <= space + 1 || len > rest.len() || rest[len - 1] != b'\n' {
            return Err(bad("bad record"));
        }
        let record = &rest[space + 1..len - 1];
        rest = &rest[len..];
        let eq = record
            .iter()
            .position(|&b| b == b'=')
            .ok_or_else(|| bad("no '='"))?;
        let (key, value) = (&record[..eq], &record[eq + 1..]);
        let duplicate = match key {
            b"path" => pax.path.replace(value.to_vec()).is_some(),
            b"linkpath" => pax.link.replace(value.to_vec()).is_some(),
            b"size" => {
                let size = std::str::from_utf8(value)
                    .ok()
                    .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| bad("bad size"))?;
                pax.size.replace(size).is_some()
            }
            _ if key.starts_with(b"GNU.sparse.") => {
                pax.sparse = true;
                false
            }
            _ => false,
        };
        if duplicate {
            return Err(bad("repeated key"));
        }
    }
    Ok(pax)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(key: &str, value: &str) -> Vec<u8> {
        // Length includes its own digits, so find the fixed point.
        let base = key.len() + value.len() + 3;
        let mut len = base + base.to_string().len();
        if len.to_string().len() != base.to_string().len() {
            len = base + len.to_string().len();
        }
        format!("{len} {key}={value}\n").into_bytes()
    }

    #[test]
    fn parses_pax_records() {
        let mut body = record("path", "package/a b=c.js");
        body.extend(record("mtime", "1700000000.5"));
        body.extend(record("size", "42"));
        body.extend(record("linkpath", "x"));
        let pax = parse_pax(&body).unwrap();
        assert_eq!(pax.path.as_deref(), Some(&b"package/a b=c.js"[..]));
        assert_eq!(pax.link.as_deref(), Some(&b"x"[..]));
        assert_eq!(pax.size, Some(42));
        assert!(!pax.sparse);
        assert!(parse_pax(&record("GNU.sparse.major", "1")).unwrap().sparse);
    }

    #[test]
    fn rejects_malformed_pax() {
        let mut twice = record("path", "a");
        twice.extend(record("path", "b"));
        for bad in [
            &b"5 a=b"[..],   // no newline
            b"99 path=a\n",  // length past the end
            b"x path=a\n",   // non-numeric length
            b"6 patha\n",    // no '='
            b"0 \n",         // zero length
            b"10 size=-1\n", // negative size
            b"9 size=\n\n",  // empty size
            twice.as_slice(),
        ] {
            assert!(
                parse_pax(bad).is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn gnu_names_drop_only_trailing_nuls() {
        assert_eq!(gnu_name(b"a/b\0\0".to_vec()).unwrap(), b"a/b");
        assert!(gnu_name(b"a\0../../evil".to_vec()).is_err());
    }
}
