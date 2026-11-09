//! Zip, including Python wheels. Only stored and deflated entries are accepted.

use std::io::{Read, Seek, SeekFrom};

use zip::result::ZipError;
use zip::{CompressionMethod, ZipArchive};

use crate::meter::Decompressed;
use crate::walker::Walker;
use crate::{Error, Limits};

const EOCD_SIG: &[u8; 4] = b"PK\x05\x06";
const ZIP64_LOCATOR_SIG: &[u8; 4] = b"PK\x06\x07";
const EOCD_LEN: u64 = 22;
const MAX_COMMENT: u64 = u16::MAX as u64;

const S_IFMT: u32 = 0o170000;
const SPECIAL_TYPES: [u32; 4] = [0o010000, 0o020000, 0o060000, 0o140000]; // fifo, char, block, socket

pub(crate) fn walk<R: Read + Seek>(
    mut input: R,
    size: u64,
    walker: &mut Walker<'_>,
) -> Result<(), Error> {
    precheck(&mut input, size, walker.limits)?;
    input.seek(SeekFrom::Start(0)).map_err(Error::Io)?;
    let meter = walker.meter;
    // Entries may overlap or repeat compressed data, so the ratio is measured against the
    // whole archive rather than each entry's declared compressed size.
    meter.set_compressed(size);

    let mut archive = ZipArchive::new(input).map_err(|e| zip_error(e, walker))?;
    if archive.len() as u64 > walker.limits.max_entries {
        return Err(Error::TooManyEntries {
            limit: walker.limits.max_entries,
        });
    }
    for index in 0..archive.len() {
        let file = archive.by_index(index).map_err(|e| zip_error(e, walker))?;
        let name = file.name_raw().to_vec();
        if file.encrypted() {
            return Err(walker.refuse(&name, false, "encrypted entry"));
        }
        let method = file.compression();
        if method != CompressionMethod::Stored && method != CompressionMethod::Deflated {
            return Err(walker.refuse(&name, false, &format!("compression method {method:?}")));
        }
        let mode = file.unix_mode().unwrap_or(0);
        if SPECIAL_TYPES.contains(&(mode & S_IFMT)) {
            return Err(walker.refuse(&name, true, "special file"));
        }
        let permissions = mode & 0o7777;

        if file.is_symlink() {
            let mut target = Vec::new();
            let cap = walker.limits.max_path_bytes as u64 + 1;
            Decompressed { inner: file, meter }
                .take(cap)
                .read_to_end(&mut target)
                .map_err(|e| walker.io(e))?;
            walker.symlink(&name, &target)?;
        } else if file.is_dir() {
            walker.dir(&name, permissions)?;
        } else {
            let declared = file.size();
            walker.file(
                &name,
                permissions,
                declared,
                &mut Decompressed { inner: file, meter },
            )?;
        }
    }
    Ok(())
}

/// Reads the end-of-central-directory record before the zip crate loads the central directory
/// into memory, so the entry limit holds even for a crafted directory. Zip64 is refused: no
/// archive within our size limits needs it.
fn precheck<R: Read + Seek>(input: &mut R, size: u64, limits: &Limits) -> Result<(), Error> {
    if size < EOCD_LEN {
        return Err(Error::Malformed("zip too short".into()));
    }
    let tail_len = size.min(EOCD_LEN + MAX_COMMENT);
    input
        .seek(SeekFrom::Start(size - tail_len))
        .map_err(Error::Io)?;
    let mut tail = vec![0u8; tail_len as usize];
    input.read_exact(&mut tail).map_err(Error::Io)?;

    let candidates: Vec<usize> = (0..=tail.len() - EOCD_LEN as usize)
        .rev()
        .filter(|&i| &tail[i..i + 4] == EOCD_SIG)
        .collect();
    let exact = candidates.iter().copied().find(|&i| {
        let comment = u16::from_le_bytes([tail[i + 20], tail[i + 21]]) as usize;
        i + EOCD_LEN as usize + comment == tail.len()
    });
    let at = exact
        .or(candidates.first().copied())
        .ok_or_else(|| Error::Malformed("no end of central directory".into()))?;

    let entries = u16::from_le_bytes([tail[at + 10], tail[at + 11]]);
    let dir_offset =
        u32::from_le_bytes([tail[at + 16], tail[at + 17], tail[at + 18], tail[at + 19]]);
    let has_locator = at >= 20 && &tail[at - 20..at - 16] == ZIP64_LOCATOR_SIG;
    if entries == u16::MAX || dir_offset == u32::MAX || has_locator {
        return Err(Error::Unsupported {
            path: String::new(),
            what: "zip64".into(),
        });
    }
    if u64::from(entries) > limits.max_entries {
        return Err(Error::TooManyEntries {
            limit: limits.max_entries,
        });
    }
    Ok(())
}

fn zip_error(err: ZipError, walker: &Walker<'_>) -> Error {
    match err {
        ZipError::Io(e) => walker.io(e),
        ZipError::CompressionMethodNotSupported(method) => Error::Unsupported {
            path: String::new(),
            what: format!("compression method {method}"),
        },
        other => Error::Malformed(other.to_string()),
    }
}
