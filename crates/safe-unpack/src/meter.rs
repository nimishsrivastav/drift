//! Readers that count bytes and stop the stream the moment a limit is crossed.
//!
//! A tripped limit surfaces through `io::Read` as a generic error, because that is all a reader
//! can return. The precise reason is parked in the [`Meter`] and recovered by [`Meter::error`].

use std::cell::Cell;
use std::io::{self, Read};

use crate::{Error, Limits};

#[derive(Debug, Clone)]
pub(crate) enum Trip {
    Stream,
    Ratio,
    File(String),
    Total,
}

/// Shared byte counts for one extraction.
pub(crate) struct Meter {
    compressed: Cell<u64>,
    decompressed: Cell<u64>,
    file_total: Cell<u64>,
    tripped: Cell<Option<Trip>>,
    max_stream: u64,
    max_ratio: u64,
    grace: u64,
    max_total: u64,
    max_file: u64,
}

impl Meter {
    pub(crate) fn new(limits: &Limits) -> Self {
        Self {
            compressed: Cell::new(0),
            decompressed: Cell::new(0),
            file_total: Cell::new(0),
            tripped: Cell::new(None),
            max_stream: limits.max_stream_bytes(),
            max_ratio: limits.max_ratio,
            grace: limits.ratio_grace_bytes,
            max_total: limits.max_total_bytes,
            max_file: limits.max_file_bytes,
        }
    }

    /// For formats whose compressed size is the whole input, such as zip.
    pub(crate) fn set_compressed(&self, bytes: u64) {
        self.compressed.set(bytes);
    }

    pub(crate) fn total_written(&self) -> u64 {
        self.file_total.get()
    }

    fn trip(&self, trip: Trip) -> io::Error {
        self.tripped.set(Some(trip));
        io::Error::other("extraction limit exceeded")
    }

    /// Converts an I/O error into the limit that caused it, if one did.
    pub(crate) fn error(&self, err: io::Error) -> Error {
        match self.tripped.take() {
            Some(Trip::Stream) => Error::StreamTooLarge {
                limit: self.max_stream,
            },
            Some(Trip::Ratio) => Error::RatioExceeded {
                limit: self.max_ratio,
            },
            Some(Trip::File(path)) => Error::FileTooLarge {
                path,
                limit: self.max_file,
            },
            Some(Trip::Total) => Error::TotalTooLarge {
                limit: self.max_total,
            },
            None => Error::Io(err),
        }
    }

    fn add_decompressed(&self, n: usize) -> io::Result<()> {
        let total = self.decompressed.get().saturating_add(n as u64);
        self.decompressed.set(total);
        if total > self.max_stream {
            return Err(self.trip(Trip::Stream));
        }
        let allowed = self.compressed.get().max(1).saturating_mul(self.max_ratio);
        if total > self.grace && total > allowed {
            return Err(self.trip(Trip::Ratio));
        }
        Ok(())
    }
}

/// Counts bytes pulled from the compressed input.
pub(crate) struct Compressed<'m, R> {
    pub(crate) inner: R,
    pub(crate) meter: &'m Meter,
}

impl<R: Read> Read for Compressed<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.meter
            .compressed
            .set(self.meter.compressed.get().saturating_add(n as u64));
        Ok(n)
    }
}

/// Counts decompressed bytes and enforces the stream and ratio limits.
pub(crate) struct Decompressed<'m, R> {
    pub(crate) inner: R,
    pub(crate) meter: &'m Meter,
}

impl<R: Read> Read for Decompressed<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.meter.add_decompressed(n)?;
        Ok(n)
    }
}

/// Wraps one file's contents and enforces the per-file and total limits on bytes actually
/// read, whatever size the archive declared.
pub(crate) struct FileBudget<'m, R> {
    inner: R,
    meter: &'m Meter,
    path: &'m str,
    read: u64,
}

impl<'m, R> FileBudget<'m, R> {
    pub(crate) fn new(inner: R, meter: &'m Meter, path: &'m str) -> Self {
        Self {
            inner,
            meter,
            path,
            read: 0,
        }
    }

    pub(crate) fn bytes_read(&self) -> u64 {
        self.read
    }
}

impl<R: Read> Read for FileBudget<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read = self.read.saturating_add(n as u64);
        if self.read > self.meter.max_file {
            return Err(self.meter.trip(Trip::File(self.path.to_owned())));
        }
        let total = self.meter.file_total.get().saturating_add(n as u64);
        self.meter.file_total.set(total);
        if total > self.meter.max_total {
            return Err(self.meter.trip(Trip::Total));
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(r: &mut impl Read) -> io::Result<u64> {
        io::copy(r, &mut io::sink())
    }

    #[test]
    fn ratio_trips_after_grace() {
        let limits = Limits {
            max_ratio: 10,
            ratio_grace_bytes: 100,
            ..Limits::default()
        };
        let meter = Meter::new(&limits);
        meter.set_compressed(5);
        // 50 bytes is within grace; 150 is over grace and over 5 * 10.
        let mut ok = Decompressed {
            inner: &[0u8; 50][..],
            meter: &meter,
        };
        assert_eq!(drain(&mut ok).unwrap(), 50);
        let mut bad = Decompressed {
            inner: &[0u8; 100][..],
            meter: &meter,
        };
        let err = drain(&mut bad).unwrap_err();
        assert!(matches!(
            meter.error(err),
            Error::RatioExceeded { limit: 10 }
        ));
    }

    #[test]
    fn file_budget_counts_actual_bytes() {
        let limits = Limits {
            max_file_bytes: 10,
            max_total_bytes: 15,
            ..Limits::default()
        };
        let meter = Meter::new(&limits);
        let mut first = FileBudget::new(&[0u8; 10][..], &meter, "a");
        assert_eq!(drain(&mut first).unwrap(), 10);
        let mut big = FileBudget::new(&[0u8; 11][..], &meter, "b");
        let err = drain(&mut big).unwrap_err();
        assert!(
            matches!(meter.error(err), Error::FileTooLarge { ref path, limit: 10 } if path == "b")
        );

        let meter = Meter::new(&limits);
        let mut a = FileBudget::new(&[0u8; 8][..], &meter, "a");
        drain(&mut a).unwrap();
        let mut b = FileBudget::new(&[0u8; 8][..], &meter, "b");
        let err = drain(&mut b).unwrap_err();
        assert!(matches!(
            meter.error(err),
            Error::TotalTooLarge { limit: 15 }
        ));
    }

    #[test]
    fn untripped_errors_stay_io_errors() {
        let meter = Meter::new(&Limits::default());
        let err = meter.error(io::Error::other("disk full"));
        assert!(matches!(err, Error::Io(_)));
    }
}
