//! Extraction limits.

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;

/// Limits enforced while an archive streams. Every limit is checked before or while bytes are
/// produced, never by trusting sizes an archive declares about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Size of the archive file itself, before decompression.
    pub max_archive_bytes: u64,
    /// Sum of the sizes of all extracted files.
    pub max_total_bytes: u64,
    /// Size of any one extracted file.
    pub max_file_bytes: u64,
    /// Number of entries of any kind: files, directories and links.
    pub max_entries: u64,
    /// Number of components in a path.
    pub max_depth: usize,
    /// Length of a path in bytes, before normalization.
    pub max_path_bytes: usize,
    /// Largest allowed ratio of decompressed to compressed bytes.
    pub max_ratio: u64,
    /// The ratio is only enforced once this many bytes have been decompressed, so that small,
    /// very compressible files don't trip it.
    pub ratio_grace_bytes: u64,
    /// Size of a tar GNU long-name, long-link or pax header body, which has to be held in memory.
    pub max_extension_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_archive_bytes: 256 * MIB,
            max_total_bytes: 1024 * MIB,
            max_file_bytes: 256 * MIB,
            max_entries: 100_000,
            max_depth: 64,
            max_path_bytes: 4096,
            max_ratio: 200,
            ratio_grace_bytes: 8 * MIB,
            max_extension_bytes: 64 * KIB,
        }
    }
}

impl Limits {
    /// The most decompressed bytes a tar stream may contain: file contents plus headers and
    /// padding for every allowed entry. Bounding the stream bounds the work done on it.
    pub(crate) fn max_stream_bytes(&self) -> u64 {
        // Each entry costs at most a header, an extension header with its body, and padding.
        let per_entry = 512 * 3 + self.max_extension_bytes;
        self.max_total_bytes
            .saturating_add(self.max_entries.saturating_add(1).saturating_mul(per_entry))
            .saturating_add(1024)
    }
}
