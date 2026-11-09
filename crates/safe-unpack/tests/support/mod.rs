//! Crafts the archives in `tests/attacks/`. Headers are written byte by byte because archive
//! writers refuse to produce most of these. Every archive is inert: names and link targets point
//! at paths that tests check stay untouched, and no content is ever executable code.
//!
//! Regenerate the committed files with:
//! `cargo test -p safe-unpack --test attacks -- --ignored regenerate`

#![allow(dead_code)]

use std::io::{Cursor, Write};

use flate2::{Compression, GzBuilder};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipWriter};

pub const MIB: usize = 1024 * 1024;

/// Tar type flags.
pub mod flag {
    pub const FILE: u8 = b'0';
    pub const HARDLINK: u8 = b'1';
    pub const SYMLINK: u8 = b'2';
    pub const CHAR: u8 = b'3';
    pub const FIFO: u8 = b'6';
    pub const DIR: u8 = b'5';
    pub const PAX: u8 = b'x';
    pub const PAX_GLOBAL: u8 = b'g';
    pub const LONG_NAME: u8 = b'L';
    pub const SPARSE: u8 = b'S';
}

fn octal(field: &mut [u8], value: u64) {
    let digits = field.len() - 1;
    let text = format!("{value:0digits$o}");
    assert_eq!(text.len(), digits, "value too large for field");
    field[..digits].copy_from_slice(text.as_bytes());
    field[digits] = 0;
}

/// A ustar header. `name` up to 100 bytes, `link` up to 100.
pub fn header(name: &[u8], typeflag: u8, size: u64, link: &[u8], mode: u32) -> [u8; 512] {
    assert!(name.len() <= 100 && link.len() <= 100);
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name);
    octal(&mut h[100..108], u64::from(mode));
    octal(&mut h[108..116], 0);
    octal(&mut h[116..124], 0);
    octal(&mut h[124..136], size);
    octal(&mut h[136..148], 0);
    h[156] = typeflag;
    h[157..157 + link.len()].copy_from_slice(link);
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].fill(b' ');
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    h
}

/// A tar stream built entry by entry.
#[derive(Default)]
pub struct Tar {
    buf: Vec<u8>,
}

impl Tar {
    pub fn new() -> Self {
        Self::default()
    }

    /// An entry whose header size is `data.len()`.
    pub fn entry(mut self, name: &[u8], typeflag: u8, data: &[u8], link: &[u8], mode: u32) -> Self {
        self.buf
            .extend_from_slice(&header(name, typeflag, data.len() as u64, link, mode));
        self.push_body(data);
        self
    }

    /// Only a header, declaring `size` bytes that never follow.
    pub fn header_only(mut self, name: &[u8], typeflag: u8, size: u64) -> Self {
        self.buf
            .extend_from_slice(&header(name, typeflag, size, b"", 0o644));
        self
    }

    pub fn file(self, name: &str, data: &[u8]) -> Self {
        self.entry(name.as_bytes(), flag::FILE, data, b"", 0o644)
    }

    pub fn dir(self, name: &str) -> Self {
        self.entry(name.as_bytes(), flag::DIR, b"", b"", 0o755)
    }

    pub fn symlink(self, name: &str, target: &str) -> Self {
        self.entry(
            name.as_bytes(),
            flag::SYMLINK,
            b"",
            target.as_bytes(),
            0o777,
        )
    }

    pub fn hardlink(self, name: &str, target: &str) -> Self {
        self.entry(
            name.as_bytes(),
            flag::HARDLINK,
            b"",
            target.as_bytes(),
            0o644,
        )
    }

    /// A pax extended header (`x`, or `g` for global) with the given records.
    pub fn pax(self, typeflag: u8, records: &[(&str, &str)]) -> Self {
        let mut body = Vec::new();
        for (key, value) in records {
            body.extend(pax_record(key, value));
        }
        self.entry(b"././@PaxHeader", typeflag, &body, b"", 0o644)
    }

    /// A GNU long-name header for the entry that follows.
    pub fn long_name(self, name: &[u8]) -> Self {
        let mut body = name.to_vec();
        body.push(0);
        self.entry(b"././@LongLink", flag::LONG_NAME, &body, b"", 0o644)
    }

    /// One 512-byte zero block: an end-of-archive marker to some readers, not to others.
    pub fn zero_block(mut self) -> Self {
        self.buf.extend_from_slice(&[0u8; 512]);
        self
    }

    fn push_body(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        self.buf.extend(std::iter::repeat_n(0, pad));
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.buf.extend_from_slice(&[0u8; 1024]);
        self.buf
    }

    pub fn gz(self) -> Vec<u8> {
        gzip(&self.finish())
    }
}

pub fn pax_record(key: &str, value: &str) -> Vec<u8> {
    let base = key.len() + value.len() + 3;
    let mut len = base + base.to_string().len();
    while len != base + len.to_string().len() {
        len = base + len.to_string().len();
    }
    format!("{len} {key}={value}\n").into_bytes()
}

/// Gzip with a fixed header, so output is reproducible.
pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::best());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn zip_options(method: CompressionMethod) -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(method)
        .last_modified_time(DateTime::default())
        .unix_permissions(0o644)
}

pub enum ZipEntry<'a> {
    File(&'a str, &'a [u8]),
    Symlink(&'a str, &'a str),
}

pub fn zip(entries: &[ZipEntry<'_>]) -> Vec<u8> {
    zip_with_comment(entries, b"")
}

pub fn zip_with_comment(entries: &[ZipEntry<'_>], comment: &[u8]) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .set_raw_comment(comment.to_vec().into_boxed_slice())
        .unwrap();
    for entry in entries {
        match entry {
            ZipEntry::File(name, data) => {
                writer
                    .start_file(*name, zip_options(CompressionMethod::Deflated))
                    .unwrap();
                writer.write_all(data).unwrap();
            }
            ZipEntry::Symlink(name, target) => {
                writer
                    .add_symlink(*name, *target, zip_options(CompressionMethod::Stored))
                    .unwrap();
            }
        }
    }
    writer.finish().unwrap().into_inner()
}

/// Rewrites the Unix mode of the first central directory entry. Zip writers mask the file
/// type bits, so device entries have to be patched in.
pub fn patch_zip_mode(mut archive: Vec<u8>, mode: u32) -> Vec<u8> {
    let at = archive
        .windows(4)
        .position(|w| w == b"PK\x01\x02")
        .expect("central directory");
    archive[at + 5] = 3; // version made by: Unix
    archive[at + 38..at + 42].copy_from_slice(&(mode << 16).to_le_bytes());
    archive
}

/// Every committed archive, by file name.
pub fn all() -> Vec<(&'static str, Vec<u8>)> {
    let zeros = vec![0u8; 32 * MIB];
    let deep = vec!["d"; 80].join("/") + "/f.txt";
    let many = (0..50).fold(Tar::new(), |t, i| {
        t.file(&format!("package/f{i}.txt"), b"x")
    });
    vec![
        (
            "benign.tgz",
            Tar::new()
                .dir("package/")
                .file(
                    "package/package.json",
                    br#"{"name":"benign","version":"1.0.0"}"#,
                )
                .entry(
                    b"package/bin.js",
                    flag::FILE,
                    b"// synthetic fixture\n",
                    b"",
                    0o755,
                )
                .dir("package/lib/")
                .file("package/lib/a.js", b"module.exports = 1;\n")
                .symlink("package/alias.js", "lib/a.js")
                .long_name(format!("package/{}.js", "n".repeat(120)).as_bytes())
                .file("ignored-by-long-name", b"long\n")
                .pax(
                    flag::PAX,
                    &[("path", "package/pax name ✓.js"), ("mtime", "1700000000.5")],
                )
                .file("ignored-by-pax", b"pax\n")
                .gz(),
        ),
        (
            "benign.zip",
            zip(&[
                ZipEntry::File("pkg/__init__.py", b"# synthetic fixture\n"),
                ZipEntry::File("pkg-1.0.dist-info/METADATA", b"Name: pkg\n"),
            ]),
        ),
        (
            "tar_traversal.tgz",
            Tar::new()
                .file("package/index.js", b"1")
                .file("package/../../evil.txt", b"x")
                .gz(),
        ),
        (
            "tar_absolute.tgz",
            Tar::new()
                .file("/tmp/drift-safe-unpack-evil.txt", b"x")
                .gz(),
        ),
        (
            "tar_symlink_escape.tgz",
            Tar::new().symlink("package/link", "../../../etc").gz(),
        ),
        (
            "tar_symlink_absolute.tgz",
            Tar::new().symlink("package/passwd", "/etc/passwd").gz(),
        ),
        (
            "tar_symlink_write_through.tgz",
            Tar::new()
                .dir("package/")
                .symlink("package/sub", ".")
                .file("package/sub/x.txt", b"x")
                .gz(),
        ),
        (
            "tar_hardlink_escape.tgz",
            Tar::new().hardlink("package/h", "../../etc/passwd").gz(),
        ),
        (
            "tar_char_device.tgz",
            Tar::new()
                .entry(b"package/tty", flag::CHAR, b"", b"", 0o644)
                .gz(),
        ),
        (
            "tar_fifo.tgz",
            Tar::new()
                .entry(b"package/pipe", flag::FIFO, b"", b"", 0o644)
                .gz(),
        ),
        (
            "tar_gzip_bomb.tgz",
            Tar::new().file("package/zeros.bin", &zeros).gz(),
        ),
        ("tar_many_entries.tgz", many.gz()),
        (
            "tar_deep_path.tgz",
            Tar::new()
                .long_name(deep.as_bytes())
                .file("short", b"x")
                .gz(),
        ),
        (
            "tar_long_name_traversal.tgz",
            Tar::new()
                .long_name(b"package/../../evil.txt")
                .file("package/innocent.txt", b"x")
                .gz(),
        ),
        (
            "tar_pax_path_traversal.tgz",
            Tar::new()
                .pax(flag::PAX, &[("path", "../../evil.txt")])
                .file("package/innocent.txt", b"x")
                .gz(),
        ),
        (
            "tar_pax_size_override.tgz",
            Tar::new()
                .pax(flag::PAX, &[("size", "1024")])
                .file("package/a.txt", b"")
                .gz(),
        ),
        (
            "tar_pax_global_path.tgz",
            Tar::new()
                .pax(flag::PAX_GLOBAL, &[("path", "evil.txt")])
                .file("package/a.txt", b"x")
                .gz(),
        ),
        (
            "tar_huge_extension.tgz",
            Tar::new()
                .header_only(b"././@LongLink", flag::LONG_NAME, 10 * MIB as u64)
                .gz(),
        ),
        (
            "tar_duplicate.tgz",
            Tar::new()
                .file("package/index.js", b"1")
                .file("package/index.js", b"2")
                .gz(),
        ),
        (
            "tar_file_dir_conflict.tgz",
            Tar::new()
                .file("package/lib", b"x")
                .file("package/lib/a.js", b"x")
                .gz(),
        ),
        (
            "tar_sparse.tgz",
            Tar::new()
                .entry(b"package/sparse", flag::SPARSE, b"", b"", 0o644)
                .gz(),
        ),
        (
            "tar_control_char.tgz",
            Tar::new().file("package/\x1b[2Jevil.js", b"x").gz(),
        ),
        ("zip_slip.zip", zip(&[ZipEntry::File("../evil.txt", b"x")])),
        (
            "zip_absolute.zip",
            zip(&[ZipEntry::File("/tmp/drift-safe-unpack-evil.txt", b"x")]),
        ),
        (
            "zip_backslash.zip",
            zip(&[ZipEntry::File("..\\evil.txt", b"x")]),
        ),
        (
            "zip_symlink_escape.zip",
            zip(&[ZipEntry::Symlink("pkg/link", "../../etc")]),
        ),
        ("zip_bomb.zip", zip(&[ZipEntry::File("zeros.bin", &zeros)])),
        (
            "tar_zero_block_smuggle.tgz",
            Tar::new()
                .file("package/index.js", b"// benign\n")
                .zero_block()
                .file(
                    "package/hidden.js",
                    b"// read by node-tar, not by a reader that stops at one zero block\n",
                )
                .gz(),
        ),
        (
            "tar_dot_prefix.tgz",
            Tar::new()
                .file("package/index.js", b"// benign\n")
                .file("./index.js", b"// installed by npm as index.js\n")
                .gz(),
        ),
        (
            "tar_empty_component.tgz",
            Tar::new().file("package//index.js", b"x").gz(),
        ),
        (
            "tar_pax_and_long_name.tgz",
            Tar::new()
                .pax(flag::PAX, &[("path", "package/dist/x.min.js")])
                .long_name(b"package/index.js")
                .file("package/innocent.txt", b"x")
                .gz(),
        ),
        (
            "tar_file_with_trailing_slash.tgz",
            Tar::new().file("package/lib/", b"").gz(),
        ),
        ("zip_trailing_data.zip", {
            let mut z = zip(&[ZipEntry::File("pkg/__init__.py", b"# synthetic\n")]);
            z.extend_from_slice(b"appended bytes some readers see");
            z
        }),
        (
            "zip_two_eocd.zip",
            zip_with_comment(
                &[ZipEntry::File("pkg/__init__.py", b"# synthetic\n")],
                b"PK\x05\x06 fake end record in the comment",
            ),
        ),
        (
            "zip_char_device.zip",
            patch_zip_mode(zip(&[ZipEntry::File("pkg/tty", b"")]), 0o020644),
        ),
    ]
}
