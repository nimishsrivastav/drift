//! End-to-end tests of `analyze` on synthetic fixtures (`fixtures/npm/`). Tarballs are packed
//! here from the fixture directories, so no archive is committed. Set `UPDATE_GOLDEN=1` to
//! rewrite the golden files after an intended change.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use drift_proto::v1::{AnalyzeResponse, ArtifactPair, Ecosystem, PackageVersion};
use flate2::{Compression, GzBuilder};
use static_rs::{Config, analyze};

const PACKAGE: &str = "drift-fixture-install-hook";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn fixture(package: &str) -> PathBuf {
    repo_root().join("fixtures/npm").join(package)
}

/// Packs (path, contents, mode) entries into a gzipped tarball, deterministically.
fn pack(entries: &[(String, Vec<u8>, u32)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, data, mode) in entries {
        let mut header = tar::Header::new_ustar();
        header.set_size(data.len() as u64);
        header.set_mode(*mode);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Regular);
        builder
            .append_data(&mut header, path, data.as_slice())
            .unwrap();
    }
    let tar = builder.into_inner().unwrap();
    let mut gz = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::default());
    gz.write_all(&tar).unwrap();
    gz.finish().unwrap()
}

/// Every file under `dir`, as `package/<relative path>`.
fn pack_dir(dir: &Path) -> Vec<u8> {
    let mut entries = Vec::new();
    collect(dir, dir, &mut entries);
    entries.sort();
    pack(&entries)
}

fn collect(base: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>, u32)>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect(base, &path, out);
        } else {
            let rel = path
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            out.push((format!("package/{rel}"), fs::read(&path).unwrap(), 0o644));
        }
    }
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let path = entry.unwrap().path();
        let target = to.join(path.file_name().unwrap());
        if path.is_dir() {
            copy_dir(&path, &target);
        } else {
            fs::copy(&path, &target).unwrap();
        }
    }
}

/// A scratch artifacts root laid out like the orchestrator's data directory.
struct Artifacts {
    root: tempfile::TempDir,
}

impl Artifacts {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("tarballs")).unwrap();
        fs::create_dir_all(root.path().join("repos")).unwrap();
        Self { root }
    }

    fn tarball(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.root.path().join("tarballs").join(name);
        fs::write(&path, bytes).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn repo(&self, name: &str, from: &Path) -> String {
        let path = self.root.path().join("repos").join(name);
        copy_dir(from, &path);
        path.to_string_lossy().into_owned()
    }

    fn config(&self) -> Config {
        Config::new(self.root.path())
    }
}

fn version(
    name: &str,
    version: &str,
    tarball: String,
    repo: Option<(String, &str)>,
) -> PackageVersion {
    let (repo_path, repo_ref) = repo.map_or((String::new(), "unresolved".to_owned()), |(p, r)| {
        (p, r.to_owned())
    });
    PackageVersion {
        ecosystem: Ecosystem::Npm.into(),
        name: name.into(),
        version: version.into(),
        tarball_path: tarball,
        tarball_sha256: String::new(),
        repo_path,
        repo_ref,
    }
}

fn pair(old: Option<PackageVersion>, new: PackageVersion) -> ArtifactPair {
    ArtifactPair {
        job_id: "test".into(),
        old,
        new: Some(new),
        parent_job_id: String::new(),
        depth: 0,
    }
}

/// One line per finding, sorted, so the golden file reads on its own.
fn render(response: &AnalyzeResponse) -> String {
    let mut lines: Vec<String> = response
        .findings
        .iter()
        .map(|f| {
            let evidence: Vec<String> = f
                .evidence
                .iter()
                .map(|e| format!("{}:{} {}", e.file, e.line, e.snippet))
                .collect();
            let mut attrs: Vec<String> = f.attrs.iter().map(|(k, v)| format!("{k}={v}")).collect();
            attrs.sort();
            format!(
                "{} {} {} confidence={:.2}\n  evidence: {}\n  attrs: {}",
                f.kind,
                f.capability().as_str_name(),
                f.context().as_str_name(),
                f.confidence,
                evidence.join(" | "),
                attrs.join(" "),
            )
        })
        .collect();
    lines.sort();
    let mut notes = response.errors.clone();
    notes.sort();
    format!(
        "{}\nnotes:\n{}\n",
        lines.join("\n"),
        notes.iter().map(|n| format!("  {n}\n")).collect::<String>()
    )
}

fn assert_golden(name: &str, actual: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, actual).unwrap();
        return;
    }
    let expected = fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("{} missing; run with UPDATE_GOLDEN=1", path.display()));
    assert_eq!(
        actual, expected,
        "golden file {name} differs; rerun with UPDATE_GOLDEN=1 if intended"
    );
}

fn kinds(response: &AnalyzeResponse) -> Vec<String> {
    let mut kinds: Vec<String> = response.findings.iter().map(|f| f.kind.clone()).collect();
    kinds.sort();
    kinds
}

#[test]
fn malicious_install_hook_update() {
    let a = Artifacts::new();
    let dir = fixture(PACKAGE);
    let old = version(
        PACKAGE,
        "1.0.0",
        a.tarball("old.tgz", &pack_dir(&dir.join("1.0.0"))),
        None,
    );
    let repo = a.repo("fixture/v1.0.1", &dir.join("repo"));
    let new = version(
        PACKAGE,
        "1.0.1",
        a.tarball("new.tgz", &pack_dir(&dir.join("1.0.1"))),
        Some((repo, "v1.0.1")),
    );
    let response = analyze(&pair(Some(old), new), &a.config());

    // The acceptance signal for M3: the new install hook and the file it runs.
    let hook = response
        .findings
        .iter()
        .find(|f| f.kind == "install_hook_added")
        .expect("install hook finding");
    assert_eq!(hook.attrs["script"], "node ./lib/build.js");
    assert!(hook.evidence[0].line > 0);
    let only = response
        .findings
        .iter()
        .find(|f| f.kind == "tarball_only_file")
        .expect("tarball-only finding");
    assert_eq!(only.evidence[0].file, "lib/build.js");
    assert_eq!(only.context().as_str_name(), "EXEC_CONTEXT_INSTALL");
    assert_golden("drift-fixture-install-hook.txt", &render(&response));
}

#[test]
fn identical_versions_have_no_findings() {
    let a = Artifacts::new();
    let bytes = pack_dir(&fixture(PACKAGE).join("1.0.0"));
    let old = version(PACKAGE, "1.0.0", a.tarball("a.tgz", &bytes), None);
    let new = version(PACKAGE, "1.0.0", a.tarball("b.tgz", &bytes), None);
    let response = analyze(&pair(Some(old), new), &a.config());
    assert!(response.findings.is_empty(), "{:?}", response.findings);
    assert_eq!(
        response.errors,
        ["tarball-vs-repo diff skipped: no source checkout for either version"]
    );
}

#[test]
fn new_package_mode_reports_absolute_install_behavior() {
    let a = Artifacts::new();
    let new = version(
        PACKAGE,
        "1.0.1",
        a.tarball("new.tgz", &pack_dir(&fixture(PACKAGE).join("1.0.1"))),
        None,
    );
    let response = analyze(&pair(None, new), &a.config());
    assert_eq!(kinds(&response), ["file_added", "install_hook_added"]);
    let file = response
        .findings
        .iter()
        .find(|f| f.kind == "file_added")
        .unwrap();
    assert_eq!(file.evidence[0].file, "lib/build.js");
}

#[test]
fn rejected_archive_is_a_finding() {
    let a = Artifacts::new();
    let good = version(
        PACKAGE,
        "1.0.0",
        a.tarball("old.tgz", &pack_dir(&fixture(PACKAGE).join("1.0.0"))),
        None,
    );
    // A gzip stream that ends mid-member can't be inspected; it must not look clean.
    let mut truncated = pack_dir(&fixture(PACKAGE).join("1.0.1"));
    truncated.truncate(truncated.len() / 2);
    let bad = version(PACKAGE, "1.0.1", a.tarball("new.tgz", &truncated), None);
    let response = analyze(&pair(Some(good), bad), &a.config());
    assert_eq!(kinds(&response), ["archive_rejected"]);
    assert!((response.findings[0].confidence - 0.7).abs() < 1e-9);
}

#[test]
fn layout_hooks_and_binaries() {
    let a = Artifacts::new();
    let base = vec![
        (
            "package/package.json".to_owned(),
            br#"{"name":"x","version":"1.0.0"}"#.to_vec(),
            0o644,
        ),
        (
            "package/index.js".to_owned(),
            b"module.exports = 1;\n".to_vec(),
            0o644,
        ),
    ];
    let mut next = base.clone();
    next.push((
        "package/binding.gyp".into(),
        b"{\"targets\":[]}\n".to_vec(),
        0o644,
    ));
    next.push((
        "package/prebuilt/addon.bin".into(),
        b"\x7fELF\x02\x01\x01".to_vec(),
        0o755,
    ));
    // A second top-level directory merges into the install on extraction.
    next.push((
        "other/index.js".into(),
        b"module.exports = 2;\n".to_vec(),
        0o644,
    ));
    let old = version("x", "1.0.0", a.tarball("old.tgz", &pack(&base)), None);
    let new = version("x", "1.0.1", a.tarball("new.tgz", &pack(&next)), None);
    let response = analyze(&pair(Some(old), new), &a.config());

    let hook = response
        .findings
        .iter()
        .find(|f| f.kind == "install_hook_added")
        .unwrap();
    assert_eq!(hook.attrs["implicit"], "binding.gyp");
    assert_eq!(hook.attrs["script"], "node-gyp rebuild");
    let native = response
        .findings
        .iter()
        .find(|f| f.kind == "native_binary_added")
        .unwrap();
    assert_eq!(native.attrs["binary"], "elf");
    let roots = response
        .findings
        .iter()
        .find(|f| f.kind == "tarball_multiple_roots")
        .unwrap();
    assert_eq!(roots.attrs["roots"], "other, package");
    // other/index.js replaced package/index.js at the installed path, the way npm extracts it.
    assert!(
        response
            .findings
            .iter()
            .any(|f| f.kind == "file_modified" && f.evidence[0].file == "index.js")
    );
}

#[test]
fn paths_outside_the_artifacts_root_are_refused() {
    let a = Artifacts::new();
    let elsewhere = tempfile::NamedTempFile::new().unwrap();
    fs::write(elsewhere.path(), pack_dir(&fixture(PACKAGE).join("1.0.1"))).unwrap();
    let new = version(
        PACKAGE,
        "1.0.1",
        elsewhere.path().to_string_lossy().into_owned(),
        None,
    );
    let response = analyze(&pair(None, new), &a.config());
    assert!(response.findings.is_empty());
    assert!(
        response.errors[0].contains("not under the artifacts root"),
        "{:?}",
        response.errors
    );
}

#[test]
fn old_checkout_is_a_weaker_fallback() {
    let a = Artifacts::new();
    let dir = fixture(PACKAGE);
    let repo = a.repo("fixture/v1.0.0", &dir.join("repo"));
    let old = version(
        PACKAGE,
        "1.0.0",
        a.tarball("old.tgz", &pack_dir(&dir.join("1.0.0"))),
        Some((repo, "v1.0.0")),
    );
    let new = version(
        PACKAGE,
        "1.0.1",
        a.tarball("new.tgz", &pack_dir(&dir.join("1.0.1"))),
        None,
    );
    let response = analyze(&pair(Some(old), new), &a.config());
    let only = response
        .findings
        .iter()
        .find(|f| f.kind == "tarball_only_file")
        .unwrap();
    // 0.9 for a file an install hook runs, halved for using the old version's source.
    assert!((only.confidence - 0.45).abs() < 1e-9, "{}", only.confidence);
    assert!(
        response
            .errors
            .iter()
            .any(|e| e.contains("compared with v1.0.0"))
    );
}

#[test]
fn unparseable_manifest_still_reports_its_hooks() {
    let a = Artifacts::new();
    let base = vec![(
        "package/package.json".to_owned(),
        br#"{"name":"x","version":"1.0.0"}"#.to_vec(),
        0o644,
    )];
    // A BOM is fine; the lone surrogate is what serde_json refuses and npm accepts.
    let mut manifest = b"\xef\xbb\xbf".to_vec();
    manifest.extend_from_slice(
        br#"{"name":"x","description":"\ud800","scripts":{"preinstall":"node x.js"}}"#,
    );
    let next = vec![
        ("package/package.json".to_owned(), manifest, 0o644),
        ("package/x.js".to_owned(), b"// synthetic\n".to_vec(), 0o644),
    ];
    let old = version("x", "1.0.0", a.tarball("old.tgz", &pack(&base)), None);
    let new = version("x", "1.0.1", a.tarball("new.tgz", &pack(&next)), None);
    let response = analyze(&pair(Some(old), new), &a.config());
    let kinds = kinds(&response);
    assert!(
        kinds.contains(&"manifest_unparseable".to_owned()),
        "{kinds:?}"
    );
    let hook = response
        .findings
        .iter()
        .find(|f| f.kind == "install_hook_added")
        .expect("hook recovered from raw text");
    assert_eq!(hook.attrs["script"], "node x.js");
    let file = response
        .findings
        .iter()
        .find(|f| f.kind == "file_added")
        .unwrap();
    assert_eq!(file.context().as_str_name(), "EXEC_CONTEXT_INSTALL");
}

#[test]
fn junk_files_cannot_bury_the_payload() {
    let a = Artifacts::new();
    let dir = fixture(PACKAGE);
    let old = version(
        PACKAGE,
        "1.0.0",
        a.tarball("old.tgz", &pack_dir(&dir.join("1.0.0"))),
        None,
    );
    let mut entries = Vec::new();
    collect(&dir.join("1.0.1"), &dir.join("1.0.1"), &mut entries);
    // 300 files that sort before lib/build.js, more than the per-kind cap.
    for i in 0..300 {
        entries.push((
            format!("package/aaa/{i:04}.js"),
            b"// junk\n".to_vec(),
            0o644,
        ));
    }
    entries.sort();
    let new = version(
        PACKAGE,
        "1.0.1",
        a.tarball("new.tgz", &pack(&entries)),
        None,
    );
    let response = analyze(&pair(Some(old), new), &a.config());
    assert!(
        response
            .findings
            .iter()
            .any(|f| f.kind == "file_added" && f.evidence[0].file == "lib/build.js")
    );
    assert!(
        response
            .errors
            .iter()
            .any(|e| e.contains("file_added") && e.contains("more findings not listed"))
    );
}

#[test]
fn zip_disguised_as_a_tarball_is_rejected() {
    let a = Artifacts::new();
    let good = version(
        PACKAGE,
        "1.0.0",
        a.tarball("old.tgz", &pack_dir(&fixture(PACKAGE).join("1.0.0"))),
        None,
    );
    // Starts like a zip; npm would read it as tar regardless.
    let bad = version(
        PACKAGE,
        "1.0.1",
        a.tarball("new.tgz", b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
        None,
    );
    let response = analyze(&pair(Some(good), bad), &a.config());
    assert_eq!(kinds(&response), ["archive_rejected"]);
    assert!(response.findings[0].attrs["error"].contains("Zip"));
}
