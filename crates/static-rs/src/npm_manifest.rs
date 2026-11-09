//! `package.json`: install hooks and the files they run.

use std::collections::{BTreeMap, BTreeSet};

use drift_proto::v1::{Capability, ExecContext};

use crate::artifact::Tree;
use crate::findings::{Collector, Finding};

const MAX_MANIFEST: u64 = 16 << 20;

/// Lifecycle scripts npm runs when a package is installed, with how likely each is to run
/// for a package installed from the registry. `prepare` and its hooks run only for git and
/// local installs, so they matter less for a registry update.
const LIFECYCLE: [(&str, f64); 6] = [
    ("preinstall", 0.9),
    ("install", 0.9),
    ("postinstall", 0.9),
    ("prepare", 0.5),
    ("preprepare", 0.5),
    ("postprepare", 0.5),
];

/// What npm installs with the `node-gyp rebuild` script it adds by itself.
const IMPLICIT_GYP: &str = "node-gyp rebuild";

/// Dependency sections npm installs for a consumer. `devDependencies` are not installed.
pub const DEPENDENCY_SECTIONS: [&str; 3] =
    ["dependencies", "optionalDependencies", "peerDependencies"];

pub struct Manifest {
    pub text: String,
    pub name: Option<String>,
    pub scripts: BTreeMap<String, String>,
    /// Dependency sections by key, each mapping a name to its spec. A value that isn't a
    /// string is kept as its JSON text, so that a change to it still shows.
    pub dependency_sections: BTreeMap<String, BTreeMap<String, String>>,
    pub bundled: Bundled,
    /// Peers marked `optional` in `peerDependenciesMeta`, which npm doesn't install by itself.
    pub optional_peers: BTreeSet<String>,
    pub entries: Entries,
}

/// `bundleDependencies`: shipped inside the tarball rather than fetched.
#[derive(Debug, Clone, Default, PartialEq)]
pub enum Bundled {
    #[default]
    None,
    All,
    Names(BTreeSet<String>),
}

impl Bundled {
    pub fn contains(&self, name: &str) -> bool {
        match self {
            Self::None => false,
            Self::All => true,
            Self::Names(names) => names.contains(name),
        }
    }
}

/// Where the package's code is entered from, as declared.
#[derive(Debug, Clone, Default)]
pub struct Entries {
    /// `main`. Node falls back to `index.js` when it is absent.
    pub main: Option<String>,
    /// What `require`/`import` of the package can load: every path in `exports`, and `module`.
    pub exports: Vec<String>,
    /// Commands the package installs. They run only when someone invokes them.
    pub bin: Vec<String>,
}

impl Manifest {
    pub fn parse(text: String) -> Result<Self, String> {
        let json: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("package.json: {e}"))?;
        let name = json.get("name").and_then(|n| n.as_str()).map(str::to_owned);
        let scripts = json
            .get("scripts")
            .and_then(|s| s.as_object())
            .map(|s| {
                s.iter()
                    .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                    .collect()
            })
            .unwrap_or_default();
        let mut dependency_sections = BTreeMap::new();
        for section in DEPENDENCY_SECTIONS {
            if let Some(object) = json.get(section).and_then(|d| d.as_object()) {
                let deps = object
                    .iter()
                    .map(|(k, v)| {
                        let spec = v.as_str().map_or_else(|| v.to_string(), str::to_owned);
                        (k.clone(), spec)
                    })
                    .collect();
                dependency_sections.insert(section.to_owned(), deps);
            }
        }
        // npm reads `bundleDependencies` and accepts the misspelling too.
        let bundled = match json
            .get("bundleDependencies")
            .or_else(|| json.get("bundledDependencies"))
        {
            Some(serde_json::Value::Bool(true)) => Bundled::All,
            Some(serde_json::Value::Array(names)) => Bundled::Names(
                names
                    .iter()
                    .filter_map(|n| n.as_str().map(str::to_owned))
                    .collect(),
            ),
            _ => Bundled::None,
        };
        let optional_peers = json
            .get("peerDependenciesMeta")
            .and_then(|m| m.as_object())
            .map(|m| {
                m.iter()
                    .filter(|(_, v)| {
                        v.get("optional").and_then(serde_json::Value::as_bool) == Some(true)
                    })
                    .map(|(k, _)| k.clone())
                    .collect()
            })
            .unwrap_or_default();
        let mut entries = Entries {
            main: json.get("main").and_then(|m| m.as_str()).map(str::to_owned),
            ..Entries::default()
        };
        if let Some(exports) = json.get("exports") {
            string_leaves(exports, &mut entries.exports);
        }
        if let Some(module) = json.get("module").and_then(|m| m.as_str()) {
            entries.exports.push(module.to_owned());
        }
        if let Some(bin) = json.get("bin") {
            string_leaves(bin, &mut entries.bin);
        }
        Ok(Self {
            text,
            name,
            scripts,
            dependency_sections,
            bundled,
            optional_peers,
            entries,
        })
    }

    /// The 1-based line of `"key":` inside `"section":`, or 0. Finds a dependency in its own
    /// section rather than the first key of that name anywhere in the file.
    pub fn key_line_in(&self, section: &str, key: &str) -> u32 {
        let start = self.key_line(section);
        if start == 0 {
            return 0;
        }
        let section_quoted = format!("\"{section}\"");
        let quoted = format!("\"{key}\"");
        for (index, line) in self.text.lines().enumerate().skip(start as usize - 1) {
            // The section key and its first entry can share a line.
            let from = if index + 1 == start as usize {
                line.find(&section_quoted)
                    .map_or(0, |at| at + section_quoted.len())
            } else {
                0
            };
            if let Some(at) = line[from..].find(&quoted)
                && line[from + at + quoted.len()..]
                    .trim_start()
                    .starts_with(':')
            {
                return u32::try_from(index + 1).unwrap_or(0);
            }
        }
        0
    }

    /// The 1-based line where `"key":` first appears, or 0.
    pub fn key_line(&self, key: &str) -> u32 {
        let quoted = format!("\"{key}\"");
        for (index, line) in self.text.lines().enumerate() {
            if let Some(at) = line.find(&quoted)
                && line[at + quoted.len()..].trim_start().starts_with(':')
            {
                return u32::try_from(index + 1).unwrap_or(0);
            }
        }
        0
    }
}

/// A `package.json` as read, plus why it couldn't be read normally, if it couldn't.
pub struct Loaded {
    /// Parsed, or reconstructed from the raw text when parsing failed.
    pub manifest: Option<Manifest>,
    pub problem: Option<String>,
}

/// Reads the installed `package.json`, if there is one, as leniently as npm does: a BOM is
/// skipped and invalid UTF-8 is replaced. If it still won't parse, or is too large, the hooks
/// are recovered from the raw text and the problem is reported, because a manifest npm accepts
/// and we don't must not hide its install hooks.
pub fn load(tree: &Tree) -> Loaded {
    if !tree.files.contains_key("package.json") {
        return Loaded {
            manifest: None,
            problem: None,
        };
    }
    let Some((bytes, truncated)) = tree.read_prefix("package.json", MAX_MANIFEST) else {
        return Loaded {
            manifest: None,
            problem: Some("package.json unreadable".into()),
        };
    };
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
    let text = String::from_utf8_lossy(bytes).into_owned();
    if truncated {
        let problem = format!("package.json is over {MAX_MANIFEST} bytes");
        return Loaded {
            manifest: Some(Manifest::scan(text)),
            problem: Some(problem),
        };
    }
    match Manifest::parse(text.clone()) {
        Ok(manifest) => Loaded {
            manifest: Some(manifest),
            problem: None,
        },
        Err(err) => Loaded {
            manifest: Some(Manifest::scan(text)),
            problem: Some(err),
        },
    }
}

impl Manifest {
    /// Recovers lifecycle scripts from text that isn't valid JSON to us: each `"hook": "..."`
    /// pair is found by hand. Less exact than parsing, and only used when parsing fails.
    pub fn scan(text: String) -> Self {
        let mut scripts = BTreeMap::new();
        for (name, _) in LIFECYCLE {
            let quoted = format!("\"{name}\"");
            let mut from = 0;
            while let Some(at) = text[from..].find(&quoted) {
                let after = from + at + quoted.len();
                from = after;
                let rest = text[after..].trim_start();
                let Some(rest) = rest.strip_prefix(':') else {
                    continue;
                };
                let rest = rest.trim_start();
                let Some(body) = rest.strip_prefix('"') else {
                    continue;
                };
                if let Some(value) = string_literal(body) {
                    // The last one wins, as with duplicate JSON keys.
                    scripts.insert(name.to_owned(), value);
                }
            }
        }
        let mut dependency_sections = BTreeMap::new();
        for section in DEPENDENCY_SECTIONS {
            if let Some(deps) = scan_string_object(&text, section) {
                dependency_sections.insert(section.to_owned(), deps);
            }
        }
        Self {
            text,
            name: None,
            scripts,
            dependency_sections,
            bundled: Bundled::None,
            optional_peers: BTreeSet::new(),
            entries: Entries::default(),
        }
    }
}

/// Every string inside a JSON value. `exports` and `bin` nest paths in objects keyed by
/// condition or command.
fn string_leaves(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(items) => items.iter().for_each(|v| string_leaves(v, out)),
        serde_json::Value::Object(map) => map.values().for_each(|v| string_leaves(v, out)),
        _ => {}
    }
}

/// Recovers `"key": {"a": "x", "b": "y"}` from text that isn't valid JSON to us, reading
/// string values only. The last occurrence of the key wins, as with duplicate JSON keys.
fn scan_string_object(text: &str, key: &str) -> Option<BTreeMap<String, String>> {
    let quoted = format!("\"{key}\"");
    let mut found = None;
    let mut from = 0;
    while let Some(at) = text[from..].find(&quoted) {
        let after = from + at + quoted.len();
        from = after;
        let Some(rest) = text[after..].trim_start().strip_prefix(':') else {
            continue;
        };
        let Some(mut body) = rest.trim_start().strip_prefix('{') else {
            continue;
        };
        let mut map = BTreeMap::new();
        loop {
            body = body.trim_start().trim_start_matches(',').trim_start();
            let Some((name, rest)) = body.strip_prefix('"').and_then(split_string) else {
                break;
            };
            let Some(rest) = rest.trim_start().strip_prefix(':') else {
                break;
            };
            let Some((value, rest)) = rest.trim_start().strip_prefix('"').and_then(split_string)
            else {
                break;
            };
            map.insert(name, value);
            body = rest;
        }
        found = Some(map);
    }
    found
}

/// Splits a JSON string body at its closing quote into the decoded string and what follows.
fn split_string(body: &str) -> Option<(String, &str)> {
    let mut escaped = false;
    for (i, c) in body.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => return Some((string_literal(body)?, &body[i + 1..])),
            _ => {}
        }
    }
    None
}

/// Reads a JSON string body up to its closing quote, decoding escapes where possible.
fn string_literal(body: &str) -> Option<String> {
    let mut escaped = false;
    for (i, c) in body.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => {
                let raw = &body[..i];
                return Some(
                    serde_json::from_str::<String>(&format!("\"{raw}\""))
                        .unwrap_or_else(|_| raw.to_owned()),
                );
            }
            _ => {}
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq)]
pub struct Hook {
    pub script: String,
    pub weight: f64,
    /// Added by npm itself rather than declared.
    pub implicit: bool,
}

/// The install hooks npm would run for this version.
pub fn install_hooks(manifest: Option<&Manifest>, tree: &Tree) -> BTreeMap<String, Hook> {
    let mut hooks = BTreeMap::new();
    let scripts = manifest.map(|m| &m.scripts);
    for (name, weight) in LIFECYCLE {
        if let Some(script) = scripts
            .and_then(|s| s.get(name))
            .filter(|s| !s.trim().is_empty())
        {
            hooks.insert(
                name.to_owned(),
                Hook {
                    script: script.clone(),
                    weight,
                    implicit: false,
                },
            );
        }
    }
    // npm adds `install: node-gyp rebuild` when binding.gyp exists and neither install nor
    // preinstall is declared.
    if tree.files.contains_key("binding.gyp")
        && !hooks.contains_key("install")
        && !hooks.contains_key("preinstall")
    {
        hooks.insert(
            "install".into(),
            Hook {
                script: IMPLICIT_GYP.into(),
                weight: 0.8,
                implicit: true,
            },
        );
    }
    hooks
}

/// Reports hooks present in `new` but absent from `old`, or changed. With no `old`, every hook
/// is new.
pub fn diff_hooks(
    old: Option<&BTreeMap<String, Hook>>,
    new: &BTreeMap<String, Hook>,
    manifest: Option<&Manifest>,
    collector: &mut Collector,
) {
    for (name, hook) in new {
        let previous = old.and_then(|o| o.get(name));
        let kind = match previous {
            None => "install_hook_added",
            Some(p) if p.script != hook.script => "install_hook_changed",
            Some(_) => continue,
        };
        let (file, line) = if hook.implicit {
            ("binding.gyp", 0)
        } else {
            ("package.json", manifest.map_or(0, |m| m.key_line(name)))
        };
        let snippet = format!(
            "\"{name}\": {}",
            serde_json::Value::String(hook.script.clone())
        );
        let mut finding = Finding::new(
            kind,
            Capability::InstallHook,
            ExecContext::Install,
            hook.weight,
        )
        .evidence(file, line, &snippet)
        .attr("hook", name)
        .attr("script", &hook.script);
        if hook.implicit {
            finding = finding.attr("implicit", "binding.gyp");
        }
        if let Some(p) = previous {
            finding = finding.attr("old_script", &p.script);
        }
        collector.push(finding);
    }
}

/// Files in the tree that install hooks name, such as `build.js` in `node build.js`. This is
/// a word-level heuristic; M4's import graph follows what those files load.
pub fn referenced_files(hooks: &BTreeMap<String, Hook>, tree: &Tree) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for hook in hooks.values() {
        let words = hook
            .script
            .split(|c: char| c.is_whitespace() || ";&|()<>`=".contains(c));
        for word in words {
            let word = word.trim_matches(|c| c == '"' || c == '\'');
            let word = word.strip_prefix("./").unwrap_or(word);
            if word.is_empty() {
                continue;
            }
            for candidate in [
                word.to_owned(),
                format!("{word}.js"),
                format!("{word}.cjs"),
                format!("{word}.mjs"),
                format!("{word}/index.js"),
            ] {
                if tree.files.contains_key(&candidate) {
                    found.insert(candidate);
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_key_lines() {
        let m = Manifest::parse(
            "{\n  \"name\": \"x\",\n  \"scripts\": {\n    \"postinstall\" : \"node a.js\"\n  }\n}"
                .into(),
        )
        .unwrap();
        assert_eq!(m.key_line("postinstall"), 4);
        assert_eq!(m.key_line("preinstall"), 0);
        assert_eq!(m.name.as_deref(), Some("x"));
        assert_eq!(m.scripts["postinstall"], "node a.js");
    }

    #[test]
    fn scan_recovers_hooks_from_invalid_json() {
        // A lone surrogate and trailing junk: npm's parser copes, serde_json doesn't.
        let text = r#"{"description":"\ud800","scripts":{"preinstall" : "node x.js","postinstall":"a \"quoted\" b"}} junk"#;
        assert!(Manifest::parse(text.to_owned()).is_err());
        let m = Manifest::scan(text.to_owned());
        assert_eq!(m.scripts["preinstall"], "node x.js");
        assert_eq!(m.scripts["postinstall"], "a \"quoted\" b");
        assert_eq!(m.key_line("preinstall"), 1);
    }

    #[test]
    fn non_string_scripts_are_ignored() {
        let m =
            Manifest::parse(r#"{"scripts":{"postinstall":["node","a.js"],"test":"jest"}}"#.into())
                .unwrap();
        assert!(!m.scripts.contains_key("postinstall"));
        assert_eq!(m.scripts["test"], "jest");
    }
}
