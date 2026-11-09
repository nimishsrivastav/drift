//! `package.json`: install hooks and the files they run.

use std::collections::{BTreeMap, BTreeSet};

use drift_proto::v1::{Capability, ExecContext};

use crate::artifact::Tree;
use crate::findings::{Collector, Finding};

const MAX_MANIFEST: u64 = 5 << 20;

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

pub struct Manifest {
    pub text: String,
    pub name: Option<String>,
    pub scripts: BTreeMap<String, String>,
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
        Ok(Self {
            text,
            name,
            scripts,
        })
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

/// Reads the installed `package.json`, if there is one.
pub fn load(tree: &Tree) -> Result<Option<Manifest>, String> {
    if !tree.files.contains_key("package.json") {
        return Ok(None);
    }
    let bytes = tree
        .read("package.json", MAX_MANIFEST)
        .ok_or("package.json unreadable or too large")?;
    let text = String::from_utf8(bytes).map_err(|_| "package.json is not UTF-8".to_owned())?;
    Manifest::parse(text).map(Some)
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
    fn non_string_scripts_are_ignored() {
        let m =
            Manifest::parse(r#"{"scripts":{"postinstall":["node","a.js"],"test":"jest"}}"#.into())
                .unwrap();
        assert!(!m.scripts.contains_key("postinstall"));
        assert_eq!(m.scripts["test"], "jest");
    }
}
