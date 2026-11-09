//! Building findings. Everything quoted into a finding comes from a package, so it is escaped
//! and truncated before it leaves the analyzer.

use std::collections::HashMap;

use drift_proto::v1::{Capability, DriftFinding, Evidence, ExecContext};

pub const ANALYZER: &str = "static-rs";
const MAX_SNIPPET: usize = 200;
const MAX_ATTR: usize = 500;

/// Escapes control characters and truncates to `max` characters.
pub fn clean(text: &str, max: usize) -> String {
    let mut out = String::new();
    for (count, c) in text.chars().enumerate() {
        if count >= max {
            out.push('…');
            break;
        }
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// A finding under construction.
pub struct Finding {
    inner: DriftFinding,
}

impl Finding {
    pub fn new(kind: &str, capability: Capability, context: ExecContext, confidence: f64) -> Self {
        Self {
            inner: DriftFinding {
                analyzer: ANALYZER.to_owned(),
                kind: kind.to_owned(),
                capability: capability.into(),
                context: context.into(),
                evidence: Vec::new(),
                confidence: confidence.clamp(0.0, 1.0),
                attrs: HashMap::new(),
                via_dependency: String::new(),
            },
        }
    }

    pub fn evidence(mut self, file: &str, line: u32, snippet: &str) -> Self {
        self.inner.evidence.push(Evidence {
            file: clean(file, MAX_SNIPPET),
            line,
            snippet: clean(snippet, MAX_SNIPPET),
            trace_event: String::new(),
        });
        self
    }

    pub fn attr(mut self, key: &str, value: impl AsRef<str>) -> Self {
        self.inner
            .attrs
            .insert(key.to_owned(), clean(value.as_ref(), MAX_ATTR));
        self
    }

    pub fn build(self) -> DriftFinding {
        self.inner
    }
}

/// Collects findings, capping how many of one kind are listed so that a huge diff can't
/// swamp the report. What was left out is recorded as a note.
pub struct Collector {
    findings: Vec<DriftFinding>,
    per_kind: HashMap<String, usize>,
    pub notes: Vec<String>,
    cap: usize,
}

impl Collector {
    pub fn new(cap: usize) -> Self {
        Self {
            findings: Vec::new(),
            per_kind: HashMap::new(),
            notes: Vec::new(),
            cap,
        }
    }

    pub fn push(&mut self, finding: Finding) {
        let finding = finding.build();
        let count = self.per_kind.entry(finding.kind.clone()).or_default();
        *count += 1;
        if *count <= self.cap {
            self.findings.push(finding);
        }
    }

    pub fn note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    pub fn finish(mut self) -> (Vec<DriftFinding>, Vec<String>) {
        let mut kinds: Vec<_> = self
            .per_kind
            .iter()
            .filter(|(_, n)| **n > self.cap)
            .collect();
        kinds.sort();
        for (kind, n) in kinds {
            self.notes
                .push(format!("{kind}: {} more findings not listed", n - self.cap));
        }
        (self.findings, self.notes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_escapes_and_truncates() {
        assert_eq!(clean("a\x1b[2Jb\n", 100), "a\\u{1b}[2Jb\\n");
        assert_eq!(clean("abcdef", 3), "abc…");
    }

    #[test]
    fn collector_caps_each_kind() {
        let mut c = Collector::new(2);
        for _ in 0..5 {
            c.push(Finding::new(
                "file_added",
                Capability::Unspecified,
                ExecContext::Unspecified,
                0.1,
            ));
        }
        c.push(Finding::new(
            "install_hook_added",
            Capability::InstallHook,
            ExecContext::Install,
            0.9,
        ));
        let (findings, notes) = c.finish();
        assert_eq!(findings.len(), 3);
        assert_eq!(notes, ["file_added: 3 more findings not listed"]);
    }
}
