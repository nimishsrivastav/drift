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

/// Collects findings, capping how many of one kind are listed so that a huge diff can't swamp
/// the report. Within a kind, install-time findings are always kept and the rest are ranked by
/// confidence, so padding a package with junk files can't push the payload out of the list.
/// What was left out is recorded as a note.
pub struct Collector {
    findings: Vec<DriftFinding>,
    pub notes: Vec<String>,
    cap: usize,
}

const MAX_NOTE: usize = 1000;

impl Collector {
    pub fn new(cap: usize) -> Self {
        Self {
            findings: Vec::new(),
            notes: Vec::new(),
            cap,
        }
    }

    pub fn push(&mut self, finding: Finding) {
        self.findings.push(finding.build());
    }

    /// Notes can quote package data, so they are cleaned like findings.
    pub fn note(&mut self, note: impl AsRef<str>) {
        self.notes.push(clean(note.as_ref(), MAX_NOTE));
    }

    pub fn finish(mut self) -> (Vec<DriftFinding>, Vec<String>) {
        let mut by_kind: HashMap<&str, Vec<usize>> = HashMap::new();
        for (index, finding) in self.findings.iter().enumerate() {
            by_kind
                .entry(finding.kind.as_str())
                .or_default()
                .push(index);
        }
        let mut keep = vec![false; self.findings.len()];
        let mut omitted: Vec<(String, usize)> = Vec::new();
        for (kind, mut indices) in by_kind {
            let install = |i: &usize| self.findings[*i].context() == ExecContext::Install;
            indices.sort_by(|a, b| {
                install(b)
                    .cmp(&install(a))
                    .then(
                        self.findings[*b]
                            .confidence
                            .total_cmp(&self.findings[*a].confidence),
                    )
                    .then(a.cmp(b))
            });
            let mut kept = 0;
            for i in &indices {
                if install(i) || kept < self.cap {
                    keep[*i] = true;
                    kept += 1;
                }
            }
            if kept < indices.len() {
                omitted.push((kind.to_owned(), indices.len() - kept));
            }
        }
        omitted.sort();
        for (kind, n) in omitted {
            self.notes
                .push(format!("{kind}: {n} more findings not listed"));
        }
        let findings = self
            .findings
            .into_iter()
            .zip(keep)
            .filter_map(|(f, k)| k.then_some(f))
            .collect();
        (findings, self.notes)
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

    #[test]
    fn collector_keeps_install_findings_and_the_most_confident() {
        let mut c = Collector::new(1);
        for _ in 0..3 {
            c.push(Finding::new(
                "file_added",
                Capability::Unspecified,
                ExecContext::Unspecified,
                0.3,
            ));
        }
        c.push(
            Finding::new(
                "file_added",
                Capability::Unspecified,
                ExecContext::Unspecified,
                0.6,
            )
            .attr("which", "best"),
        );
        c.push(
            Finding::new(
                "file_added",
                Capability::Unspecified,
                ExecContext::Install,
                0.8,
            )
            .attr("which", "install-1"),
        );
        c.push(
            Finding::new(
                "file_added",
                Capability::Unspecified,
                ExecContext::Install,
                0.8,
            )
            .attr("which", "install-2"),
        );
        let (findings, notes) = c.finish();
        let mut kept: Vec<&str> = findings.iter().map(|f| f.attrs["which"].as_str()).collect();
        kept.sort();
        // The cap is spent on install-time findings first, but those are never dropped.
        assert_eq!(kept, ["install-1", "install-2"]);
        assert_eq!(notes, ["file_added: 4 more findings not listed"]);
    }

    #[test]
    fn notes_are_cleaned() {
        let mut c = Collector::new(1);
        c.note("bad \x1b]8;;x\x07 name");
        assert!(!c.finish().1[0].chars().any(char::is_control));
    }
}
