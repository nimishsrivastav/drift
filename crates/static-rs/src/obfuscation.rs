//! Obfuscation signals: encoded blobs, high-entropy and escape-heavy strings, obfuscator
//! output, newly minified files, and decoded data flowing into code execution.

use std::collections::{HashMap, HashSet};

use drift_proto::v1::Capability;
use tree_sitter::Node;

use crate::capabilities::strings;
use crate::capabilities::{Captured, File, FileFacts, Qualified};

/// Most uses recorded per file; a huge bundle can't exhaust memory with them.
pub const MAX_USES: usize = 10_000;
/// Most nodes walked when looking through one expression for a decoded value.
const MAX_SCAN: usize = 512;
/// How many rounds a decoded value is followed through assignments.
const TAINT_ROUNDS: usize = 4;

/// Whether a file looks minified: long lines throughout, or one or two huge ones.
pub fn is_minified(source: &[u8]) -> bool {
    if source.len() < 2048 {
        return false;
    }
    let lines = source.iter().filter(|&&b| b == b'\n').count() + 1;
    source.len() / lines > 250 || (lines <= 3 && source.len() > 4096)
}

/// Signals that come from the file's text as a whole.
pub fn file_signals(source: &[u8], facts: &mut FileFacts) {
    // obfuscator.io renames every identifier to _0x followed by hex digits.
    let mut count = 0;
    let mut first = None;
    let mut i = 0;
    while let Some(at) = find(&source[i..], b"_0x") {
        let start = i + at;
        let digits = source[start + 3..]
            .iter()
            .take_while(|b| b.is_ascii_hexdigit())
            .count();
        if digits >= 4 {
            count += 1;
            first.get_or_insert(start);
        }
        i = start + 3 + digits;
    }
    if count >= 25
        && let Some(start) = first
    {
        let line = source[..start].iter().filter(|&&b| b == b'\n').count() + 1;
        let end = (start + 80).min(source.len());
        facts.uses.push(crate::capabilities::Use {
            capability: Capability::Obfuscation,
            signal: "obfuscator_identifiers",
            detail: format!("{count} _0x identifiers"),
            line: u32::try_from(line).unwrap_or(u32::MAX),
            snippet: String::from_utf8_lossy(&source[start..end]).into_owned(),
            top_level: true,
        });
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Signals from one string literal.
pub(crate) fn string_signals(
    file: &File,
    node: Node,
    decoded: &str,
    escapes: usize,
    facts: &mut FileFacts,
) {
    if facts.uses.len() >= MAX_USES {
        return;
    }
    let chars = decoded.chars().count();
    let top = file.top_level(node);
    let (signal, detail) = if let Some(kind) = strings::encoded_blob(decoded) {
        ("encoded_blob", format!("{kind}, {chars} characters"))
    } else if escapes >= 16 && escapes * 2 >= chars {
        (
            "escaped_string",
            format!("{escapes} escapes in {chars} characters"),
        )
    } else if chars >= 64 && strings::entropy(decoded) >= 5.2 {
        (
            "high_entropy_string",
            format!(
                "{chars} characters, {:.1} bits each",
                strings::entropy(decoded)
            ),
        )
    } else {
        return;
    };
    facts
        .uses
        .push(file.use_at(node, Capability::Obfuscation, signal, detail, top));
}

/// The decoding a call performs, if it decodes: base64 or hex, char codes, URI escapes,
/// decompression or decryption.
fn decoder(file: &File, q: &Qualified, args: Option<Node>) -> Option<&'static str> {
    let encoding = || {
        args.and_then(|a| a.named_child(1))
            .and_then(|e| file.const_string(e))
            .map(|e| e.to_ascii_lowercase())
    };
    let from_bytes = || {
        args.and_then(|a| a.named_child(0))
            .is_some_and(|a| a.kind() == "array")
    };
    match q {
        Qualified::Global(m) => match m.join(".").as_str() {
            "atob" => Some("atob"),
            "Buffer.from" | "Buffer" => match encoding().as_deref() {
                Some("base64" | "base64url") => Some("base64"),
                Some("hex") => Some("hex"),
                _ if from_bytes() => Some("byte array"),
                _ => None,
            },
            "String.fromCharCode" | "String.fromCharCode.apply" => Some("char codes"),
            "decodeURIComponent" | "decodeURI" | "unescape" => Some("URI escapes"),
            _ => None,
        },
        Qualified::Module(module, members) => match (module.as_str(), q.last()) {
            ("zlib", Some(f))
                if f.contains("nflate") || f.contains("unzip") || f.contains("ecompress") =>
            {
                Some("decompression")
            }
            ("crypto", Some("createDecipher" | "createDecipheriv")) => Some("decryption"),
            ("buffer", _) if members.join(".") == "Buffer.from" => {
                matches!(encoding().as_deref(), Some("base64" | "base64url" | "hex"))
                    .then_some("base64")
            }
            _ => None,
        },
    }
}

/// The kind of code execution a call or `new` performs, if any.
fn sink(file: &File, q: Option<&Qualified>, callee: Node, args: Option<Node>) -> Option<String> {
    if callee.kind() == "member_expression"
        && callee
            .child_by_field_name("property")
            .is_some_and(|p| file.text(p) == "_compile")
    {
        return Some("Module._compile".into());
    }
    match q? {
        Qualified::Global(m) => match m.join(".").as_str() {
            g @ ("eval" | "Function") => Some(g.to_owned()),
            g @ ("setTimeout" | "setInterval")
                if args
                    .and_then(|a| a.named_child(0))
                    .is_some_and(|a| !a.kind().contains("function")) =>
            {
                Some(g.to_owned())
            }
            _ => None,
        },
        Qualified::Module(module, _) if module == "vm" => Some(q?.display()),
        _ => None,
    }
}

/// Reports decoded data reaching code execution: `eval(atob(s))`, or through variables,
/// `const s = Buffer.from(b, "base64").toString(); new Function(s)()`. Intra-file and
/// flow-insensitive, which is enough for the payload loaders seen in real incidents.
pub(crate) fn decode_exec(
    file: &File,
    captured: &Captured,
    bindings: &HashMap<String, Qualified>,
    facts: &mut FileFacts,
) {
    // Where each decoding call starts, sorted, so "does this expression decode" is a search.
    let mut decoders: Vec<(usize, &'static str)> = Vec::new();
    for (call, callee, args) in &captured.calls {
        if let Some(q) = file.qualify(*callee, bindings, 0)
            && let Some(kind) = decoder(file, &q, Some(*args))
        {
            decoders.push((call.start_byte(), kind));
        }
    }
    for (new, callee) in &captured.news {
        if let Some(q) = file.qualify(*callee, bindings, 0)
            && let Some(kind) = decoder(file, &q, new.child_by_field_name("arguments"))
        {
            decoders.push((new.start_byte(), kind));
        }
    }
    if decoders.is_empty() {
        return;
    }
    decoders.sort_unstable();
    let decodes = |node: Node| -> Option<&'static str> {
        let range = node.byte_range();
        let i = decoders.partition_point(|&(at, _)| at < range.start);
        decoders
            .get(i)
            .filter(|&&(at, _)| at < range.end)
            .map(|&(_, kind)| kind)
    };

    // Names that hold decoded data, followed through assignments.
    let mut tainted: HashMap<String, &'static str> = HashMap::new();
    let scanned: Vec<(String, Option<&'static str>, HashSet<String>)> = captured
        .binds
        .iter()
        .filter(|(name, _)| name.kind() == "identifier")
        .map(|(name, value)| {
            (
                file.text(*name).to_owned(),
                decodes(*value),
                identifiers(file, *value),
            )
        })
        .collect();
    for _ in 0..TAINT_ROUNDS {
        let before = tainted.len();
        for (name, direct, idents) in &scanned {
            if tainted.contains_key(name) {
                continue;
            }
            let kind = direct.or_else(|| idents.iter().find_map(|i| tainted.get(i).copied()));
            if let Some(kind) = kind {
                tainted.insert(name.clone(), kind);
            }
        }
        if tainted.len() == before {
            break;
        }
    }

    let sinks = captured
        .calls
        .iter()
        .map(|(call, callee, args)| (*call, *callee, Some(*args)))
        .chain(
            captured
                .news
                .iter()
                .map(|(new, callee)| (*new, *callee, new.child_by_field_name("arguments"))),
        );
    for (node, callee, args) in sinks {
        if facts.uses.len() >= MAX_USES {
            return;
        }
        let q = file.qualify(callee, bindings, 0);
        let Some(sink) = sink(file, q.as_ref(), callee, args) else {
            continue;
        };
        let Some(args) = args else { continue };
        let source = decodes(args).or_else(|| {
            identifiers(file, args)
                .iter()
                .find_map(|i| tainted.get(i).copied())
        });
        if let Some(source) = source {
            let top = file.top_level(node);
            facts.uses.push(file.use_at(
                node,
                Capability::Obfuscation,
                "decode_exec",
                format!("{source} → {sink}"),
                top,
            ));
        }
    }
}

/// Identifier names in an expression, looking at most MAX_SCAN nodes.
fn identifiers(file: &File, node: Node) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut cursor = node.walk();
    let mut visited = 0;
    loop {
        visited += 1;
        if visited > MAX_SCAN {
            return out;
        }
        let n = cursor.node();
        if n.kind() == "identifier" {
            out.insert(file.text(n).to_owned());
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.node() == node {
                return out;
            }
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return out;
            }
        }
    }
}
