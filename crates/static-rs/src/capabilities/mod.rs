//! Capability extraction from JavaScript and TypeScript, by parsing with tree-sitter. Nothing
//! is evaluated: names are resolved through the file's own `require`/`import` bindings.
//!
//! Candidate nodes are found by one walk that dispatches on node kind, not by tree-sitter
//! queries: a query cursor's cost grows with nesting depth times size, and nesting is
//! attacker-controlled (see docs/DECISIONS.md). Every input here is attacker-controlled, so all
//! tree walks are iterative or depth-capped, and parsing has a size limit and a deadline.

pub mod strings;

use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;
use std::time::{Duration, Instant};

use drift_proto::v1::Capability;
use tree_sitter::{Language, Node, ParseOptions, Parser, TreeCursor};

use crate::obfuscation;

/// Files larger than this are not parsed; the analysis says so in a note.
pub const MAX_FILE_BYTES: u64 = 4 << 20;
/// How long one file may take to parse.
const PARSE_DEADLINE: Duration = Duration::from_secs(3);
/// How deep name resolution follows a member chain or a constant expression.
const MAX_EXPR_DEPTH: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grammar {
    JavaScript,
    TypeScript,
    Tsx,
}

/// The grammar for a file by its name, or `None` if it isn't code we parse. Declaration files
/// hold types only.
pub fn grammar_for(path: &str) -> Option<Grammar> {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    if [".d.ts", ".d.mts", ".d.cts"]
        .iter()
        .any(|e| name.ends_with(e))
    {
        return None;
    }
    match name.rsplit_once('.')?.1 {
        "js" | "cjs" | "mjs" | "jsx" => Some(Grammar::JavaScript),
        "ts" | "mts" | "cts" => Some(Grammar::TypeScript),
        "tsx" => Some(Grammar::Tsx),
        _ => None,
    }
}

/// An import of another module: a path in the package, a dependency or a builtin.
#[derive(Debug, Clone, PartialEq)]
pub struct Import {
    pub specifier: String,
    /// Runs when the importing file loads, not later inside a function.
    pub top_level: bool,
}

/// One use of a capability.
#[derive(Debug, Clone, PartialEq)]
pub struct Use {
    pub capability: Capability,
    /// The obfuscation signal, which keys the diff alongside the capability. Empty otherwise.
    pub signal: &'static str,
    /// What was used: `child_process.exec`, `process.env.NPM_TOKEN`, `npm: .npmrc`.
    pub detail: String,
    pub line: u32,
    pub snippet: String,
    pub top_level: bool,
}

/// What one file can do, independent of how the package reaches it.
#[derive(Debug, Clone, Default)]
pub struct FileFacts {
    pub imports: Vec<Import>,
    pub uses: Vec<Use>,
    pub minified: bool,
    /// Why the file was not analyzed, or only partly.
    pub problem: Option<String>,
}

fn language(grammar: Grammar) -> Language {
    match grammar {
        Grammar::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Grammar::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Grammar::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
    }
}

/// Parses one file and lists what it imports and what capabilities it uses.
pub fn extract(grammar: Grammar, source: &[u8]) -> FileFacts {
    let mut parser = Parser::new();
    if parser.set_language(&language(grammar)).is_err() {
        return FileFacts {
            problem: Some("grammar unavailable".into()),
            ..FileFacts::default()
        };
    }
    let started = Instant::now();
    let mut over_time = |_: &tree_sitter::ParseState| {
        if started.elapsed() > PARSE_DEADLINE {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    };
    let len = source.len();
    let tree = parser.parse_with_options(
        &mut |offset, _| if offset < len { &source[offset..] } else { &[] },
        None,
        Some(ParseOptions::new().progress_callback(&mut over_time)),
    );
    let Some(tree) = tree else {
        return FileFacts {
            problem: Some(format!("not parsed within {}s", PARSE_DEADLINE.as_secs())),
            minified: obfuscation::is_minified(source),
            ..FileFacts::default()
        };
    };
    let file = File {
        source,
        deferred: deferred_ranges(tree.root_node()),
    };
    let mut facts = file.analyze(tree.root_node());
    facts.minified = obfuscation::is_minified(source);
    obfuscation::file_signals(source, &mut facts);
    facts
}

/// A parsed file, and the byte ranges of functions that don't run when it loads.
pub(crate) struct File<'s> {
    pub source: &'s [u8],
    deferred: Vec<(usize, usize)>,
}

/// Captured nodes, grouped by pattern.
#[derive(Default)]
pub(crate) struct Captured<'t> {
    pub calls: Vec<(Node<'t>, Node<'t>, Node<'t>)>, // call, callee, arguments
    pub news: Vec<(Node<'t>, Node<'t>)>,            // new, constructor
    pub imports: Vec<(Node<'t>, Node<'t>, Option<Node<'t>>)>, // statement, source, TS binding
    pub binds: Vec<(Node<'t>, Node<'t>)>,           // name, value
    pub members: Vec<Node<'t>>,
    pub strings: Vec<Node<'t>>,
}

/// What a name refers to: a module (with members) or a global (with members).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Qualified {
    Module(String, Vec<String>),
    Global(Vec<String>),
}

impl Qualified {
    fn member(&self, name: &str) -> Option<Self> {
        let mut q = self.clone();
        let members = match &mut q {
            Self::Module(_, m) | Self::Global(m) => m,
        };
        if members.len() >= MAX_EXPR_DEPTH {
            return None;
        }
        members.push(name.to_owned());
        Some(q)
    }

    pub fn display(&self) -> String {
        match self {
            Self::Module(module, members) if members.is_empty() => module.clone(),
            Self::Module(module, members) => format!("{module}.{}", members.join(".")),
            Self::Global(members) => members.join("."),
        }
    }

    /// The members as one dotted string, for globals.
    pub fn global(&self) -> Option<String> {
        match self {
            Self::Global(m) => Some(m.join(".")),
            Self::Module(..) => None,
        }
    }

    pub fn last(&self) -> Option<&str> {
        match self {
            Self::Module(_, m) | Self::Global(m) => m.last().map(String::as_str),
        }
    }
}

/// Globals whose members are resolved. Any other free name is unknown, since it may be a
/// local we don't track.
const GLOBALS: [&str; 20] = [
    "eval",
    "Function",
    "fetch",
    "require",
    "process",
    "Buffer",
    "atob",
    "setTimeout",
    "setInterval",
    "setImmediate",
    "WebSocket",
    "XMLHttpRequest",
    "EventSource",
    "navigator",
    "module",
    "String",
    "ethereum",
    "decodeURIComponent",
    "decodeURI",
    "unescape",
];

/// Prefixes that name the global object itself.
const GLOBAL_OBJECTS: [&str; 4] = ["window", "globalThis", "global", "self"];

impl<'s> File<'s> {
    pub fn text(&self, node: Node) -> &'s str {
        std::str::from_utf8(&self.source[node.byte_range()]).unwrap_or("")
    }

    pub fn line(node: Node) -> u32 {
        u32::try_from(node.start_position().row + 1).unwrap_or(u32::MAX)
    }

    /// The source line holding the node, or the node itself if the line is long (minified).
    pub fn snippet(&self, node: Node) -> String {
        let start = node.start_byte();
        let line_start = self.source[..start]
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |i| i + 1);
        let line_end = self.source[start..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(self.source.len(), |i| start + i);
        let line = &self.source[line_start..line_end];
        let text = if line.len() <= 200 {
            line
        } else {
            &self.source[node.byte_range()][..node.byte_range().len().min(160)]
        };
        String::from_utf8_lossy(text).trim().to_owned()
    }

    /// Whether code at the node runs when the file is loaded.
    pub fn top_level(&self, node: Node) -> bool {
        let at = node.start_byte();
        let i = self.deferred.partition_point(|&(start, _)| start <= at);
        i == 0 || at >= self.deferred[i - 1].1
    }

    /// Collects the candidate nodes in one pre-order walk. The node kinds are the same in the
    /// JavaScript, TypeScript and TSX grammars.
    fn capture<'t>(root: Node<'t>) -> Captured<'t> {
        let mut out = Captured::default();
        let mut cursor = root.walk();
        loop {
            let node = cursor.node();
            let field = |name: &str| node.child_by_field_name(name);
            match node.kind() {
                "call_expression" => {
                    if let (Some(f), Some(a)) = (field("function"), field("arguments")) {
                        out.calls.push((node, f, a));
                    }
                }
                "new_expression" => {
                    if let Some(f) = field("constructor") {
                        out.news.push((node, f));
                    }
                }
                "import_statement" | "export_statement" => {
                    if let Some(s) = field("source") {
                        out.imports.push((node, s, None));
                    }
                }
                // TypeScript's `import x = require("y")`.
                "import_require_clause" => {
                    if let Some(s) = field("source") {
                        out.imports.push((node, s, node.named_child(0)));
                    }
                }
                "variable_declarator" => {
                    if let (Some(n), Some(v)) = (field("name"), field("value")) {
                        out.binds.push((n, v));
                    }
                }
                "assignment_expression" => {
                    if let (Some(n), Some(v)) = (field("left"), field("right")) {
                        out.binds.push((n, v));
                    }
                }
                "member_expression" | "subscript_expression" => out.members.push(node),
                "string" | "template_string" => out.strings.push(node),
                _ => {}
            }
            if cursor.goto_first_child() {
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return out;
                }
            }
        }
    }

    fn analyze(&self, root: Node) -> FileFacts {
        let captured = Self::capture(root);
        let mut facts = FileFacts::default();
        let mut bindings: HashMap<String, Qualified> = HashMap::new();

        for (statement, source, ts_name) in &captured.imports {
            let Some(specifier) = self.const_string(*source) else {
                continue;
            };
            let module = normalize_module(&specifier);
            facts.imports.push(Import {
                specifier: specifier.clone(),
                top_level: self.top_level(*statement),
            });
            if let Some(name) = ts_name {
                bindings.insert(
                    self.text(*name).to_owned(),
                    Qualified::Module(module.clone(), vec![]),
                );
            }
            self.bind_import_clause(*statement, &module, &mut bindings);
            if let Some(cap) = module_capability(&module) {
                facts
                    .uses
                    .push(self.use_at(*statement, cap, "", module.clone(), false));
            }
        }

        // Twice, so that a binding to an earlier binding resolves.
        for _ in 0..2 {
            for (name, value) in &captured.binds {
                if let Some(q) = self.qualify(*value, &bindings, 0) {
                    self.bind_pattern(*name, &q, &mut bindings);
                }
            }
        }

        for (call, callee, args) in &captured.calls {
            self.classify_call(*call, *callee, *args, &bindings, &mut facts);
        }
        for (new, callee) in &captured.news {
            let Some(q) = self.qualify(*callee, &bindings, 0) else {
                continue;
            };
            let capability = match (&q, q.global().as_deref()) {
                (_, Some("Function")) => Some(Capability::DynamicCode),
                (_, Some("WebSocket" | "XMLHttpRequest" | "EventSource")) => {
                    Some(Capability::Network)
                }
                (Qualified::Module(m, _), _) => module_capability(m),
                _ => None,
            };
            if let Some(cap) = capability {
                let top = self.top_level(*new);
                facts
                    .uses
                    .push(self.use_at(*new, cap, "", q.display(), top));
            }
        }
        for member in &captured.members {
            let Some(q) = self.qualify(*member, &bindings, 0) else {
                continue;
            };
            let Some(global) = q.global() else { continue };
            let capability = if global == "process.env" || global.starts_with("process.env.") {
                Capability::EnvAccess
            } else if global.starts_with("ethereum.") {
                Capability::CryptoWallet
            } else {
                continue;
            };
            let top = self.top_level(*member);
            facts
                .uses
                .push(self.use_at(*member, capability, "", global, top));
        }

        let mut wallets: Vec<(Node, &'static str)> = Vec::new();
        let mut seen_wallets = HashSet::new();
        for string in &captured.strings {
            let raw = self.string_body(*string);
            let (decoded, escapes) = strings::decode_js(raw);
            if let Some(label) = strings::sensitive_path(&decoded) {
                let top = self.top_level(*string);
                facts.uses.push(self.use_at(
                    *string,
                    Capability::FsSensitiveRead,
                    "",
                    format!("{label}: {decoded}"),
                    top,
                ));
            }
            if let Some(chain) = strings::wallet_address(&decoded)
                && seen_wallets.insert(decoded.clone())
            {
                wallets.push((*string, chain));
            }
            obfuscation::string_signals(self, *string, &decoded, escapes, &mut facts);
        }
        // One address is a donation link; several is a replacement table.
        if wallets.len() >= 3 {
            let (node, chain) = wallets[0];
            let top = self.top_level(node);
            facts.uses.push(self.use_at(
                node,
                Capability::CryptoWallet,
                "",
                format!("{} wallet addresses, first {chain}", wallets.len()),
                top,
            ));
        }

        obfuscation::decode_exec(self, &captured, &bindings, &mut facts);
        facts
    }

    pub fn use_at(
        &self,
        node: Node,
        capability: Capability,
        signal: &'static str,
        detail: String,
        top_level: bool,
    ) -> Use {
        Use {
            capability,
            signal,
            detail,
            line: Self::line(node),
            snippet: self.snippet(node),
            top_level,
        }
    }

    fn classify_call(
        &self,
        call: Node,
        callee: Node,
        args: Node,
        bindings: &HashMap<String, Qualified>,
        facts: &mut FileFacts,
    ) {
        let top = self.top_level(call);
        let first_arg = args.named_child(0);
        // require("x") and import("x").
        if callee.kind() == "import" || self.text(callee) == "require" {
            match first_arg.and_then(|a| self.const_string(a)) {
                Some(specifier) => {
                    facts.imports.push(Import {
                        specifier: specifier.clone(),
                        top_level: top,
                    });
                    let module = normalize_module(&specifier);
                    if specifier.to_ascii_lowercase().ends_with(".node") {
                        facts.uses.push(self.use_at(
                            call,
                            Capability::NativeBinary,
                            "",
                            format!("require {specifier}"),
                            top,
                        ));
                    } else if let Some(cap) = module_capability(&module) {
                        // The use is wherever the module is called; loading it is a weak sign.
                        facts.uses.push(self.use_at(call, cap, "", module, false));
                    }
                }
                None if first_arg.is_some() => facts.uses.push(self.use_at(
                    call,
                    Capability::DynamicCode,
                    "",
                    "require of a computed name".into(),
                    top,
                )),
                None => {}
            }
            return;
        }
        let Some(q) = self.qualify(callee, bindings, 0) else {
            // Sinks reached through objects we can't name: m._compile(src).
            if callee.kind() == "member_expression"
                && callee
                    .child_by_field_name("property")
                    .is_some_and(|p| self.text(p) == "_compile")
            {
                facts.uses.push(self.use_at(
                    call,
                    Capability::DynamicCode,
                    "",
                    "Module._compile".into(),
                    top,
                ));
            }
            return;
        };
        let detail = q.display();
        let capability = match &q {
            Qualified::Module(module, _) => module_capability(module),
            Qualified::Global(members) => match members.join(".").as_str() {
                "eval" | "Function" => Some(Capability::DynamicCode),
                "setTimeout" | "setInterval" | "setImmediate"
                    if first_arg.is_some_and(|a| {
                        matches!(a.kind(), "string" | "template_string" | "binary_expression")
                    }) =>
                {
                    Some(Capability::DynamicCode)
                }
                "fetch" | "navigator.sendBeacon" => Some(Capability::Network),
                "process.binding" | "process._linkedBinding" => Some(Capability::ProcessSpawn),
                "process.dlopen" => Some(Capability::NativeBinary),
                g if g.ends_with("._compile") => Some(Capability::DynamicCode),
                g if g.starts_with("ethereum.") => Some(Capability::CryptoWallet),
                _ => None,
            },
        };
        if let Some(cap) = capability {
            facts.uses.push(self.use_at(call, cap, "", detail, top));
        }
    }

    /// Binds the names an import statement introduces.
    fn bind_import_clause(
        &self,
        statement: Node,
        module: &str,
        bindings: &mut HashMap<String, Qualified>,
    ) {
        let mut cursor = statement.walk();
        for child in statement.named_children(&mut cursor) {
            if child.kind() != "import_clause" {
                continue;
            }
            let mut inner = child.walk();
            for part in child.named_children(&mut inner) {
                match part.kind() {
                    // import x from "m": the default export, which is the module for CommonJS.
                    "identifier" => {
                        bindings.insert(
                            self.text(part).to_owned(),
                            Qualified::Module(module.to_owned(), vec![]),
                        );
                    }
                    "namespace_import" => {
                        if let Some(id) = part.named_child(0) {
                            bindings.insert(
                                self.text(id).to_owned(),
                                Qualified::Module(module.to_owned(), vec![]),
                            );
                        }
                    }
                    "named_imports" => {
                        let mut specs = part.walk();
                        for spec in part.named_children(&mut specs) {
                            let Some(name) = spec.child_by_field_name("name") else {
                                continue;
                            };
                            let local = spec.child_by_field_name("alias").unwrap_or(name);
                            let imported = self.text(name).trim_matches(['"', '\'']);
                            bindings.insert(
                                self.text(local).to_owned(),
                                Qualified::Module(module.to_owned(), vec![imported.to_owned()]),
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Binds an identifier, or each name in a destructuring pattern, to members of `q`.
    fn bind_pattern(
        &self,
        pattern: Node,
        q: &Qualified,
        bindings: &mut HashMap<String, Qualified>,
    ) {
        match pattern.kind() {
            "identifier" => {
                bindings.insert(self.text(pattern).to_owned(), q.clone());
            }
            "object_pattern" => {
                let mut cursor = pattern.walk();
                for prop in pattern.named_children(&mut cursor) {
                    match prop.kind() {
                        "shorthand_property_identifier_pattern" => {
                            let name = self.text(prop);
                            if let Some(m) = q.member(name) {
                                bindings.insert(name.to_owned(), m);
                            }
                        }
                        "pair_pattern" => {
                            let (Some(key), Some(value)) = (
                                prop.child_by_field_name("key"),
                                prop.child_by_field_name("value"),
                            ) else {
                                continue;
                            };
                            let key = self
                                .const_string(key)
                                .unwrap_or_else(|| self.text(key).to_owned());
                            if value.kind() == "identifier"
                                && let Some(m) = q.member(&key)
                            {
                                bindings.insert(self.text(value).to_owned(), m);
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    /// Resolves an expression to the module or global it names, if it names one.
    pub(crate) fn qualify(
        &self,
        node: Node,
        bindings: &HashMap<String, Qualified>,
        depth: usize,
    ) -> Option<Qualified> {
        if depth > MAX_EXPR_DEPTH {
            return None;
        }
        match node.kind() {
            "identifier" => {
                let name = self.text(node);
                if let Some(q) = bindings.get(name) {
                    return Some(q.clone());
                }
                GLOBALS
                    .contains(&name)
                    .then(|| Qualified::Global(vec![name.to_owned()]))
            }
            "member_expression" | "subscript_expression" => {
                let object = node.child_by_field_name("object")?;
                let property = node
                    .child_by_field_name("property")
                    .or_else(|| node.child_by_field_name("index"))?;
                let name = if property.kind() == "property_identifier" {
                    self.text(property).to_owned()
                } else {
                    self.const_string(property)?
                };
                // window.fetch is fetch.
                if object.kind() == "identifier" && GLOBAL_OBJECTS.contains(&self.text(object)) {
                    if let Some(q) = bindings.get(self.text(object)) {
                        return q.member(&name);
                    }
                    return GLOBALS
                        .contains(&name.as_str())
                        .then(|| Qualified::Global(vec![name]));
                }
                self.qualify(object, bindings, depth + 1)?.member(&name)
            }
            "parenthesized_expression" | "await_expression" | "non_null_expression" => {
                self.qualify(node.named_child(0)?, bindings, depth + 1)
            }
            // (0, eval)(s): a sequence evaluates to its last expression.
            "sequence_expression" => {
                let count = u32::try_from(node.named_child_count()).ok()?;
                let last = node.named_child(count.checked_sub(1)?)?;
                self.qualify(last, bindings, depth + 1)
            }
            "call_expression" => {
                let callee = node.child_by_field_name("function")?;
                let is_load = callee.kind() == "import" || self.text(callee) == "require";
                if !is_load {
                    return None;
                }
                let args = node.child_by_field_name("arguments")?;
                let specifier = self.const_string(args.named_child(0)?)?;
                Some(Qualified::Module(normalize_module(&specifier), vec![]))
            }
            _ => None,
        }
    }

    /// The body of a string or template literal, without quotes.
    pub fn string_body(&self, node: Node) -> &'s str {
        let text = self.text(node);
        let mut chars = text.chars();
        match (chars.next(), chars.next_back()) {
            (Some(open), Some(close)) if open == close && "\"'`".contains(open) => {
                &text[1..text.len() - 1]
            }
            _ => text,
        }
    }

    /// The value of a constant string expression: a literal, a template without
    /// substitutions, or a concatenation of those ("child_" + "process").
    pub fn const_string(&self, node: Node) -> Option<String> {
        let mut out = String::new();
        let mut stack = vec![node];
        let mut visited = 0;
        while let Some(n) = stack.pop() {
            visited += 1;
            if visited > 64 || out.len() > 4096 {
                return None;
            }
            match n.kind() {
                "string" => out.push_str(&strings::decode_js(self.string_body(n)).0),
                "template_string" => {
                    let mut cursor = n.walk();
                    if n.named_children(&mut cursor)
                        .any(|c| c.kind() == "template_substitution")
                    {
                        return None;
                    }
                    out.push_str(&strings::decode_js(self.string_body(n)).0);
                }
                "binary_expression" => {
                    let operator = n.child_by_field_name("operator")?;
                    if self.text(operator) != "+" {
                        return None;
                    }
                    // Right first, so the left is popped (and appended) first.
                    stack.push(n.child_by_field_name("right")?);
                    stack.push(n.child_by_field_name("left")?);
                }
                "parenthesized_expression" => stack.push(n.named_child(0)?),
                _ => return None,
            }
        }
        Some(out)
    }
}

/// `node:fs/promises` → `fs`, `@scope/pkg/sub` → `@scope/pkg`. Relative paths are kept.
pub fn normalize_module(specifier: &str) -> String {
    let s = specifier.strip_prefix("node:").unwrap_or(specifier);
    if s.starts_with('.') || s.starts_with('/') {
        return s.to_owned();
    }
    let mut parts = s.splitn(3, '/');
    match (parts.next(), parts.next()) {
        (Some(scope), Some(name)) if scope.starts_with('@') => format!("{scope}/{name}"),
        (Some(name), _) => name.to_owned(),
        _ => s.to_owned(),
    }
}

/// The capability a module grants by itself.
pub fn module_capability(module: &str) -> Option<Capability> {
    const NETWORK: [&str; 21] = [
        "http",
        "https",
        "http2",
        "net",
        "tls",
        "dgram",
        "dns",
        "undici",
        "axios",
        "node-fetch",
        "got",
        "request",
        "ws",
        "socket.io-client",
        "superagent",
        "needle",
        "phin",
        "cross-fetch",
        "isomorphic-fetch",
        "ky",
        "make-fetch-happen",
    ];
    const SPAWN: [&str; 6] = [
        "child_process",
        "cluster",
        "execa",
        "cross-spawn",
        "shelljs",
        "node-pty",
    ];
    if NETWORK.contains(&module) {
        Some(Capability::Network)
    } else if SPAWN.contains(&module) {
        Some(Capability::ProcessSpawn)
    } else if module == "vm" {
        Some(Capability::DynamicCode)
    } else {
        None
    }
}

/// The byte ranges of function bodies that don't run when their file loads, outermost only,
/// sorted. A function runs at load when it is called on the spot (`(function(){})()`,
/// `(function(){}).call(this)`) or passed to a call made at load (a callback, a UMD factory).
/// This over-approximates for callbacks that run later, such as request handlers.
fn deferred_ranges(root: Node) -> Vec<(usize, usize)> {
    const FUNCTIONS: [&str; 7] = [
        "function_declaration",
        "function_expression",
        "function",
        "arrow_function",
        "method_definition",
        "generator_function_declaration",
        "generator_function",
    ];
    let mut ranges = Vec::new();
    let mut cursor: TreeCursor = root.walk();
    // Each ancestor's kind and the field its child sits in.
    let mut path: Vec<(&str, Option<&str>)> = Vec::new();
    loop {
        let node = cursor.node();
        let field = cursor.field_name();
        // Named only: the `function` keyword token shares a kind name.
        let deferred =
            node.is_named() && FUNCTIONS.contains(&node.kind()) && !runs_at_once(&path, field);
        if deferred {
            ranges.push((node.start_byte(), node.end_byte()));
        } else if cursor.goto_first_child() {
            path.push((node.kind(), field));
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return ranges;
            }
            path.pop();
        }
    }
}

/// Whether a function whose ancestors are `path` (nearest last) and which sits in `field` of
/// its parent is called where it is defined.
fn runs_at_once(path: &[(&str, Option<&str>)], field: Option<&str>) -> bool {
    // Look through parentheses: (function(){})().
    let mut field = field;
    let mut i = path.len();
    while i > 0 && path[i - 1].0 == "parenthesized_expression" {
        field = path[i - 1].1;
        i -= 1;
    }
    let Some(&(parent, parent_field)) = i.checked_sub(1).map(|j| &path[j]) else {
        return false;
    };
    match parent {
        "call_expression" => field == Some("function"),
        // A callback: f(function(){}).
        "arguments" => i >= 2 && matches!(path[i - 2].0, "call_expression" | "new_expression"),
        // (function(){}).call(this)
        "member_expression" => {
            field == Some("object")
                && parent_field == Some("function")
                && i >= 2
                && path[i - 2].0 == "call_expression"
        }
        // !function(){}() parses as !(call), handled above; new function(){} runs at once.
        "new_expression" => field == Some("constructor"),
        _ => false,
    }
}

#[cfg(test)]
mod tests;
