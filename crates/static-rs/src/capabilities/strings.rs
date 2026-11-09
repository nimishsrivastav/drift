//! What string literals reveal: sensitive paths, wallet addresses, encoded data.

/// Decodes a JavaScript string literal's body (without its quotes). Escapes are what hide
/// `.ssh` as `\x2e\x73\x73\x68`, so they are decoded before matching. Returns the decoded text
/// and how many `\x`/`\u` escapes it had.
pub fn decode_js(raw: &str) -> (String, usize) {
    let mut out = String::with_capacity(raw.len());
    let mut escapes = 0;
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(e) = chars.next() else { break };
        match e {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'v' => out.push('\u{b}'),
            '0' => out.push('\0'),
            'x' => {
                let hex: String = chars.by_ref().take(2).collect();
                escapes += 1;
                match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    Some(d) => out.push(d),
                    None => out.push_str(&hex),
                }
            }
            'u' => {
                escapes += 1;
                let hex: String = if chars.peek() == Some(&'{') {
                    chars.next();
                    chars.by_ref().take_while(|&c| c != '}').take(6).collect()
                } else {
                    chars.by_ref().take(4).collect()
                };
                match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    Some(d) => out.push(d),
                    None => out.push_str(&hex),
                }
            }
            '\r' | '\n' => {} // line continuation
            other => out.push(other),
        }
    }
    (out, escapes)
}

/// Path segments that name credentials or wallets on their own.
const SENSITIVE_SEGMENTS: [(&str, &str); 22] = [
    (".ssh", "ssh"),
    ("id_rsa", "ssh"),
    ("id_ed25519", "ssh"),
    ("id_ecdsa", "ssh"),
    (".aws", "aws"),
    (".npmrc", "npm"),
    (".pypirc", "pypi"),
    (".netrc", "netrc"),
    (".git-credentials", "git"),
    (".gnupg", "gpg"),
    (".kube", "kubernetes"),
    (".docker", "docker"),
    (".azure", "azure"),
    (".bash_history", "shell-history"),
    (".zsh_history", "shell-history"),
    ("wallet.dat", "wallet"),
    (".electrum", "wallet"),
    ("exodus", "wallet"),
    (".ethereum", "wallet"),
    ("login data", "browser"),
    ("web data", "browser"),
    ("application_default_credentials.json", "gcloud"),
];

/// Longer paths that are sensitive only together.
const SENSITIVE_PATHS: [(&str, &str); 7] = [
    ("etc/passwd", "system"),
    ("etc/shadow", "system"),
    ("local storage/leveldb", "browser"),
    (".config/gcloud", "gcloud"),
    ("solana/id.json", "wallet"),
    (".terraform.d/credentials", "terraform"),
    // MetaMask's extension ID, which browser-profile stealers enumerate.
    ("nkbihfbbogaeaoehlefnkodbefgpgknn", "wallet"),
];

/// The kind of secret a string points at, if it names a credential or wallet path.
pub fn sensitive_path(text: &str) -> Option<&'static str> {
    if text.len() > 512 {
        return None;
    }
    let lower = text.to_ascii_lowercase().replace('\\', "/");
    for (needle, label) in SENSITIVE_PATHS {
        if lower.contains(needle) {
            return Some(label);
        }
    }
    for segment in lower.split('/') {
        for (name, label) in SENSITIVE_SEGMENTS {
            if segment == name {
                return Some(label);
            }
        }
    }
    None
}

const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BECH32: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// The chain of a cryptocurrency address, if the whole string is one.
pub fn wallet_address(text: &str) -> Option<&'static str> {
    let b = text.as_bytes();
    if b.len() == 42 && text.starts_with("0x") && b[2..].iter().all(u8::is_ascii_hexdigit) {
        // Exclude all-zero and other trivially repetitive constants.
        if b[2..].iter().any(|&c| c != b'0') {
            return Some("ethereum");
        }
    }
    if let Some(rest) = text.strip_prefix("bc1")
        && (25..=87).contains(&rest.len())
        && rest.bytes().all(|c| BECH32.contains(&c))
    {
        return Some("bitcoin");
    }
    let base58 = |s: &[u8]| s.iter().all(|c| BASE58.contains(c));
    if (b.first() == Some(&b'1') || b.first() == Some(&b'3'))
        && (26..=35).contains(&b.len())
        && base58(b)
        && has_mixed_case_and_digits(text)
    {
        return Some("bitcoin");
    }
    if b.first() == Some(&b'T') && b.len() == 34 && base58(b) && has_mixed_case_and_digits(text) {
        return Some("tron");
    }
    None
}

fn has_mixed_case_and_digits(text: &str) -> bool {
    text.bytes().any(|c| c.is_ascii_uppercase())
        && text.bytes().any(|c| c.is_ascii_lowercase())
        && text.bytes().any(|c| c.is_ascii_digit())
}

/// Shannon entropy in bits per character.
pub fn entropy(text: &str) -> f64 {
    let mut counts = std::collections::HashMap::new();
    let mut total = 0usize;
    for c in text.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let total = total as f64;
    counts
        .values()
        .map(|&n| {
            let p = n as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// What kind of encoded data a long string is, if it is one.
pub fn encoded_blob(text: &str) -> Option<&'static str> {
    const MIN: usize = 256;
    if text.len() < MIN {
        return None;
    }
    // Images and fonts are routinely inlined as data URIs.
    let lower_head = text[..text.len().min(40)].to_ascii_lowercase();
    if lower_head.starts_with("data:image/") || lower_head.starts_with("data:font/") {
        return None;
    }
    let body = text.trim_end_matches('=');
    if body.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Some("hex");
    }
    if body
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'-' || c == b'_')
        && has_mixed_case_and_digits(body)
    {
        return Some("base64");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_escapes() {
        assert_eq!(decode_js(r"\x2e\x73\x73\x68"), (".ssh".into(), 4));
        assert_eq!(decode_js(r"a\u0062\u{63}\n"), ("abc\n".into(), 2));
        assert_eq!(decode_js(r"it\'s"), ("it's".into(), 0));
        assert_eq!(decode_js(r"\xZZ"), ("ZZ".into(), 1));
    }

    #[test]
    fn finds_sensitive_paths() {
        assert_eq!(sensitive_path(".npmrc"), Some("npm"));
        assert_eq!(sensitive_path("/home/x/.ssh/id_rsa"), Some("ssh"));
        assert_eq!(sensitive_path(r"C:\Users\x\.aws\credentials"), Some("aws"));
        assert_eq!(sensitive_path("/etc/passwd"), Some("system"));
        assert_eq!(
            sensitive_path("Google/Chrome/User Data/Default/Login Data"),
            Some("browser")
        );
        assert_eq!(sensitive_path("ssh is a protocol"), None);
        assert_eq!(sensitive_path("my.npmrc.example"), None);
        assert_eq!(sensitive_path("README.md"), None);
    }

    #[test]
    fn recognizes_wallet_addresses() {
        assert_eq!(
            wallet_address("0x52908400098527886E0F7030069857D2E4169EE7"),
            Some("ethereum")
        );
        assert_eq!(
            wallet_address("0x0000000000000000000000000000000000000000"),
            None
        );
        assert_eq!(
            wallet_address("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
            Some("bitcoin")
        );
        assert_eq!(
            wallet_address("1BoatSLRHtKNngkdXEeobR76b53LETtpyT"),
            Some("bitcoin")
        );
        assert_eq!(
            wallet_address("TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7"),
            Some("tron")
        );
        assert_eq!(wallet_address("1234567890123456789012345678"), None);
        assert_eq!(wallet_address("hello"), None);
    }

    #[test]
    fn measures_entropy_and_blobs() {
        assert!(entropy("aaaa") < 0.01);
        assert!((entropy("abcd") - 2.0).abs() < 1e-9);
        let b64 =
            "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk"
                .repeat(4)
                + "=";
        assert_eq!(encoded_blob(&b64), Some("base64"));
        assert_eq!(encoded_blob(&"deadbeef".repeat(40)), Some("hex"));
        let data_uri = format!("data:image/png;base64,{b64}");
        assert_eq!(encoded_blob(&data_uri), None);
        assert_eq!(encoded_blob(&"word ".repeat(80)), None);
    }
}
