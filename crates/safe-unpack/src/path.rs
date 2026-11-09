//! Path normalization. Every path from an archive goes through here before it is used.

use crate::Limits;
use crate::error::PathError;

/// Normalizes an archive path to `a/b/c`, relative to the root.
///
/// Returns `Ok(None)` for the root itself (`""` after stripping `.` components, such as `./`).
/// Rejects absolute paths, `..`, NUL and control characters, backslashes, non-UTF-8 names and
/// paths over the depth or length limits. Rejecting rather than repairing means the extracted
/// tree never differs from what the archive says in a way an attacker could steer.
pub(crate) fn sanitize(raw: &[u8], limits: &Limits) -> Result<Option<String>, PathError> {
    if raw.is_empty() {
        return Err(PathError::Empty);
    }
    if raw.len() > limits.max_path_bytes {
        return Err(PathError::TooLong);
    }
    let text = std::str::from_utf8(raw).map_err(|_| PathError::NotUtf8)?;
    if text.chars().any(|c| c.is_control() || c == '\\') {
        return Err(PathError::BadChar);
    }
    if text.starts_with('/') || has_drive_prefix(text) {
        return Err(PathError::Absolute);
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in text.split('/') {
        match part {
            "" | "." => {}
            ".." => return Err(PathError::Traversal),
            _ => parts.push(part),
        }
    }
    if parts.len() > limits.max_depth {
        return Err(PathError::TooDeep);
    }
    Ok((!parts.is_empty()).then(|| parts.join("/")))
}

/// `C:` style prefixes, which some zip tools write and Windows extractors treat as absolute.
fn has_drive_prefix(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// Resolves a symlink target lexically against the link's own directory. Returns the target as
/// a root-relative path (empty for the root), or `None` if it is absolute, malformed or climbs
/// above the root.
pub(crate) fn resolve_symlink(link: &str, target: &[u8], limits: &Limits) -> Option<String> {
    if target.is_empty() || target.len() > limits.max_path_bytes {
        return None;
    }
    let text = std::str::from_utf8(target).ok()?;
    if text.chars().any(|c| c.is_control() || c == '\\') {
        return None;
    }
    if text.starts_with('/') || has_drive_prefix(text) {
        return None;
    }
    let mut parts: Vec<&str> = link.split('/').collect();
    parts.pop(); // the link's own name
    for part in text.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            _ => parts.push(part),
        }
    }
    if parts.len() > limits.max_depth {
        return None;
    }
    Some(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(raw: &str) -> Option<String> {
        sanitize(raw.as_bytes(), &Limits::default()).unwrap()
    }

    fn err(raw: &[u8]) -> PathError {
        sanitize(raw, &Limits::default()).unwrap_err()
    }

    #[test]
    fn normalizes_ordinary_paths() {
        assert_eq!(ok("package/index.js").as_deref(), Some("package/index.js"));
        assert_eq!(
            ok("./package//lib/./a.js").as_deref(),
            Some("package/lib/a.js")
        );
        assert_eq!(ok("package/").as_deref(), Some("package"));
        assert_eq!(ok("./"), None);
        assert_eq!(ok("."), None);
        assert_eq!(ok("dir/ünïcode ✓.js").as_deref(), Some("dir/ünïcode ✓.js"));
        // A name that merely contains dots is fine.
        assert_eq!(ok("a/..b/c..").as_deref(), Some("a/..b/c.."));
    }

    #[test]
    fn rejects_dangerous_paths() {
        let cases: &[(&[u8], PathError)] = &[
            (b"", PathError::Empty),
            (b"../evil", PathError::Traversal),
            (b"package/../../evil", PathError::Traversal),
            (b"package/..", PathError::Traversal),
            (b"/etc/passwd", PathError::Absolute),
            (b"//server/share", PathError::Absolute),
            (b"C:/Windows/evil", PathError::Absolute),
            (b"c:evil", PathError::Absolute),
            (b"..\\evil", PathError::BadChar),
            (b"a\0b", PathError::BadChar),
            (b"a\nb", PathError::BadChar),
            (b"a\x1b[2Jb", PathError::BadChar),
            (b"a\x7fb", PathError::BadChar),
            (b"a\xc2\x85b", PathError::BadChar), // U+0085, a C1 control
            (b"\xff\xfe", PathError::NotUtf8),
        ];
        for (raw, want) in cases {
            assert_eq!(err(raw), *want, "{:?}", String::from_utf8_lossy(raw));
        }
    }

    #[test]
    fn enforces_depth_and_length() {
        let limits = Limits {
            max_depth: 3,
            max_path_bytes: 16,
            ..Limits::default()
        };
        assert!(sanitize(b"a/b/c", &limits).is_ok());
        assert_eq!(sanitize(b"a/b/c/d", &limits), Err(PathError::TooDeep));
        assert_eq!(sanitize(&[b'a'; 17], &limits), Err(PathError::TooLong));
    }

    #[test]
    fn resolves_symlinks_lexically() {
        let limits = Limits::default();
        let resolve = |link: &str, target: &str| resolve_symlink(link, target.as_bytes(), &limits);
        assert_eq!(
            resolve("package/lib/link", "../index.js").as_deref(),
            Some("package/index.js")
        );
        assert_eq!(
            resolve("package/link", "./a/b").as_deref(),
            Some("package/a/b")
        );
        assert_eq!(resolve("package/link", "..").as_deref(), Some(""));
        assert_eq!(resolve("package/link", "../.."), None);
        assert_eq!(resolve("package/link", "../../etc/passwd"), None);
        assert_eq!(resolve("link", "../x"), None);
        assert_eq!(resolve("package/link", "/etc/passwd"), None);
        assert_eq!(resolve("package/link", ""), None);
        assert_eq!(resolve("package/link", "a\\..\\..\\x"), None);
        // Climbing out and back in still counts as escaping at the moment it climbs out.
        assert_eq!(resolve("package/link", "../../package/x"), None);
    }
}
