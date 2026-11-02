//! The names an entry may have: what is refused, rather than cleaned up,
//! and the same on every system, so that what an archive extracts to does
//! not depend on where it is extracted.
//!
//! Cleaning names up (dropping `..`, a leading `/` or a drive) is what
//! other extractors do, and two of them clean the same name differently:
//! `foo/../bar` becomes `foo/bar` in one and `bar` in another. Refusing
//! leaves nothing to disagree on.

use std::fmt;

/// Why a name is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameError {
    /// The name is empty, or a component of it is (`a//b`).
    Empty,
    /// Not UTF-8, once decoded from the archive's encoding.
    NotUtf8,
    /// A NUL byte, another control character (U+0001 to U+001F) or DEL.
    Control,
    /// A backslash, which Windows takes for a separator.
    Backslash,
    /// It starts with `/`: an absolute path.
    Absolute,
    /// A colon: a drive (`C:`) or an NTFS alternate data stream (`a:b`).
    Colon,
    /// A character Windows does not allow in names: `<`, `>`, `"`, `|`,
    /// `?` or `*`.
    Reserved,
    /// A component `.` or `..`.
    Dot,
    /// A Windows device name, with or without an extension (`CON`,
    /// `nul.txt`, `COM1`, `LPT¹`, `CONIN$`).
    Device,
    /// A component that ends in a space or a dot, which Windows drops.
    TrailingSpaceOrDot,
    /// A component longer than 255 bytes.
    TooLong,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NameError::Empty => "empty name or component",
            NameError::NotUtf8 => "not UTF-8",
            NameError::Control => "control character",
            NameError::Backslash => "backslash",
            NameError::Absolute => "absolute path",
            NameError::Colon => "colon (drive or alternate data stream)",
            NameError::Reserved => "character Windows does not allow (< > \" | ? *)",
            NameError::Dot => "component \".\" or \"..\"",
            NameError::Device => "Windows device name",
            NameError::TrailingSpaceOrDot => "component ending in a space or a dot",
            NameError::TooLong => "component longer than 255 bytes",
        })
    }
}

/// The longest component, in bytes, that file systems take.
pub const MAX_COMPONENT: usize = 255;

/// A name that passed: its components, and whether it names a directory
/// (it ended in `/`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Name {
    pub components: Vec<String>,
    pub is_dir: bool,
}

/// The device names of Windows, which name a device in any directory,
/// whatever extension follows them. `COM` and `LPT` take a digit, or the
/// superscripts ¹, ² and ³, which Windows takes for digits too.
fn is_device(component: &str) -> bool {
    let base = component.split('.').next().unwrap_or_default();
    // Windows drops spaces before the extension: "NUL .txt" is NUL.
    let base = base.trim_end_matches(' ').to_ascii_uppercase();
    match base.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" => true,
        _ => {
            // Not split where a character is cut: names are the archive's.
            let (Some(prefix), Some(number)) = (base.get(..3), base.get(3..)) else {
                return false;
            };
            (prefix == "COM" || prefix == "LPT")
                && matches!(
                    number,
                    "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
        }
    }
}

/// The characters Windows does not allow in names, besides `\`, `/`, `:`
/// and control characters, which are refused for their own reasons.
const RESERVED: [char; 6] = ['<', '>', '"', '|', '?', '*'];

/// Checks `raw`, an entry's name as the archive gives it, `/` its only
/// separator: [`Name`], or why it is refused.
pub fn check_name(raw: &[u8]) -> Result<Name, NameError> {
    if raw.is_empty() {
        return Err(NameError::Empty);
    }
    let name = std::str::from_utf8(raw).map_err(|_| NameError::NotUtf8)?;
    if name.chars().any(|c| c.is_ascii_control()) {
        return Err(NameError::Control);
    }
    if name.contains('\\') {
        return Err(NameError::Backslash);
    }
    if name.starts_with('/') {
        return Err(NameError::Absolute);
    }
    if name.contains(':') {
        return Err(NameError::Colon);
    }
    if name.contains(RESERVED) {
        return Err(NameError::Reserved);
    }
    let (path, is_dir) = match name.strip_suffix('/') {
        Some(path) => (path, true),
        None => (name, false),
    };
    let mut components = Vec::new();
    for component in path.split('/') {
        if component.is_empty() {
            return Err(NameError::Empty);
        }
        if component == "." || component == ".." {
            return Err(NameError::Dot);
        }
        if component.len() > MAX_COMPONENT {
            return Err(NameError::TooLong);
        }
        if component.ends_with(' ') || component.ends_with('.') {
            return Err(NameError::TrailingSpaceOrDot);
        }
        if is_device(component) {
            return Err(NameError::Device);
        }
        components.push(component.to_string());
    }
    Ok(Name { components, is_dir })
}

/// `name` as the options take it, before [`check_name`]: with
/// `backslash`, `\` turned into `/`; with `sanitize`, what Python's
/// `zipfile` drops dropped (a leading `/`, a drive `C:`, and `.`, `..` and
/// empty components). A directory keeps its final `/`.
pub(crate) fn prepare(name: &str, backslash: bool, sanitize: bool) -> String {
    let name = if backslash {
        name.replace('\\', "/")
    } else {
        name.to_string()
    };
    if !sanitize {
        return name;
    }
    let is_dir = name.ends_with('/');
    let mut rest = name.as_str();
    // A drive: a letter and a colon.
    let bytes = rest.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        rest = &rest[2..];
    }
    let components: Vec<&str> = rest
        .split('/')
        .filter(|c| !c.is_empty() && *c != "." && *c != "..")
        .collect();
    let mut cleaned = components.join("/");
    if is_dir && !cleaned.is_empty() {
        cleaned.push('/');
    }
    cleaned
}

/// Where a symbolic link at `parent` (its directory, under the
/// destination) leads, as components under the destination: its target
/// must be relative, with `/` its only separator, components that pass
/// [`check_name`] besides `.` and `..`, and must not climb out of the
/// destination. The path is resolved by its text, which is how the system
/// resolves it as long as no component on the way is itself a link.
pub(crate) fn link_target(target: &[u8], parent: &[String]) -> Result<Vec<String>, NameError> {
    if target.is_empty() {
        return Err(NameError::Empty);
    }
    let text = std::str::from_utf8(target).map_err(|_| NameError::NotUtf8)?;
    if text.chars().any(|c| c.is_ascii_control()) {
        return Err(NameError::Control);
    }
    if text.contains('\\') {
        return Err(NameError::Backslash);
    }
    if text.starts_with('/') {
        return Err(NameError::Absolute);
    }
    if text.contains(':') {
        return Err(NameError::Colon);
    }
    if text.contains(RESERVED) {
        return Err(NameError::Reserved);
    }
    let mut resolved = parent.to_vec();
    for component in text.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if resolved.pop().is_none() {
                    return Err(NameError::Dot);
                }
            }
            _ => {
                let name = check_name(component.as_bytes())?;
                resolved.extend(name.components);
            }
        }
    }
    Ok(resolved)
}

/// The first link the system would follow on the way along a target that
/// [`link_target`] took, if `link_at` knows one. Each place is looked at as it
/// is reached, before a `..` takes it back off: `a/up/../x` reads as `a/x`, but
/// where `a/up` is a link to `..`, the system goes to the destination, and then
/// out of it.
pub(crate) fn link_on_the_way(
    target: &[u8],
    parent: &[String],
    link_at: impl Fn(&[String]) -> Option<u64>,
) -> Option<u64> {
    let text = std::str::from_utf8(target).ok()?;
    let mut walked = parent.to_vec();
    for component in text.split('/').filter(|c| !matches!(*c, "" | ".")) {
        if !walked.is_empty()
            && let Some(other) = link_at(&walked)
        {
            return Some(other);
        }
        if component == ".." {
            walked.pop();
        } else if let Ok(name) = check_name(component.as_bytes()) {
            walked.extend(name.components);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_names_pass() {
        assert_eq!(
            check_name(b"a/b c/d.txt"),
            Ok(Name {
                components: vec!["a".into(), "b c".into(), "d.txt".into()],
                is_dir: false
            })
        );
        assert_eq!(
            check_name("dir/naïve/".as_bytes()),
            Ok(Name {
                components: vec!["dir".into(), "naïve".into()],
                is_dir: true
            })
        );
        for ok in [
            "CONSOLE",
            "com10",
            "LPT",
            "nul2.txt",
            ".hidden",
            "a..b",
            "COM",
            "auxiliary",
            "naïve",
            "é",
            "日本語.txt",
        ] {
            assert!(check_name(ok.as_bytes()).is_ok(), "{ok}");
        }
    }

    #[test]
    fn unportable_names_are_refused() {
        let cases: &[(&[u8], NameError)] = &[
            (b"", NameError::Empty),
            (b"a//b", NameError::Empty),
            (b"/", NameError::Absolute),
            (b"\xff", NameError::NotUtf8),
            (b"a\0b", NameError::Control),
            (b"a\x1fb", NameError::Control),
            (b"a\x7f", NameError::Control),
            (b"a\\b", NameError::Backslash),
            (b"\\\\?\\C:\\x", NameError::Backslash),
            (b"/etc/passwd", NameError::Absolute),
            (b"//server/share", NameError::Absolute),
            (b"C:x", NameError::Colon),
            (b"file.txt:stream", NameError::Colon),
            (b"a<b", NameError::Reserved),
            (b"a>b", NameError::Reserved),
            (b"a\"b", NameError::Reserved),
            (b"dir/a|b", NameError::Reserved),
            (b"what?", NameError::Reserved),
            (b"*.txt", NameError::Reserved),
            (b"../x", NameError::Dot),
            (b"a/../b", NameError::Dot),
            (b"./a", NameError::Dot),
            (b"a/.", NameError::Dot),
            (b"CON", NameError::Device),
            (b"con.txt", NameError::Device),
            (b"dir/Nul.tar.gz", NameError::Device),
            (b"NUL .txt", NameError::Device),
            (b"COM1", NameError::Device),
            (b"lpt9.log", NameError::Device),
            ("COM¹".as_bytes(), NameError::Device),
            ("lpt³.x".as_bytes(), NameError::Device),
            (b"CONIN$", NameError::Device),
            (b"conout$.txt", NameError::Device),
            (b"a /b", NameError::TrailingSpaceOrDot),
            (b"a./b", NameError::TrailingSpaceOrDot),
            (b"file.", NameError::TrailingSpaceOrDot),
        ];
        for &(raw, error) in cases {
            assert_eq!(
                check_name(raw),
                Err(error),
                "{}",
                String::from_utf8_lossy(raw)
            );
        }
        let long = "x".repeat(MAX_COMPONENT + 1);
        assert_eq!(check_name(long.as_bytes()), Err(NameError::TooLong));
        assert!(check_name("x".repeat(MAX_COMPONENT).as_bytes()).is_ok());
    }

    #[test]
    fn names_are_prepared_as_asked() {
        assert_eq!(prepare("a\\b\\c", true, false), "a/b/c");
        assert_eq!(prepare("a\\b", false, false), "a\\b");
        assert_eq!(prepare("/etc/passwd", false, true), "etc/passwd");
        assert_eq!(prepare("C:\\x\\..\\y", true, true), "x/y");
        assert_eq!(prepare("a/./b//../c/", false, true), "a/b/c/");
        assert_eq!(prepare("../../", false, true), "");
        // A drive is a letter and a colon, as Windows reads it.
        assert_eq!(prepare("a:b", false, true), "b");
        assert_eq!(prepare("ab:c", false, true), "ab:c");
    }

    #[test]
    fn link_targets_stay_inside() {
        let parent = vec!["a".to_string(), "b".to_string()];
        assert_eq!(
            link_target(b"c", &parent),
            Ok(vec!["a".into(), "b".into(), "c".into()])
        );
        assert_eq!(
            link_target(b"../c", &parent),
            Ok(vec!["a".into(), "c".into()])
        );
        assert_eq!(
            link_target(b"../../c/./d", &parent),
            Ok(vec!["c".into(), "d".into()])
        );
        assert_eq!(link_target(b"../..", &parent), Ok(vec![]));
        assert_eq!(link_target(b"../../../c", &parent), Err(NameError::Dot));
        assert_eq!(
            link_target(b"/etc/passwd", &parent),
            Err(NameError::Absolute)
        );
        assert_eq!(link_target(b"C:/x", &parent), Err(NameError::Colon));
        assert_eq!(link_target(b"..\\x", &parent), Err(NameError::Backslash));
        assert_eq!(link_target(b"nul", &parent), Err(NameError::Device));
        assert_eq!(link_target(b"", &parent), Err(NameError::Empty));
    }

    #[test]
    fn links_on_the_way_are_found_before_a_climb_hides_them() {
        let link_at = |walked: &[String]| (walked == ["a", "up"]).then_some(7);
        let way = |target: &[u8]| link_on_the_way(target, &[], link_at);
        assert_eq!(way(b"a/up/x"), Some(7));
        assert_eq!(way(b"a/up/../x"), Some(7));
        assert_eq!(way(b"a/./up//../../../x"), Some(7));
        // At the end, the system goes no further than the link.
        assert_eq!(way(b"a/up"), None);
        assert_eq!(way(b"a/x/../y"), None);
        // From the link's own directory.
        let parent = vec!["a".to_string()];
        assert_eq!(link_on_the_way(b"up/../x", &parent, link_at), Some(7));
        assert_eq!(link_on_the_way(b"../a/up/x", &parent, link_at), Some(7));
    }

    /// Names are the archive's: any bytes are checked without panicking.
    #[test]
    fn any_bytes_are_checked() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let alphabet = "a./\\:\0 éC¹ON\u{1}".as_bytes();
        for _ in 0..20_000 {
            let mut raw = Vec::new();
            for _ in 0..(x % 12) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                raw.push(if x.is_multiple_of(3) {
                    x as u8
                } else {
                    alphabet[(x >> 8) as usize % alphabet.len()]
                });
            }
            if let Ok(name) = check_name(&raw) {
                assert!(!name.components.is_empty());
            }
        }
    }
}
