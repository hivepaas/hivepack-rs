//! The names an entry may have: what is refused, rather than cleaned up.
//! What would lead outside the destination (`..`, a leading `/`) is refused
//! everywhere; what a system cannot name (`a:b` on Windows) is refused as
//! [`NameRules`] says, by this system's rules or by every system's, and can be
//! renamed ([`Options::on_unnamable`](crate::extract::Options::on_unnamable)).
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

impl NameError {
    /// Whether the name is one the system cannot take, or might not show for what
    /// it is, rather than one that leads outside the destination or names
    /// nothing: it can be left out, or renamed, and the rest extracted. Not
    /// [`NameError::Empty`], [`NameError::Absolute`] or [`NameError::Dot`].
    pub fn is_unnamable(self) -> bool {
        !matches!(
            self,
            NameError::Empty | NameError::Absolute | NameError::Dot
        )
    }
}

/// Which systems' rules a name keeps to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameRules {
    /// This system's (the default): Windows' characters, device names and ends
    /// of names on Windows only, so that `a:b` and `aux.txt` extract on Linux and
    /// macOS; and two names that differ only in case, or in how their Unicode is
    /// composed, are the same path only where the destination's file system takes
    /// them for one, as it is found to before anything is written: on Windows and
    /// macOS by default, a USB stick in exFAT on Linux too, and never in a
    /// [`Sink`](crate::extract::Sink), whose archive can hold both. Into a
    /// sink, only what leads outside on any system (`..`, `\\` and `:` taken to
    /// split a name as Windows takes them, `/`, `\\` or a drive at its start) and
    /// control characters are refused: the archive it makes holds any other
    /// name, on every system.
    #[default]
    Native,
    /// Every system's, wherever it runs, as [`check_name`] has them: what extracts
    /// here extracts anywhere, the same.
    Portable,
}

impl NameRules {
    /// Whether Windows' rules apply.
    pub(crate) fn windows(self) -> bool {
        cfg!(windows) || self == NameRules::Portable
    }
}

/// What a name is checked for: by [`NameRules`], for a folder; or, for an
/// archive a [`Sink`](crate::extract::Sink) makes, only for what leads outside
/// on any system and for control characters, as the archive holds any other
/// name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Checks {
    Folder(NameRules),
    Archive,
}

impl Checks {
    /// Whether what Windows cannot name is refused.
    fn windows(self) -> bool {
        matches!(self, Checks::Folder(rules) if rules.windows())
    }

    /// Whether `\` and `:` split a name, as Windows takes them, to find what
    /// climbs.
    fn splits(self) -> bool {
        match self {
            Checks::Folder(rules) => rules.windows(),
            Checks::Archive => true,
        }
    }
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
/// separator, by every system's rules ([`NameRules::Portable`]): [`Name`], or
/// why it is refused.
pub fn check_name(raw: &[u8]) -> Result<Name, NameError> {
    check_name_for(raw, NameRules::Portable)
}

/// Checks `raw` as [`check_name`] does, by the rules `rules` says. What leads
/// outside the destination, or names nothing, is said before what a system
/// cannot name: a name refused as [`NameError::is_unnamable`] has neither.
pub fn check_name_for(raw: &[u8], rules: NameRules) -> Result<Name, NameError> {
    check(raw, Checks::Folder(rules))
}

/// Checks `raw` for what `checks` say.
pub(crate) fn check(raw: &[u8], checks: Checks) -> Result<Name, NameError> {
    if raw.is_empty() {
        return Err(NameError::Empty);
    }
    let name = std::str::from_utf8(raw).map_err(|_| NameError::NotUtf8)?;
    if name.starts_with('/') {
        return Err(NameError::Absolute);
    }
    // Where Windows extracts the archive made, `\x` and `C:x` lead outside.
    if checks == Checks::Archive && (name.starts_with('\\') || has_drive(name)) {
        return Err(NameError::Absolute);
    }
    let windows = checks.windows();
    let splits = checks.splits();
    let (path, is_dir) = match name.strip_suffix('/') {
        Some(path) => (path, true),
        None => (name, false),
    };
    let parts: Vec<&str> = path.split('/').collect();
    // On Windows a `\` separates too, and a drive leads outside: `..\x`, `C:x`.
    let pieces = |part: &&str| -> Vec<String> {
        if splits {
            part.split(['\\', ':']).map(str::to_owned).collect()
        } else {
            vec![(*part).to_owned()]
        }
    };
    for piece in parts.iter().flat_map(pieces) {
        if piece == "." || piece == ".." {
            return Err(NameError::Dot);
        }
    }
    if parts.iter().any(|part| part.is_empty()) {
        return Err(NameError::Empty);
    }
    if name.chars().any(|c| c.is_ascii_control()) {
        return Err(NameError::Control);
    }
    if windows && name.contains('\\') {
        return Err(NameError::Backslash);
    }
    if windows && name.contains(':') {
        return Err(NameError::Colon);
    }
    if windows && name.contains(RESERVED) {
        return Err(NameError::Reserved);
    }
    let mut components = Vec::new();
    for component in parts {
        if checks != Checks::Archive && component.len() > MAX_COMPONENT {
            return Err(NameError::TooLong);
        }
        if windows && (component.ends_with(' ') || component.ends_with('.')) {
            return Err(NameError::TrailingSpaceOrDot);
        }
        if windows && is_device(component) {
            return Err(NameError::Device);
        }
        components.push(component.to_string());
    }
    Ok(Name { components, is_dir })
}

/// A name for `text`, which `rules` refuse as [`NameError::is_unnamable`], that
/// they take: what cannot be in a name made `_` (a control character, and by
/// Windows' rules `\ : < > " | ? *` and a space or dot at a name's end), a device
/// name given a `_` before it, and a part too long cut down, its extension kept.
/// It is checked again: none if it still does not pass.
pub(crate) fn renamed(text: &str, checks: Checks) -> Option<Name> {
    let windows = checks.windows();
    let (path, is_dir) = match text.strip_suffix('/') {
        Some(path) => (path, true),
        None => (text, false),
    };
    // What leads outside, or names nothing, is never made into a name.
    if path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return None;
    }
    let fixed: Vec<String> = path
        .split('/')
        .map(|part| {
            let mut fixed: String = part
                .chars()
                .map(|c| {
                    let banned = c.is_control()
                        || (windows && (c == '\\' || c == ':' || RESERVED.contains(&c)));
                    if banned { '_' } else { c }
                })
                .collect();
            if windows {
                let kept = fixed.trim_end_matches([' ', '.']).len();
                if kept < fixed.len() {
                    let cut = fixed.len() - kept;
                    fixed.truncate(kept);
                    fixed.push_str(&"_".repeat(cut));
                }
                if is_device(&fixed) {
                    fixed.insert(0, '_');
                }
            }
            shortened(&fixed)
        })
        .collect();
    let mut joined = fixed.join("/");
    if is_dir {
        joined.push('/');
    }
    check(joined.as_bytes(), checks).ok()
}

/// Whether `name` starts with a drive, a letter and a colon.
fn has_drive(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// `part`, cut down to [`MAX_COMPONENT`] bytes if it is longer: its extension (a
/// short one) kept, its stem cut where a character ends.
fn shortened(part: &str) -> String {
    if part.len() <= MAX_COMPONENT {
        return part.to_owned();
    }
    let extension = part
        .rfind('.')
        .map(|dot| &part[dot..])
        .filter(|ext| ext.len() <= 32)
        .unwrap_or("");
    let stem = &part[..part.len() - extension.len()];
    let mut end = MAX_COMPONENT - extension.len();
    while !stem.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{extension}", &stem[..end])
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

/// A symbolic link's target as text, if it is a path at all, wherever it leads:
/// not empty, UTF-8, and without a control character.
pub(crate) fn link_text(target: &[u8]) -> Result<String, NameError> {
    if target.is_empty() {
        return Err(NameError::Empty);
    }
    let text = std::str::from_utf8(target).map_err(|_| NameError::NotUtf8)?;
    if text.chars().any(|c| c.is_ascii_control()) {
        return Err(NameError::Control);
    }
    Ok(text.to_owned())
}

/// Where a symbolic link at `parent` (its directory, under the
/// destination) leads, as components under the destination: its target
/// must be relative, with `/` its only separator, components that pass
/// [`check_name`] besides `.` and `..`, and must not climb out of the
/// destination. The path is resolved by its text, which is how the system
/// resolves it as long as no component on the way is itself a link.
pub(crate) fn link_target(
    target: &[u8],
    parent: &[String],
    checks: Checks,
) -> Result<Vec<String>, NameError> {
    let text = link_text(target)?;
    let text = text.as_str();
    // Windows' separator and drive, wherever the link is followed from.
    if text.contains('\\') {
        return Err(NameError::Backslash);
    }
    if text.starts_with('/') {
        return Err(NameError::Absolute);
    }
    if checks.windows() && text.contains(':') {
        return Err(NameError::Colon);
    }
    if checks.windows() && text.contains(RESERVED) {
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
                let name = check(component.as_bytes(), checks)?;
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
        } else {
            // What link_target took first: each part a name.
            walked.push(component.to_owned());
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
            link_target(b"c", &parent, Checks::Folder(NameRules::Portable)),
            Ok(vec!["a".into(), "b".into(), "c".into()])
        );
        assert_eq!(
            link_target(b"../c", &parent, Checks::Folder(NameRules::Portable)),
            Ok(vec!["a".into(), "c".into()])
        );
        assert_eq!(
            link_target(b"../../c/./d", &parent, Checks::Folder(NameRules::Portable)),
            Ok(vec!["c".into(), "d".into()])
        );
        assert_eq!(
            link_target(b"../..", &parent, Checks::Folder(NameRules::Portable)),
            Ok(vec![])
        );
        assert_eq!(
            link_target(b"../../../c", &parent, Checks::Folder(NameRules::Portable)),
            Err(NameError::Dot)
        );
        assert_eq!(
            link_target(b"/etc/passwd", &parent, Checks::Folder(NameRules::Portable)),
            Err(NameError::Absolute)
        );
        assert_eq!(
            link_target(b"C:/x", &parent, Checks::Folder(NameRules::Portable)),
            Err(NameError::Colon)
        );
        assert_eq!(
            link_target(b"..\\x", &parent, Checks::Folder(NameRules::Portable)),
            Err(NameError::Backslash)
        );
        assert_eq!(
            link_target(b"nul", &parent, Checks::Folder(NameRules::Portable)),
            Err(NameError::Device)
        );
        assert_eq!(
            link_target(b"", &parent, Checks::Folder(NameRules::Portable)),
            Err(NameError::Empty)
        );
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
    fn a_name_renamed_is_one_the_rules_take() {
        let portable = Checks::Folder(NameRules::Portable);
        let renamed_as = |text: &str| renamed(text, portable).map(|n| n.components.join("/"));
        assert_eq!(renamed_as("dir/a:b?.txt").as_deref(), Some("dir/a_b_.txt"));
        assert_eq!(renamed_as("con.txt").as_deref(), Some("_con.txt"));
        assert_eq!(renamed_as("tab\there. ").as_deref(), Some("tab_here__"));
        assert_eq!(renamed_as("back\\slash").as_deref(), Some("back_slash"));
        let long = format!("{}.pdf", "ệ".repeat(100));
        let short = renamed_as(&long).unwrap();
        assert!(
            short.len() <= MAX_COMPONENT && short.ends_with("ệ.pdf"),
            "{short}"
        );
        // What climbs is not made to take.
        assert_eq!(renamed_as("../x"), None);
    }

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
