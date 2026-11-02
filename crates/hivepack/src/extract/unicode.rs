//! Names as file systems compare them: case folded and canonically
//! decomposed, with the tables of one Unicode version (made by
//! `scripts/unicode.py`), the same on every system. So `é` written as one
//! character and as `e` with a combining accent are one name, as macOS
//! takes them, and so are the Kelvin sign and `K`, also one by
//! decomposition, `σ` and `ς`, as a case-insensitive file system takes
//! them, and `ß` and `ss`, or the ligature `ﬁ` and `fi`, as macOS folds
//! them.
//!
//! This is Unicode's canonical caseless match (definition D145): NFD of
//! the full case folding of NFD(name). Composing again (NFC) is not needed
//! to compare. Compatibility forms that do not fold stay apart: the
//! fullwidth `Ａ` is not `A`.

mod tables;

pub use tables::VERSION;

// Hangul syllables decompose by computation (Unicode, section 3.12).
const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const V_COUNT: u32 = 21;
const T_COUNT: u32 = 28;
const N_COUNT: u32 = V_COUNT * T_COUNT;
const S_COUNT: u32 = 19 * N_COUNT;

/// The canonical combining class of `c`.
pub(crate) fn combining_class(c: char) -> u8 {
    let found = tables::COMBINING.binary_search_by(|&(first, last, _)| {
        if last < c {
            std::cmp::Ordering::Less
        } else if first > c {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    });
    match found {
        Ok(i) => tables::COMBINING[i].2,
        Err(_) => 0,
    }
}

/// Appends the full canonical decomposition of `c` to `out`.
fn decompose(c: char, out: &mut Vec<char>) {
    let s = u32::from(c).wrapping_sub(S_BASE);
    if s < S_COUNT {
        // Jamo, valid characters by construction.
        out.extend(char::from_u32(L_BASE + s / N_COUNT));
        out.extend(char::from_u32(V_BASE + s % N_COUNT / T_COUNT));
        if s % T_COUNT != 0 {
            out.extend(char::from_u32(T_BASE + s % T_COUNT));
        }
        return;
    }
    match tables::DECOMPOSITIONS.binary_search_by_key(&c, |&(c, _)| c) {
        Ok(i) => out.extend_from_slice(tables::DECOMPOSITIONS[i].1),
        Err(_) => out.push(c),
    }
}

/// Appends the full case folding of `c` to `out`.
fn fold(c: char, out: &mut Vec<char>) {
    match tables::FOLDING.binary_search_by_key(&c, |&(c, _)| c) {
        Ok(i) => out.extend_from_slice(tables::FOLDING[i].1),
        Err(_) => out.push(c),
    }
}

/// The canonical decomposition of `chars` (NFD): each decomposed, then
/// each run of combining marks put in the order of their classes, those
/// of one class kept as they came.
fn nfd_chars(chars: impl Iterator<Item = char>) -> Vec<char> {
    let mut out = Vec::new();
    for c in chars {
        decompose(c, &mut out);
    }
    let mut start = 0;
    while start < out.len() {
        let end = out[start..]
            .iter()
            .position(|&c| combining_class(c) == 0)
            .map_or(out.len(), |n| start + n);
        if end > start {
            out[start..end].sort_by_key(|&c| combining_class(c));
        }
        start = end + 1;
    }
    out
}

/// The canonical decomposition of `s` (NFD).
#[cfg(test)]
fn nfd(s: &str) -> String {
    nfd_chars(s.chars()).into_iter().collect()
}

/// `s` as names are compared: NFD(fold(NFD(s))). Two names with the same
/// key are one name to some file system.
pub(crate) fn key(s: &str) -> String {
    // ASCII has no decompositions or marks, and folds `A` to `Z` only.
    if s.is_ascii() {
        return s.to_ascii_lowercase();
    }
    full_key(s)
}

/// [`key`], the whole way.
fn full_key(s: &str) -> String {
    let mut folded = Vec::new();
    for c in nfd_chars(s.chars()) {
        fold(c, &mut folded);
    }
    nfd_chars(folded.into_iter()).into_iter().collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::path::{Path, PathBuf};

    #[test]
    fn names_that_are_one_name_have_one_key() {
        for (a, b) in [
            ("caf\u{e9}", "cafe\u{301}"),
            ("CAF\u{c9}", "cafe\u{301}"),
            // The Kelvin and Ångström signs, and final sigma.
            ("\u{212a}", "k"),
            ("\u{212b}", "a\u{30a}"),
            ("\u{3a3}\u{3c2}", "\u{3c3}\u{3c3}"),
            // İ is I with a dot above, which folds to i with it.
            ("\u{130}", "i\u{307}"),
            // Full case folding, as macOS's.
            ("stra\u{df}e", "strasse"),
            ("\u{fb01}", "fi"),
            ("\u{1e9e}", "ss"),
            // A Hangul syllable, and its jamo.
            ("\u{d55c}", "\u{1112}\u{1161}\u{11ab}"),
            // Marks of different classes, in either order.
            ("a\u{301}\u{323}", "a\u{323}\u{301}"),
        ] {
            assert_eq!(key(a), key(b), "{a:?} {b:?}");
        }
        for (a, b) in [
            // Compatibility forms that do not fold.
            ("\u{ff21}", "a"),
            ("\u{2460}", "1"),
            // Marks of one class keep their order.
            ("a\u{301}\u{300}", "a\u{300}\u{301}"),
        ] {
            assert_ne!(key(a), key(b), "{a:?} {b:?}");
        }
    }

    /// Where `scripts/testdata.py` puts what it fetches, and the Unicode
    /// database there, or `None` if it is not fetched (and that is
    /// allowed).
    fn database() -> Option<PathBuf> {
        let cache = std::env::var_os("HIVEPACK_TESTDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/testdata"));
        let (major, minor, update) = VERSION;
        let folder = cache.join(format!("unicode-{major}.{minor}.{update}"));
        if folder.join(".complete").exists() {
            return Some(folder);
        }
        let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
        assert!(
            !required.split(',').any(|g| g == "all" || g == "core"),
            "{} is missing: run `python3 scripts/testdata.py fetch`",
            folder.display()
        );
        eprintln!("skipping: the Unicode database is not fetched");
        None
    }

    fn chars(field: &str) -> Vec<char> {
        field
            .split_whitespace()
            .map(|cp| char::from_u32(u32::from_str_radix(cp, 16).unwrap()).unwrap())
            .collect()
    }

    fn all_chars() -> impl Iterator<Item = char> {
        (0..=0x10_ffff).filter_map(char::from_u32)
    }

    /// Unicode's own test: each line's five columns decompose as it says,
    /// and every character its first part does not list decomposes to
    /// itself.
    #[test]
    fn decomposition_passes_unicode_normalization_test() {
        let Some(folder) = database() else {
            return;
        };
        let text = std::fs::read_to_string(folder.join("NormalizationTest.txt")).unwrap();
        let mut part = "";
        let mut listed = HashSet::new();
        let mut lines = 0;
        for line in text.lines() {
            let line = line.split('#').next().unwrap().trim();
            if let Some(name) = line.strip_prefix('@') {
                part = name.split_whitespace().next().unwrap();
                continue;
            }
            if line.is_empty() {
                continue;
            }
            let c: Vec<String> = line
                .split(';')
                .take(5)
                .map(|field| chars(field).into_iter().collect())
                .collect();
            for (from, to) in [(0, 2), (1, 2), (2, 2), (3, 4), (4, 4)] {
                assert_eq!(nfd(&c[from]), c[to], "{line}: column {}", from + 1);
            }
            if part == "Part1" {
                listed.insert(c[0].chars().next().unwrap());
            }
            lines += 1;
        }
        assert!(lines > 20_000 && listed.len() > 10_000, "{lines} lines");
        for c in all_chars().filter(|c| !listed.contains(c)) {
            assert_eq!(nfd(&c.to_string()), c.to_string(), "U+{:04X}", u32::from(c));
        }
    }

    /// The tables hold what the database says, for every character: its
    /// combining class, its full decomposition, and its full case
    /// folding.
    #[test]
    fn tables_hold_the_database() {
        let Some(folder) = database() else {
            return;
        };
        let data = std::fs::read_to_string(folder.join("UnicodeData.txt")).unwrap();
        let mut classes = HashMap::new();
        let mut mappings = HashMap::new();
        for line in data.lines() {
            let fields: Vec<&str> = line.split(';').collect();
            // Surrogates are listed, and are not characters.
            let Some(c) = char::from_u32(u32::from_str_radix(fields[0], 16).unwrap()) else {
                continue;
            };
            classes.insert(c, fields[3].parse::<u8>().unwrap());
            if !fields[5].is_empty() && !fields[5].starts_with('<') {
                mappings.insert(c, chars(fields[5]));
            }
        }
        fn full(c: char, mappings: &HashMap<char, Vec<char>>, out: &mut Vec<char>) {
            match mappings.get(&c) {
                Some(parts) => parts.iter().for_each(|&p| full(p, mappings, out)),
                None => out.push(c),
            }
        }
        let folding_text = std::fs::read_to_string(folder.join("CaseFolding.txt")).unwrap();
        let mut folding = HashMap::new();
        for line in folding_text.lines() {
            let fields: Vec<&str> = line.split('#').next().unwrap().split(';').collect();
            if fields.len() >= 3 && matches!(fields[1].trim(), "C" | "F") {
                folding.insert(chars(fields[0])[0], chars(fields[2]));
            }
        }
        for c in all_chars() {
            let class = classes.get(&c).copied().unwrap_or(0);
            assert_eq!(combining_class(c), class, "U+{:04X}", u32::from(c));
            let mut folded = Vec::new();
            fold(c, &mut folded);
            let want = folding.get(&c).cloned().unwrap_or_else(|| vec![c]);
            assert_eq!(folded, want, "U+{:04X}", u32::from(c));
            let hangul = u32::from(c).wrapping_sub(S_BASE) < S_COUNT;
            if !hangul {
                let (mut want, mut got) = (Vec::new(), Vec::new());
                full(c, &mappings, &mut want);
                decompose(c, &mut got);
                assert_eq!(got, want, "U+{:04X}", u32::from(c));
            }
        }
    }

    #[test]
    fn ascii_takes_a_short_way() {
        for b in 0..128u8 {
            let s = char::from(b).to_string();
            assert_eq!(key(&s), full_key(&s), "{b}");
        }
        assert_eq!(key("Dir/File.TXT"), full_key("Dir/File.TXT"));
    }

    /// A key is its own key, for every character, and for every line of
    /// Unicode's test, whose canonically equivalent strings have one key.
    #[test]
    fn keys_are_stable() {
        for c in all_chars() {
            let k = key(&c.to_string());
            assert_eq!(key(&k), k, "U+{:04X}", u32::from(c));
        }
        let Some(folder) = database() else {
            return;
        };
        let text = std::fs::read_to_string(folder.join("NormalizationTest.txt")).unwrap();
        for line in text.lines().filter(|l| !l.starts_with(['#', '@'])) {
            let c: Vec<String> = line
                .split(';')
                .take(5)
                .map(|field| chars(field).into_iter().collect())
                .collect();
            let k = key(&c[0]);
            assert_eq!(key(&k), k, "{line}");
            // The first three columns are canonically equivalent, and so
            // are the last two: one name each.
            assert!(c[..3].iter().all(|s| key(s) == k), "{line}");
            let k = key(&c[3]);
            assert_eq!(key(&c[4]), k, "{line}");
        }
    }
}
