//! The suffix array of a text, as the dictionary builder sorts its samples
//! (`divsufsort`, which zstd-safe does not offer to compare with; the
//! oracle's tests compare it with libzstd's): a permutation of the text's
//! positions, each suffix smaller than the next. The first byte picks the
//! text from the rest of the input, so that the long repeats the sort
//! treats apart come easily:
//! - the rest, as it is;
//! - the rest repeated, as many times as the second byte says, plus one;
//! - the rest twice over, with the second byte's value between;
//! - the rest as pairs of a byte and the length of its run.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// The text the input stands for.
fn text(data: &[u8]) -> Vec<u8> {
    let Some((&pick, rest)) = data.split_first() else {
        return Vec::new();
    };
    match pick % 4 {
        0 => rest.to_vec(),
        1 => {
            let Some((&times, unit)) = rest.split_first() else {
                return Vec::new();
            };
            unit.repeat(usize::from(times) + 1)
        }
        2 => {
            let Some((&between, half)) = rest.split_first() else {
                return Vec::new();
            };
            let mut text = half.to_vec();
            text.push(between);
            text.extend_from_slice(half);
            text
        }
        _ => rest
            .chunks_exact(2)
            .flat_map(|pair| std::iter::repeat_n(pair[0], usize::from(pair[1]) + 1))
            .collect(),
    }
}

fuzz_target!(|data: &[u8]| {
    let text = text(data);
    let n = text.len();
    let mut sa = vec![0i32; n];
    hivepack::zstd::divsufsort(&text, &mut sa).expect("a text of any bytes is sorted");

    // A permutation: each position once.
    let mut rank = vec![usize::MAX; n];
    for (k, &s) in sa.iter().enumerate() {
        let s = usize::try_from(s).expect("a position");
        assert!(s < n, "position {s} past the text");
        assert_eq!(rank[s], usize::MAX, "position {s} twice");
        rank[s] = k;
    }
    // Sorted: each suffix smaller than the next, by its first byte or, that
    // byte equal, by the ranks of the suffixes after them (the empty one
    // first).
    let after = |s: usize| if s + 1 == n { 0 } else { rank[s + 1] + 1 };
    for pair in sa.windows(2) {
        let (a, b) = (pair[0] as usize, pair[1] as usize);
        assert!(
            text[a] < text[b] || (text[a] == text[b] && after(a) < after(b)),
            "suffixes {a} and {b} out of order"
        );
    }
    // For short texts, against the suffixes sorted as slices too.
    if n <= 512 {
        let mut naive: Vec<i32> = (0..n as i32).collect();
        naive.sort_by(|&a, &b| text[a as usize..].cmp(&text[b as usize..]));
        assert_eq!(sa, naive);
    }
});
