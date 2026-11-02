//! Base64 (RFC 4648), strictly: one spelling for each value, as what is signed is
//! not what is read here, and no other text should pass for a signature.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn value(c: u8) -> Option<u32> {
    ALPHABET.iter().position(|&a| a == c).map(|v| v as u32)
}

/// `data` with padding.
pub(crate) fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let mut group = [0u8; 3];
        group[..chunk.len()].copy_from_slice(chunk);
        let bits = u32::from_be_bytes([0, group[0], group[1], group[2]]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(bits >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The bytes of padded text, or `None` for anything else, bits left over in the
/// last group included.
pub(crate) fn decode(text: &[u8]) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let groups = text.len() / 4;
    for (index, group) in text.chunks(4).enumerate() {
        let padding = match group {
            [_, _, b'=', b'='] => 2,
            [_, _, _, b'='] => 1,
            _ => 0,
        };
        if padding > 0 && index + 1 != groups {
            return None;
        }
        let mut bits = 0u32;
        for &c in &group[..4 - padding] {
            bits = bits << 6 | value(c)?;
        }
        bits <<= 6 * padding;
        if bits & ((1 << (8 * padding)) - 1) != 0 {
            return None;
        }
        out.extend_from_slice(&bits.to_be_bytes()[1..4 - padding]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4648_vectors() {
        for (plain, text) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), text);
            assert_eq!(decode(text.as_bytes()).as_deref(), Some(plain.as_bytes()));
        }
    }

    #[test]
    fn one_spelling_only() {
        for text in [
            "Zh==", "Zm9=", "Zg=", "Zg", "Z===", "====", "Zg==Zm9v", "Zm9 ", "Zm=v",
        ] {
            assert_eq!(decode(text.as_bytes()), None, "{text}");
        }
    }
}
