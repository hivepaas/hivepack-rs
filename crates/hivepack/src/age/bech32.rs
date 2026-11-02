//! Bech32 (BIP 173), in which age writes its keys: port of
//! `internal/bech32/bech32.go`. Like age's, it has no limit of 90
//! characters, as age's post-quantum keys are longer.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

fn polymod(values: &[u8]) -> u32 {
    let mut chk = 1u32;
    for &v in values {
        let top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5;
        chk ^= u32::from(v);
        for (i, &g) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let h = hrp.to_ascii_lowercase().into_bytes();
    let mut ret: Vec<u8> = h.iter().map(|c| c >> 5).collect();
    ret.push(0);
    ret.extend(h.iter().map(|c| c & 31));
    ret
}

fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    polymod(&values) == 1
}

fn create_checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0; 6]);
    let m = polymod(&values) ^ 1;
    std::array::from_fn(|p| ((m >> (5 * (5 - p))) & 31) as u8)
}

/// `convertBits`: groups of `frombits` bits into groups of `tobits`.
fn convert_bits(data: &[u8], frombits: u32, tobits: u32, pad: bool) -> Result<Vec<u8>, String> {
    let mut ret = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    let maxv = (1u32 << tobits) - 1;
    for (idx, &value) in data.iter().enumerate() {
        if u32::from(value) >> frombits != 0 {
            return Err(format!(
                "invalid data range: data[{idx}]={value} (frombits={frombits})"
            ));
        }
        acc = acc << frombits | u32::from(value);
        bits += frombits;
        while bits >= tobits {
            bits -= tobits;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            ret.push(((acc << (tobits - bits)) & maxv) as u8);
        }
    } else if bits >= frombits {
        return Err("illegal zero padding".into());
    } else if (acc << (tobits - bits)) & maxv != 0 {
        return Err("non-zero padding".into());
    }
    Ok(ret)
}

/// `Encode`: `data` under the human-readable part `hrp`, in its case.
pub(crate) fn encode(hrp: &str, data: &[u8]) -> Result<String, String> {
    let values = convert_bits(data, 8, 5, true)?;
    if hrp.is_empty() {
        return Err(format!("invalid HRP: {hrp:?}"));
    }
    if let Some((p, c)) = hrp
        .bytes()
        .enumerate()
        .find(|&(_, c)| !(33..=126).contains(&c))
    {
        return Err(format!("invalid HRP character: hrp[{p}]={c}"));
    }
    if hrp.to_ascii_uppercase() != hrp && hrp.to_ascii_lowercase() != hrp {
        return Err(format!("mixed case HRP: {hrp:?}"));
    }
    let lower = hrp.to_ascii_lowercase() == hrp;
    let hrp = hrp.to_ascii_lowercase();
    let mut ret = String::with_capacity(hrp.len() + 1 + values.len() + 6);
    ret.push_str(&hrp);
    ret.push('1');
    for &p in values.iter().chain(&create_checksum(&hrp, &values)) {
        ret.push(char::from(CHARSET[usize::from(p)]));
    }
    if lower {
        Ok(ret)
    } else {
        Ok(ret.to_ascii_uppercase())
    }
}

/// `Decode`: the human-readable part, as written, and the data.
pub(crate) fn decode(s: &str) -> Result<(String, Vec<u8>), String> {
    if s.to_lowercase() != s && s.to_uppercase() != s {
        return Err("mixed case".into());
    }
    let pos = s.rfind('1');
    let pos = match pos {
        Some(pos) if pos >= 1 && pos + 7 <= s.len() => pos,
        _ => {
            return Err(format!(
                "separator '1' at invalid position: pos={}, len={}",
                pos.map_or(-1, |p| p as i64),
                s.len()
            ));
        }
    };
    let hrp = &s[..pos];
    for (p, c) in hrp.char_indices() {
        if !(33..=126).contains(&u32::from(c)) {
            return Err(format!(
                "invalid character human-readable part: s[{p}]={}",
                u32::from(c)
            ));
        }
    }
    let mut data = Vec::with_capacity(s.len() - pos - 1);
    for (p, c) in s[pos + 1..].char_indices() {
        let c = c.to_ascii_lowercase();
        let Some(d) = CHARSET.iter().position(|&x| u32::from(x) == u32::from(c)) else {
            return Err(format!(
                "invalid character data part: s[{p}]={}",
                u32::from(c)
            ));
        };
        data.push(d as u8);
    }
    if data.len() < 6 {
        return Err("data part too short".into());
    }
    if !verify_checksum(hrp, &data) {
        return Err("invalid checksum".into());
    }
    let data = convert_bits(&data[..data.len() - 6], 5, 8, false)?;
    Ok((hrp.to_string(), data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip_173_valid_strings() {
        for s in [
            "A12UEL5L",
            "a12uel5l",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
            "?1ezyfcl",
        ] {
            assert!(decode(s).is_ok(), "{s}");
        }
    }

    #[test]
    fn bip_173_invalid_strings() {
        for s in [
            "pzry9x0s0muk",
            "1pzry9x0s0muk",
            "x1b4n0q5v",
            "li1dgmt3",
            "A1G7SGD8",
            "10a06t8",
            "1qzzfhee",
            "a12UEL5L",
        ] {
            assert!(decode(s).is_err(), "{s}");
        }
    }

    #[test]
    fn round_trips_with_case() {
        let data: Vec<u8> = (0..32).collect();
        for hrp in ["age", "AGE-SECRET-KEY-"] {
            let s = encode(hrp, &data).unwrap();
            assert_eq!(decode(&s).unwrap(), (hrp.to_string(), data.clone()));
        }
    }
}
