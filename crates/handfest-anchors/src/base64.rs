//! Strict RFC 4648 standard Base64 codec (zero external dependencies).
//!
//! Fails closed on non-alphabet bytes, whitespace, missing or misplaced `=` padding,
//! wrong lengths, and non-canonical trailing padding bits.

const ENCODE_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes arbitrary bytes into canonical RFC 4648 standard Base64 with `=` padding.
pub(crate) fn encode_standard(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }
    let out_len = input.len().div_ceil(3) * 4;
    let mut out = String::with_capacity(out_len);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        out.push(ENCODE_TABLE[(b0 >> 2) as usize] as char);
        out.push(ENCODE_TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);

        if chunk.len() > 1 {
            out.push(ENCODE_TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }

        if chunk.len() > 2 {
            out.push(ENCODE_TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Decodes strictly canonical RFC 4648 standard Base64 with `=` padding.
pub(crate) fn decode_standard(input: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.len().is_multiple_of(4) {
        return Err("base64 length must be a multiple of 4");
    }

    let (chunks, _rem) = bytes.as_chunks::<4>();
    let total_chunks = chunks.len();
    let mut out = Vec::with_capacity(total_chunks * 3);

    for (idx, chunk) in chunks.iter().enumerate() {
        let is_last = idx + 1 == total_chunks;
        decode_quad(chunk, is_last, &mut out)?;
    }

    Ok(out)
}

fn decode_quad(chunk: &[u8], is_last: bool, out: &mut Vec<u8>) -> Result<(), &'static str> {
    let v0 = decode_sextet(chunk[0])?;
    let v1 = decode_sextet(chunk[1])?;

    if chunk[2] == b'=' {
        if !is_last || chunk[3] != b'=' {
            return Err("invalid base64 padding");
        }
        if (v1 & 0x0f) != 0 {
            return Err("non-canonical base64 padding bits");
        }
        out.push((v0 << 2) | (v1 >> 4));
        return Ok(());
    }

    let v2 = decode_sextet(chunk[2])?;
    if chunk[3] == b'=' {
        if !is_last {
            return Err("invalid base64 padding");
        }
        if (v2 & 0x03) != 0 {
            return Err("non-canonical base64 padding bits");
        }
        out.push((v0 << 2) | (v1 >> 4));
        out.push((v1 << 4) | (v2 >> 2));
        return Ok(());
    }

    let v3 = decode_sextet(chunk[3])?;
    out.push((v0 << 2) | (v1 >> 4));
    out.push((v1 << 4) | (v2 >> 2));
    out.push((v2 << 6) | v3);
    Ok(())
}

fn decode_sextet(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err("invalid base64 character"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors_and_all_byte_values_round_trip() {
        let vectors: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (raw, expected) in vectors {
            assert_eq!(encode_standard(raw), expected);
            assert_eq!(decode_standard(expected), Ok(raw.to_vec()));
        }

        let all_bytes: Vec<u8> = (0u8..=255).collect();
        let encoded = encode_standard(&all_bytes);
        assert_eq!(decode_standard(&encoded), Ok(all_bytes));
    }

    #[test]
    fn decode_rejects_malformed_and_non_canonical_inputs() {
        assert_eq!(
            decode_standard("abc"),
            Err("base64 length must be a multiple of 4")
        );
        assert_eq!(decode_standard("===="), Err("invalid base64 character"));
        assert_eq!(decode_standard("A==="), Err("invalid base64 character"));
        assert_eq!(decode_standard("Zg=A"), Err("invalid base64 padding"));
        assert_eq!(decode_standard("Zg==AAAA"), Err("invalid base64 padding"));
        assert_eq!(decode_standard("Zm8=AAAA"), Err("invalid base64 padding"));
        // Non-canonical trailing bits: 'Zh==' sets low 4 bits of v1 to 1.
        assert_eq!(
            decode_standard("Zh=="),
            Err("non-canonical base64 padding bits")
        );
        // Non-canonical trailing bits: 'Zm9=' sets low 2 bits of v2 to 1.
        assert_eq!(
            decode_standard("Zm9="),
            Err("non-canonical base64 padding bits")
        );
        // Whitespace and URL-safe characters rejected.
        assert_eq!(decode_standard("Zm 9"), Err("invalid base64 character"));
        assert_eq!(decode_standard("Zm-9"), Err("invalid base64 character"));
        assert_eq!(decode_standard("Zm_9"), Err("invalid base64 character"));
        assert_eq!(decode_standard("Zm9\n"), Err("invalid base64 character"));
    }
}
