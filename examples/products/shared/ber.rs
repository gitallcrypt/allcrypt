//! BER to DER, as far as PKCS#12 and CMS need it.
//!
//! A `.p12` from Windows, from older Java or from NSS is BER, and so is
//! much CMS - anything written as a stream: lengths left indefinite and
//! closed by an end-of-contents marker, and OCTET STRINGs broken into
//! constructed pieces. The library's ASN.1 reader is DER only, on
//! purpose, so this rewrites BER into DER first: every length definite
//! and minimal, every constructed string of a universal primitive type
//! joined into one. Nothing else BER allows - a non-minimal length, a
//! constructed BIT STRING - turns up in these files. An implicitly
//! tagged string, such as CMS's `encryptedContent [0]`, keeps its
//! pieces: only its reader knows it is a string.
//!
//! A PKCS#12 MAC is over the content of the authenticated-safe OCTET
//! STRING, and a CMS message digest over the content of `eContent`;
//! joining the pieces is exactly what the specifications say that
//! content is, so what is computed over the rewritten DER is what the
//! writer computed.

/// One element: its tag bytes, and either primitive content or children.
fn element(data: &[u8], at: &mut usize, depth: usize, out: &mut Vec<u8>) -> Result<(), String> {
    if depth > 64 {
        return Err("BER: nested more than 64 deep.".to_string());
    }
    let start = *at;
    let first = *data.get(*at).ok_or("BER: truncated.")?;
    *at += 1;
    if first & 0x1f == 0x1f {
        // A high tag number: base-128 bytes, the last without the top bit.
        loop {
            let b = *data.get(*at).ok_or("BER: truncated tag.")?;
            *at += 1;
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    let tag = data[start..*at].to_vec();
    let constructed = first & 0x20 != 0;
    let length_byte = *data.get(*at).ok_or("BER: truncated length.")?;
    *at += 1;
    let length = if length_byte == 0x80 {
        None
    } else if length_byte & 0x80 == 0 {
        Some(usize::from(length_byte))
    } else {
        let n = usize::from(length_byte & 0x7f);
        if n > 4 {
            return Err("BER: a length of more than four bytes.".to_string());
        }
        let bytes = data.get(*at..*at + n).ok_or("BER: truncated length.")?;
        *at += n;
        Some(bytes.iter().fold(0usize, |acc, &b| (acc << 8) | usize::from(b)))
    };
    if !constructed {
        let n = length.ok_or("BER: an indefinite length on a primitive.")?;
        let content = data.get(*at..*at + n).ok_or("BER: content runs past the end.")?;
        *at += n;
        write_tlv(&tag, content, out);
        return Ok(());
    }
    // The children, rewritten; a string type built from pieces becomes
    // one primitive string.
    let mut children = Vec::new();
    match length {
        Some(n) => {
            let end = at.checked_add(n).filter(|&e| e <= data.len())
                .ok_or("BER: content runs past the end.")?;
            while *at < end {
                element(data, at, depth + 1, &mut children)?;
            }
            if *at != end {
                return Err("BER: an element runs past its parent.".to_string());
            }
        }
        None => loop {
            if data.get(*at..*at + 2) == Some(&[0, 0]) {
                *at += 2;
                break;
            }
            if *at >= data.len() {
                return Err("BER: an indefinite length with no end-of-contents.".to_string());
            }
            element(data, at, depth + 1, &mut children)?;
        },
    }
    // OCTET STRING, UTF8String, BMPString and the other universal string
    // and time types: number 4, 12, or 18 to 30, in the universal class.
    // (16 and 17, between them, are SEQUENCE and SET.)
    let number = first & 0x1f;
    let is_string = first & 0xc0 == 0
        && (number == 4 || number == 12 || (18..=30).contains(&number));
    if is_string {
        let mut joined = Vec::new();
        let mut inner = 0;
        while inner < children.len() {
            let (content, next) = der_content(&children, inner)?;
            joined.extend_from_slice(content);
            inner = next;
        }
        write_tlv(&[first & !0x20], &joined, out);
    } else {
        write_tlv(&tag, &children, out);
    }
    Ok(())
}

/// The content of the DER element at `at`, and where the next begins.
fn der_content(data: &[u8], at: usize) -> Result<(&[u8], usize), String> {
    let first = *data.get(at + 1).ok_or("DER: truncated.")?;
    let (n, header) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let k = usize::from(first & 0x7f);
        let bytes = data.get(at + 2..at + 2 + k).ok_or("DER: truncated.")?;
        (bytes.iter().fold(0usize, |acc, &b| (acc << 8) | usize::from(b)), 2 + k)
    };
    let content = data.get(at + header..at + header + n).ok_or("DER: truncated.")?;
    Ok((content, at + header + n))
}

fn write_tlv(tag: &[u8], content: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(tag);
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes: Vec<u8> = n.to_be_bytes().into_iter().skip_while(|&b| b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(content);
}

/// The DER form of one BER element, which must be all of `data`.
pub fn to_der(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len());
    let mut at = 0;
    element(data, &mut at, 0, &mut out)?;
    if at != data.len() {
        return Err("BER: data after the element.".to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An indefinite SEQUENCE holding a constructed OCTET STRING in two
    /// pieces, one of them itself indefinite, becomes the DER a direct
    /// writer would have produced.
    #[test]
    fn test_indefinite_lengths_and_string_pieces() {
        let ber = [0x30, 0x80,
                   0x24, 0x80, 0x04, 0x02, 0xaa, 0xbb, 0x24, 0x80, 0x04, 0x01, 0xcc, 0x00, 0x00,
                   0x00, 0x00,
                   0x02, 0x01, 0x05,
                   0x00, 0x00];
        assert_eq!(to_der(&ber).unwrap(),
                   [0x30, 0x08, 0x04, 0x03, 0xaa, 0xbb, 0xcc, 0x02, 0x01, 0x05]);
    }

    /// DER is left as it is, long lengths included.
    #[test]
    fn test_der_is_unchanged() {
        let mut der = vec![0x30, 0x82, 0x01, 0x04, 0x04, 0x82, 0x01, 0x00];
        der.extend(std::iter::repeat_n(0x5a, 256));
        assert_eq!(to_der(&der).unwrap(), der);
    }

    #[test]
    fn test_malformed_ber_is_refused() {
        for bad in [&[0x30, 0x80, 0x02, 0x01, 0x05][..], &[0x04, 0x80, 0x00, 0x00],
                    &[0x30, 0x03, 0x02, 0x02, 0x05], &[0x30, 0x00, 0x00]] {
            assert!(to_der(bad).is_err(), "{bad:02x?}");
        }
    }
}
