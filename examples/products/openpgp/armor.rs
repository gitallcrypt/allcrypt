//! ASCII armor (RFC 9580 section 6): base64 between `-----BEGIN PGP
//! ...-----` and `-----END PGP ...-----` lines, with optional `Key: Value`
//! headers and an optional CRC-24 line.

/// CRC-24 of RFC 9580 section 6.1.
pub fn crc24(data: &[u8]) -> u32 {
    let mut crc = 0xB7_04CEu32;
    for &byte in data {
        crc ^= u32::from(byte) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x100_0000 != 0 {
                crc ^= 0x186_4CFB;
            }
        }
    }
    crc & 0xFF_FFFF
}

/// One armored block: its label (`MESSAGE`, `PUBLIC KEY BLOCK`, ...),
/// its headers and its data.
pub struct Armored {
    pub label: String,
    pub headers: Vec<(String, String)>,
    pub data: Vec<u8>,
}

/// Whether `data` looks armored: its first non-blank line starts with
/// `-----BEGIN PGP `.
pub fn is_armored(data: &[u8]) -> bool {
    let start = data.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(data.len());
    data[start..].starts_with(b"-----BEGIN PGP ")
}

/// Every armored block in `text`, in order. A cleartext signed message's
/// `BEGIN PGP SIGNED MESSAGE` is not a block of this kind and is passed
/// over here (see `cleartext`).
pub fn decode_all(text: &str) -> Result<Vec<Armored>, String> {
    let mut blocks = Vec::new();
    let mut lines = text.lines().map(|l| l.trim());
    while let Some(line) = lines.next() {
        let Some(label) = line.strip_prefix("-----BEGIN PGP ")
            .and_then(|l| l.strip_suffix("-----")) else { continue };
        if label == "SIGNED MESSAGE" {
            continue;
        }
        let mut headers = Vec::new();
        let mut body = String::new();
        let mut crc = None;
        let mut in_headers = true;
        let mut ended = false;
        for line in lines.by_ref() {
            if line == format!("-----END PGP {label}-----") {
                ended = true;
                break;
            }
            if in_headers {
                if line.trim().is_empty() {
                    in_headers = false;
                    continue;
                }
                if let Some((key, value)) = line.split_once(": ") {
                    if !key.is_empty() && !key.contains(' ') {
                        headers.push((key.to_string(), value.to_string()));
                        continue;
                    }
                }
                // No blank line: the data starts at once. Some
                // writers omit it when there are no headers.
                in_headers = false;
            }
            if let Some(sum) = line.strip_prefix('=') {
                let bytes = allcrypt::pem::decode(sum)
                    .map_err(|e| format!("armor checksum: {e}"))?;
                if bytes.len() != 3 {
                    return Err("an armor checksum is three bytes".to_string());
                }
                crc = Some(u32::from(bytes[0]) << 16 | u32::from(bytes[1]) << 8
                           | u32::from(bytes[2]));
                continue;
            }
            body.push_str(line.trim());
        }
        if !ended {
            return Err(format!("no END line for BEGIN PGP {label}"));
        }
        let data = allcrypt::pem::decode(&body).map_err(|e| format!("armor: {e}"))?;
        if let Some(expected) = crc {
            if crc24(&data) != expected {
                return Err("the armor's CRC-24 does not match its data".to_string());
            }
        }
        blocks.push(Armored { label: label.to_string(), headers, data });
    }
    Ok(blocks)
}

/// The first armored block, or the data itself if it is not armored.
pub fn dearmor(data: &[u8]) -> Result<Vec<u8>, String> {
    if !is_armored(data) {
        return Ok(data.to_vec());
    }
    let text = std::str::from_utf8(data).map_err(|_| "armor that is not text")?;
    decode_all(text)?.into_iter().next().map(|b| b.data)
        .ok_or_else(|| "no armored block".to_string())
}

/// Armor `data` under `label`, with a CRC-24 line, which GnuPG expects.
pub fn encode(label: &str, data: &[u8]) -> String {
    let mut out = format!("-----BEGIN PGP {label}-----\n\n");
    let b64 = allcrypt::pem::encode(data);
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    let crc = crc24(data).to_be_bytes();
    out.push('=');
    out.push_str(&allcrypt::pem::encode(&crc[1..]));
    out.push('\n');
    out.push_str(&format!("-----END PGP {label}-----\n"));
    out
}
