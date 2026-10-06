//! S/MIME (RFC 8551): CMS inside MIME. An encrypted or opaque-signed
//! message is one `application/pkcs7-mime` part in base64; a clear-signed
//! one is `multipart/signed`, the content as it is and the signature
//! beside it in `application/pkcs7-signature`.
//!
//! What a clear signature covers is the content part's bytes in
//! canonical form - every line ending CRLF (RFC 8551 3.1.1) - between
//! the boundary lines, not counting the line break that belongs to the
//! boundary after it (RFC 2046 5.1.1).

use crate::base64;

/// One MIME entity: its headers, lower-cased names, and its body.
pub struct Entity {
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Entity {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    /// The media type, lower case.
    pub fn content_type(&self) -> String {
        let value = self.header("content-type").unwrap_or("text/plain");
        value.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
    }

    /// A parameter of a header, quotes removed.
    pub fn parameter(&self, header: &str, name: &str) -> Option<String> {
        let value = self.header(header)?;
        value.split(';').skip(1).filter_map(|part| part.split_once('='))
            .find(|(key, _)| key.trim().eq_ignore_ascii_case(name))
            .map(|(_, val)| val.trim().trim_matches('"').to_string())
    }
}

/// Where a line ends: the index after its CRLF or LF, and the index
/// where its text ends.
fn line_at(data: &[u8], start: usize) -> Option<(usize, usize)> {
    if start >= data.len() {
        return None;
    }
    let end = data[start..].iter().position(|&b| b == b'\n').map(|p| start + p)
        .unwrap_or(data.len());
    let text_end = if end > start && data.get(end - 1) == Some(&b'\r') { end - 1 } else { end };
    Some((text_end, (end + 1).min(data.len())))
}

/// Headers up to the first empty line, folded lines unfolded, and the
/// body after it.
pub fn parse(data: &[u8]) -> Result<Entity, String> {
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut at = 0;
    loop {
        let (text_end, next) = line_at(data, at).ok_or("MIME: no empty line after the \
                                                         headers.")?;
        let line = std::str::from_utf8(&data[at..text_end])
            .map_err(|_| "MIME: a header that is not text.".to_string())?;
        at = next;
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            let last = headers.last_mut().ok_or("MIME: a continuation line first.")?;
            last.1.push(' ');
            last.1.push_str(line.trim());
            continue;
        }
        let (name, value) = line.split_once(':')
            .ok_or_else(|| format!("MIME: not a header: {line:?}"))?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
    Ok(Entity { headers, body: data[at..].to_vec() })
}

/// LF or CRLF line endings, all made CRLF.
pub fn canonical(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 32);
    for (i, &b) in data.iter().enumerate() {
        if b == b'\n' && (i == 0 || data[i - 1] != b'\r') {
            out.push(b'\r');
        }
        out.push(b);
    }
    out
}

/// What an S/MIME message holds.
pub enum Message {
    /// `application/pkcs7-mime`: the CMS DER.
    Opaque(Vec<u8>),
    /// `multipart/signed`: the signed content as it appeared, and the
    /// signature's CMS DER.
    ClearSigned { content: Vec<u8>, signature: Vec<u8> },
}

fn body_bytes(entity: &Entity) -> Result<Vec<u8>, String> {
    let encoding = entity.header("content-transfer-encoding").unwrap_or("7bit")
        .to_ascii_lowercase();
    match encoding.as_str() {
        "base64" => base64::decode(&String::from_utf8_lossy(&entity.body))
            .ok_or_else(|| "S/MIME: the base64 does not decode.".to_string()),
        "binary" | "8bit" | "7bit" => Ok(entity.body.clone()),
        other => Err(format!("S/MIME: content transfer encoding {other} is not read here.")),
    }
}

pub fn read(data: &[u8]) -> Result<Message, String> {
    let entity = parse(data)?;
    let media = entity.content_type();
    match media.as_str() {
        "application/pkcs7-mime" | "application/x-pkcs7-mime"
            | "application/pkcs7-signature" | "application/x-pkcs7-signature" =>
            Ok(Message::Opaque(body_bytes(&entity)?)),
        "multipart/signed" => {
            let boundary = entity.parameter("content-type", "boundary")
                .ok_or("S/MIME: multipart/signed without a boundary.")?;
            let delimiter = format!("--{boundary}");
            let parts = split_multipart(&entity.body, delimiter.as_bytes())?;
            if parts.len() != 2 {
                return Err(format!("S/MIME: multipart/signed with {} parts, not 2.",
                                   parts.len()));
            }
            let signature = parse(parts[1])?;
            let media = signature.content_type();
            if !media.ends_with("pkcs7-signature") {
                return Err(format!("S/MIME: the signature part is {media}."));
            }
            Ok(Message::ClearSigned { content: parts[0].to_vec(),
                                      signature: body_bytes(&signature)? })
        }
        other => Err(format!("S/MIME: a {other} message holds no CMS.")),
    }
}

/// The body parts of a multipart body: what lies between delimiter
/// lines, each without the line break that belongs to the delimiter.
fn split_multipart<'a>(body: &'a [u8], delimiter: &[u8]) -> Result<Vec<&'a [u8]>, String> {
    let mut parts = Vec::new();
    let mut at = 0;
    let mut start: Option<usize> = None;
    while let Some((text_end, next)) = line_at(body, at) {
        let line = &body[at..text_end];
        let trimmed_end = line.iter().rposition(|&b| b != b' ' && b != b'\t')
            .map_or(0, |p| p + 1);
        let line = &line[..trimmed_end];
        let rest = line.strip_prefix(delimiter).filter(|r| r.is_empty() || *r == b"--");
        if let Some(rest) = rest {
            if let Some(s) = start {
                // The CRLF (or LF) before the delimiter is the delimiter's.
                let mut end = at;
                if end > s && body[end - 1] == b'\n' {
                    end -= 1;
                    if end > s && body[end - 1] == b'\r' {
                        end -= 1;
                    }
                }
                parts.push(&body[s..end]);
            }
            if rest == b"--" {
                return Ok(parts);
            }
            if rest.is_empty() {
                start = Some(next);
            }
        }
        at = next;
    }
    Err("S/MIME: the multipart body has no closing delimiter.".to_string())
}

fn base64_lines(der: &[u8]) -> String {
    let text = base64::encode(der);
    let mut out = String::new();
    for chunk in text.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push_str("\r\n");
    }
    out
}

/// `application/pkcs7-mime` with the given smime-type.
pub fn write_opaque(der: &[u8], smime_type: &str) -> Vec<u8> {
    format!("MIME-Version: 1.0\r\n\
             Content-Disposition: attachment; filename=\"smime.p7m\"\r\n\
             Content-Type: application/pkcs7-mime; smime-type={smime_type}; \
             name=\"smime.p7m\"\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n{}", base64_lines(der)).into_bytes()
}

/// RFC 8551 3.4.3.2's micalg names.
pub fn micalg(hash: &str) -> &'static str {
    match hash {
        "md5" => "md5",
        "sha1" => "sha-1",
        "sha224" => "sha-224",
        "sha256" => "sha-256",
        "sha384" => "sha-384",
        "sha512" => "sha-512",
        _ => "unknown",
    }
}

/// `multipart/signed`: `content` exactly as it was signed - already
/// canonical - and the detached signature.
pub fn write_clear_signed(content: &[u8], signature_der: &[u8], hash: &str, boundary: &str)
                          -> Vec<u8> {
    let mut out = format!(
        "MIME-Version: 1.0\r\n\
         Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; \
         micalg=\"{}\"; boundary=\"{boundary}\"\r\n\r\n\
         This is an S/MIME signed message\r\n\r\n--{boundary}\r\n",
        micalg(hash)).into_bytes();
    out.extend_from_slice(content);
    out.extend_from_slice(format!(
        "\r\n--{boundary}\r\n\
         Content-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\n\
         Content-Transfer-Encoding: base64\r\n\
         Content-Disposition: attachment; filename=\"smime.p7s\"\r\n\r\n{}\r\n\
         --{boundary}--\r\n", base64_lines(signature_der)).as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CRLF before a delimiter belongs to the delimiter, a content
    /// ending in its own line break keeps it, and a delimiter that is
    /// only a prefix of a longer line is not one.
    #[test]
    fn test_multipart_parts_end_where_rfc_2046_says() {
        let body = b"preamble\r\n--b\r\nfirst\r\n\r\n--b-not\r\n--b\nsecond\n--b--\r\nepilogue";
        let parts = split_multipart(body, b"--b").unwrap();
        assert_eq!(parts, [&b"first\r\n\r\n--b-not"[..], b"second"]);
        assert!(split_multipart(b"--b\r\nopen\r\n", b"--b").is_err());
    }

    #[test]
    fn test_canonical_line_endings() {
        assert_eq!(canonical(b"a\nb\r\nc\n"), b"a\r\nb\r\nc\r\n");
        assert_eq!(canonical(b"\n\n"), b"\r\n\r\n");
    }

    #[test]
    fn test_headers_unfold_and_parameters_are_read() {
        let e = parse(b"Content-Type: multipart/signed;\r\n\tboundary=\"x y\"; \
                        micalg=sha-256\r\n\r\nbody").unwrap();
        assert_eq!(e.content_type(), "multipart/signed");
        assert_eq!(e.parameter("content-type", "boundary").as_deref(), Some("x y"));
        assert_eq!(e.body, b"body");
    }
}
