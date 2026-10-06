//! Signed git objects: where git puts a signature in a commit and in a
//! tag, and what it signs. As `commit.c` (`do_sign_commit`,
//! `parse_buffer_signed_by_header`) and `gpg-interface.c`
//! (`parse_signed_buffer`) of git 2.43 do it.

/// What kind of object, by its first header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Commit,
    Tag,
}

pub fn kind(object: &[u8]) -> Result<Kind, String> {
    if object.starts_with(b"tree ") {
        Ok(Kind::Commit)
    } else if object.starts_with(b"object ") {
        Ok(Kind::Tag)
    } else {
        Err("Not a commit or a tag object (`git cat-file commit` or `git cat-file tag` \
             prints one).".to_string())
    }
}

/// The header a commit's signature goes in: `gpgsig` in a SHA-1
/// repository, `gpgsig-sha256` in a SHA-256 one.
pub fn header_name(sha256: bool) -> &'static [u8] {
    if sha256 { b"gpgsig-sha256" } else { b"gpgsig" }
}

/// The lines of a buffer, each with its newline if it has one.
fn lines(buf: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, &b) in buf.iter().enumerate() {
        if b == b'\n' {
            out.push(&buf[start..=i]);
            start = i + 1;
        }
    }
    if start < buf.len() {
        out.push(&buf[start..]);
    }
    out
}

/// A commit with the signature inserted as the last header, each line of
/// it after the first indented by one space.
pub fn insert_commit_signature(commit: &[u8], signature: &[u8], sha256: bool) -> Vec<u8> {
    let end_of_header = commit.windows(2).position(|w| w == b"\n\n")
        .map(|i| i + 1).unwrap_or(commit.len());
    let mut out = commit[..end_of_header].to_vec();
    for (i, line) in lines(signature).iter().enumerate() {
        if i == 0 {
            out.extend_from_slice(header_name(sha256));
        }
        out.push(b' ');
        out.extend_from_slice(line);
    }
    out.extend_from_slice(&commit[end_of_header..]);
    out
}

/// A commit's payload and signature: the object without the signature
/// header and its continuation lines, and those lines unindented. `None`
/// for an unsigned commit.
pub fn split_commit(commit: &[u8], sha256: bool) -> Option<(Vec<u8>, Vec<u8>)> {
    let name = header_name(sha256);
    let (mut payload, mut signature) = (Vec::new(), Vec::new());
    let (mut in_header, mut in_signature, mut found) = (true, false, false);
    for line in lines(commit) {
        if in_header && line == b"\n" {
            in_header = false;
            in_signature = false;
        } else if in_header && in_signature && line.starts_with(b" ") {
            signature.extend_from_slice(&line[1..]);
            continue;
        } else if in_header && line.starts_with(name) && line.get(name.len()) == Some(&b' ') {
            signature.extend_from_slice(&line[name.len() + 1..]);
            in_signature = true;
            found = true;
            continue;
        } else {
            in_signature = false;
        }
        payload.extend_from_slice(line);
    }
    found.then_some((payload, signature))
}

/// The armour lines a signature can start with, by format.
pub const MARKERS: [(&str, &str); 3] = [
    ("openpgp", "-----BEGIN PGP SIGNATURE-----"),
    ("ssh", "-----BEGIN SSH SIGNATURE-----"),
    ("x509", "-----BEGIN SIGNED MESSAGE-----"),
];

pub fn format_of(signature: &[u8]) -> Option<&'static str> {
    let text = String::from_utf8_lossy(signature);
    MARKERS.iter().find(|(_, m)| text.trim_start().starts_with(m)).map(|(f, _)| *f)
}

/// A tag's payload and signature: the signature is everything from the
/// last line that starts a known armour to the end.
pub fn split_tag(tag: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut at = None;
    let mut offset = 0;
    for line in lines(tag) {
        if MARKERS.iter().any(|(_, m)| line.starts_with(m.as_bytes())) {
            at = Some(offset);
        }
        offset += line.len();
    }
    at.map(|i| (tag[..i].to_vec(), tag[i..].to_vec()))
}

/// A payload and its signature.
pub type Parts = (Vec<u8>, Vec<u8>);

/// The payload and signature of either kind.
pub fn split(object: &[u8], sha256: bool) -> Result<Option<Parts>, String> {
    Ok(match kind(object)? {
        Kind::Commit => split_commit(object, sha256),
        Kind::Tag => split_tag(object),
    })
}

/// The object signed: a commit's signature as a header, a tag's appended.
pub fn insert(object: &[u8], signature: &[u8], sha256: bool) -> Result<Vec<u8>, String> {
    if split(object, sha256)?.is_some() {
        return Err("The object is signed already.".to_string());
    }
    Ok(match kind(object)? {
        Kind::Commit => insert_commit_signature(object, signature, sha256),
        Kind::Tag => [object, signature].concat(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT: &[u8] = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
        author A U Thor <author@example.com> 1112911993 -0700\n\
        committer C O Mitter <committer@example.com> 1112911993 -0700\n\
        \n\
        initial\n";
    const SIGNATURE: &[u8] = b"-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\nAAAA\n\
        -----END SSH SIGNATURE-----\n";

    #[test]
    fn test_a_commit_signature_round_trips() {
        let signed = insert(COMMIT, SIGNATURE, false).unwrap();
        let text = String::from_utf8(signed.clone()).unwrap();
        assert!(text.contains("\ngpgsig -----BEGIN SSH SIGNATURE-----\n U1NIU0lH\n AAAA\n \
                               -----END SSH SIGNATURE-----\n\ninitial\n"), "{text}");
        assert_eq!(split(&signed, false).unwrap(), Some((COMMIT.to_vec(), SIGNATURE.to_vec())));
        // The SHA-256 header is another header.
        assert_eq!(split(&signed, true).unwrap(), None);
        assert!(insert(&signed, SIGNATURE, false).is_err());
    }

    #[test]
    fn test_a_tag_signature_round_trips() {
        let tag = b"object 4b825dc642cb6eb9a060e54bf8d69288fbee4904\ntype commit\ntag v1\n\
                    tagger T <t@example.com> 1112911993 -0700\n\nrelease, with \
                    -----BEGIN PGP SIGNATURE----- inside a line\n";
        assert_eq!(split(tag, false).unwrap(), None);
        let signed = insert(tag, SIGNATURE, false).unwrap();
        assert_eq!(split(&signed, false).unwrap(), Some((tag.to_vec(), SIGNATURE.to_vec())));
        assert_eq!(format_of(SIGNATURE), Some("ssh"));
    }
}
