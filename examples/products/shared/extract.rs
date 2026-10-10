//! Where an archive entry may be written: under the destination, never
//! outside it ("zip slip").

#![allow(dead_code)]

use std::path::{Component, Path, PathBuf};

/// Where an entry named `name` may be written under `root`, or an error
/// for a name that is empty, absolute, or climbs out with `..`.
///
/// Both `/` and `\` separate components, on every platform: the formats
/// say `/`, and an archive made on Windows by a program that did not
/// follow them means a directory by `\`. Read as part of a file name
/// instead, `a\b` would be one oddly named file here and a directory on
/// Windows.
pub fn destination(root: &Path, name: &str) -> Result<PathBuf, String> {
    let mut out = root.to_path_buf();
    if name.is_empty() {
        return Err("An entry with no name.".to_string());
    }
    if name.starts_with(['/', '\\']) {
        return Err(format!("{name}: a name that leaves the destination."));
    }
    for part in name.split(['/', '\\']) {
        match Path::new(part).components().next() {
            None => {}
            Some(Component::Normal(p)) if Path::new(part).components().count() == 1 => out.push(p),
            Some(Component::CurDir) => {}
            _ => return Err(format!("{name}: a name that leaves the destination.")),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_name_stays_under_the_destination() {
        let root = Path::new("out");
        assert_eq!(destination(root, "a/b.txt").unwrap(), root.join("a").join("b.txt"));
        assert_eq!(destination(root, "a\\b.txt").unwrap(), root.join("a").join("b.txt"));
        assert_eq!(destination(root, "./a//b").unwrap(), root.join("a").join("b"));
        for bad in ["", "/etc/passwd", "\\x", "../x", "a/../../x", "a\\..\\..\\x", "C:x"] {
            if bad == "C:x" && !cfg!(windows) {
                continue;
            }
            assert!(destination(root, bad).is_err(), "{bad:?}");
        }
    }
}
