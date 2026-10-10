//! Command-line arguments as the examples take them: `--name value`
//! options, bare flags, and positional arguments in between, plus the
//! hex every example reads and prints.
//!
//! Every example parses its own command line, so these used to be
//! copied into each one; the copies had already begun to drift.

#![allow(dead_code)]

/// The value after `name`, if `name` is there.
pub fn value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

/// Whether the flag `name` is there.
pub fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// The arguments that are neither an option nor its value. `flags` are
/// the options that take no value; every other `--name` takes one, and
/// `counted` names any that take more.
pub fn positional<'a>(args: &'a [String], flags: &[&str], counted: &[(&str, usize)])
                      -> Vec<&'a String> {
    let mut out = Vec::new();
    let mut skip = 0;
    for arg in args {
        if skip > 0 {
            skip -= 1;
        } else if flags.contains(&arg.as_str()) {
        } else if let Some(&(_, n)) = counted.iter().find(|(name, _)| name == arg) {
            skip = n;
        } else if arg.starts_with("--") {
            skip = 1;
        } else {
            out.push(arg);
        }
    }
    out
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex, either case, after removing every character in `ignored` (the
/// colons of a fingerprint, the spaces of a pasted dump). An odd number
/// of digits or anything else that is not a digit is an error.
pub fn unhex(text: &str, ignored: &[char]) -> Result<Vec<u8>, String> {
    let digits: Vec<u8> = text.chars().filter(|c| !ignored.contains(c))
        .map(|c| u8::try_from(c).ok().filter(u8::is_ascii_hexdigit)
             .ok_or_else(|| format!("Not hex: {text}")))
        .collect::<Result<_, _>>()?;
    if !digits.len().is_multiple_of(2) {
        return Err(format!("An odd number of hex digits: {text}"));
    }
    Ok(digits.chunks(2).map(|pair| {
        let digit = |d: u8| (d as char).to_digit(16).expect("checked above") as u8;
        digit(pair[0]) << 4 | digit(pair[1])
    }).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn test_positional_skips_options_and_their_values() {
        let a = args("open --key k file --verbose out --pair x y last");
        let got = positional(&a, &["--verbose"], &[("--pair", 2)]);
        assert_eq!(got, ["open", "file", "out", "last"]);
        assert_eq!(value(&a, "--key"), Some("k"));
        assert_eq!(value(&a, "--missing"), None);
        assert!(has(&a, "--verbose"));
    }

    #[test]
    fn test_unhex() {
        assert_eq!(unhex("00fF10", &[]).unwrap(), [0, 255, 16]);
        assert_eq!(unhex("00:ff 10", &[':', ' ']).unwrap(), [0, 255, 16]);
        assert!(unhex("00:ff", &[]).is_err());
        assert!(unhex("0ff", &[]).is_err());
        assert!(unhex("zz", &[]).is_err());
        assert!(unhex("é0", &[]).is_err());
        assert_eq!(hex(&[0, 255, 16]), "00ff10");
    }
}
