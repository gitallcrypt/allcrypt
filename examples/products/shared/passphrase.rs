//! A passphrase from standard input, for the examples that otherwise take
//! one on the command line, where it is visible to every user of the
//! machine through the process list and is kept in the shell's history.
//!
//! From a pipe or a file, the first line is the passphrase, without its
//! line ending (`\n` or `\r\n`); the rest of the input is not read.
//! From a terminal, a prompt goes to standard error and echo is turned
//! off while the line is typed (through `stty`, on Unix; elsewhere the
//! line is read with echo on).

#![allow(dead_code)]

use std::io::{BufRead, IsTerminal, Read, Write};

/// One line of standard input, prompting with `prompt` if it is a
/// terminal.
pub fn read_line(prompt: &str) -> Result<Vec<u8>, String> {
    let stdin = std::io::stdin();
    let terminal = stdin.is_terminal();
    let echo_off = terminal && set_echo(false);
    if terminal {
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
    }
    let mut line = Vec::new();
    let result = stdin.lock().read_until(b'\n', &mut line);
    if echo_off {
        set_echo(true);
        eprintln!();
    }
    result.map_err(|e| format!("standard input: {e}"))?;
    if line.is_empty() {
        return Err("standard input ended before a passphrase".to_string());
    }
    Ok(without_line_ending(line))
}

/// A line read with its `\n` or `\r\n` removed. A line without one
/// (the input's last) is unchanged, and so is a lone `\r`.
fn without_line_ending(mut line: Vec<u8>) -> Vec<u8> {
    if line.ends_with(b"\n") {
        line.pop();
        if line.ends_with(b"\r") {
            line.pop();
        }
    }
    line
}

/// All of standard input, unchanged: a key file given as `-`, which may
/// hold any bytes including line endings.
pub fn read_all() -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    std::io::stdin().lock().read_to_end(&mut data).map_err(|e| format!("standard input: {e}"))?;
    Ok(data)
}

/// Whether echo was changed.
#[cfg(unix)]
fn set_echo(on: bool) -> bool {
    std::process::Command::new("stty")
        .arg(if on { "echo" } else { "-echo" })
        .stdin(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(not(unix))]
fn set_echo(_on: bool) -> bool {
    false
}

#[cfg(test)]
mod passphrase_tests {
    use super::without_line_ending;

    #[test]
    fn test_the_line_ending_is_removed_and_nothing_else() {
        assert_eq!(without_line_ending(b"pass word\n".to_vec()), b"pass word");
        assert_eq!(without_line_ending(b"pass word\r\n".to_vec()), b"pass word");
        assert_eq!(without_line_ending(b"no ending".to_vec()), b"no ending");
        assert_eq!(without_line_ending(b" spaces kept \n".to_vec()), b" spaces kept ");
        assert_eq!(without_line_ending(b"ends in cr\r".to_vec()), b"ends in cr\r");
        assert_eq!(without_line_ending(b"\n".to_vec()), b"");
    }
}
