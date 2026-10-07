// The NT and LM password hashes, dumped for comparison. Verified by
// scripts/diff_check.py: the NT hash against its MD4 (pinned to
// OpenSSL's) over the UTF-16LE password, the LM hash against the
// construction written out from MS-NLMP over python-cryptography's DES.
//
// LM rows sweep every length from 0 to 14 bytes, with lowercase,
// digits, punctuation, bytes above 0x7f (used as they are) and zero
// bytes, which pad exactly like the padding. NT rows take text with
// characters from one to four UTF-8 bytes, so both UTF-16 forms - one
// unit and a surrogate pair - appear.
//
//   lm <password bytes> <hash>
//   nt <password as UTF-8> <hash>
use allcrypt::kdf::windows::{lm_hash, nt_hash};

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let mut cases = 0usize;
    let alphabets: [&[u8]; 5] = [
        b"password", b"Pa55w0rd!#%&", b"\x80\xe9\x90\xff\xa0",
        b"a\0b\0c", b"zZyYxXwWvVuUtTsS",
    ];
    for alphabet in alphabets {
        for length in 0..=14 {
            let password: Vec<u8> = (0..length).map(|i| alphabet[(i * 5 + length) % alphabet.len()])
                .collect();
            println!("lm {} {}", hex(&password), hex(&lm_hash(&password).unwrap()));
            cases += 1;
        }
    }
    for password in [&b"Password"[..], b"password", b"PASSWORD"] {
        println!("lm {} {}", hex(password), hex(&lm_hash(password).unwrap()));
        cases += 1;
    }
    let texts = ["", "Password", "password", "SecREt01", "\u{e9}t\u{e9}", "\u{20ac}uro",
                 "\u{1f600}", "a\u{1f511}b\u{20ac}c\u{e9}d", "\u{4e2d}\u{6587}\u{5bc6}\u{7801}",
                 "a much longer pass phrase than fourteen characters"];
    for text in texts {
        println!("nt {} {}", hex(text.as_bytes()), hex(&nt_hash(text)));
        cases += 1;
    }
    eprintln!("[diff_windows_hashes] {} cases", cases);
}
