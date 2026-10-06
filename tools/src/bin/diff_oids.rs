// Every object identifier constant, dumped for two checks that the Rust
// tests cannot do. Verified by scripts/diff_check.py.
//
// `src/x509/oids.rs` already has a test that each constant equals
// `asn1::encode_oid` of its dotted form. That catches a typo in the bytes
// and nothing else, because both sides of it are ours: if `encode_oid`
// were wrong, every constant would match it and every one would be wrong.
// And nothing at all checks that the dotted string is the number the
// world assigns to that *name* - both were typed from one glance at one
// document.
//
// So the checker does two things this cannot:
//
//   * re-encodes the dotted form with an OID encoder written from X.690
//     in Python, which is independent of ours;
//   * looks the *name* up in python-cryptography's tables, which are
//     OpenSSL's, and compares the number.
//
// A constant with no counterpart in those tables is reported rather than
// skipped. A checker that quietly covers two thirds of a table is the
// failure mode this whole exercise exists to prevent, moved somewhere
// harder to see.
//
//   oid <identifier> <dotted>  <bytes>
use allcrypt::x509::oids::ALL_NAMED;

fn main() {
    for (name, dotted, bytes) in ALL_NAMED {
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        println!("oid {} {} {}", name, dotted, hex);
    }
    eprintln!("[diff_oids] {} constants", ALL_NAMED.len());
}
