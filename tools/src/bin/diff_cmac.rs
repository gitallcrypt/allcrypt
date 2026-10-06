// CMAC over every block cipher here, dumped for comparison. Verified by
// scripts/diff_check.py.
//
// This corpus is in two halves and they prove different things.
//
// **AES, Triple DES and Blowfish** are compared against OpenSSL's CMAC
// through python-cryptography. That is a real independent implementation,
// and between them they cover both block sizes - so both values of Rb,
// the padding rule and the two subkeys are checked by somebody else's
// code.
//
// **Kuznyechik and Magma** have no CMAC anywhere on this machine, so
// those rows go to the construction written out from NIST SP 800-38B in
// the checker, driven by *its own* ciphers rather than ours. So both
// halves compare against an independent implementation; what differs is
// that the first half's mode is somebody else's code and the second
// half's is a second reading of the specification.
//
// DES and GOST 28147-89 are deliberately absent: nothing here can check
// a CMAC over either, and a corpus row that nothing checks counts towards
// the total and proves nothing.
//
// Lengths sweep 0 to 3 blocks byte by byte, because the last block is the
// only one treated differently and every length is either exactly on a
// boundary or not.
//
//   cmac <cipher> <key> <message>  <tag>
use allcrypt::mac::cmac::cmac;

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn filler(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| ((i as u32 * 167 + seed as u32 * 61 + 29) & 0xff) as u8).collect()
}

fn main() {
    let mut cases = 0usize;

    // (name, key lengths to try)
    let ciphers: &[(&str, &[usize])] = &[
        ("aes", &[16, 24, 32]),
        ("3des", &[24]),
        ("blowfish", &[16]),
        ("kuznyechik", &[32]),
        ("magma", &[32]),
    ];

    for (name, key_lengths) in ciphers {
        for (index, key_length) in key_lengths.iter().enumerate() {
            let key = filler(*key_length, index as u8 + 3);
            // Zero through three blocks, byte by byte, plus a few long
            // ones. The boundary cases are 0, b, 2b and 3b: the empty
            // message is padded and every full block is not.
            let message = filler(200, index as u8 + 70);
            let mut lengths: Vec<usize> = (0..=48).collect();
            lengths.extend([49, 63, 64, 65, 127, 128, 129, 200]);

            for length in lengths {
                let tag = cmac(name, &key, &message[..length]).unwrap();
                println!("cmac {} {} {} {}",
                         name, hex(&key), hex(&message[..length]), hex(&tag));
                cases += 1;
            }
        }
    }

    eprintln!("[diff_cmac] {} cases", cases);
}
