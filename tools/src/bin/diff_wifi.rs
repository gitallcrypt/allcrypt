// Dumps Michael, TKIP's per-packet key mixing and WEP, swept over
// lengths and sequence counters, so `scripts/diff_check.py wifi` can
// redo them with its own references: Michael and TKIP written out from
// IEEE 802.11 / the Linux kernel, and WEP's RC4+CRC with python's.
use allcrypt::mac::michael::michael;
use allcrypt::stream_ciphers::tkip::rc4_key;
use allcrypt::stream_ciphers::wep;
use allcrypt::to_hex;

fn data(n: usize) -> Vec<u8> { (0..n).map(|i| ((i * 167 + 13) & 0xff) as u8).collect() }
fn key(n: usize) -> Vec<u8> { (0..n).map(|i| ((i * 89 + 7) & 0xff) as u8).collect() }

fn main() {
    let mkey: [u8; 8] = key(8).try_into().unwrap();
    for n in 0..40 {
        println!("michael/{n} {}", to_hex(&michael(&mkey, &data(n))).to_lowercase());
    }
    let tk: [u8; 16] = key(16).try_into().unwrap();
    let ta: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    for tsc in [0u64, 1, 0xffff, 0x10000, 0x1_0001, 0xffff_ffff, 0x1_0000_0000,
                0x1234_5678_9abc, 0xffff_ffff_ffff] {
        println!("tkip/{tsc:012x} {}", to_hex(&rc4_key(&tk, &ta, tsc)).to_lowercase());
    }
    for n in [1usize, 16, 100, 500] {
        let sealed = wep::encrypt(&key(13), &[0x01, 0x02, 0x03], &data(n));
        println!("wep/{n} {}", to_hex(&sealed).to_lowercase());
    }
}
