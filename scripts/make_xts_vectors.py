#!/usr/bin/env python3
"""Generate the pinned AES-XTS known answers in `src/block_ciphers/xts.rs`.

IEEE 1619's own test vectors are inside the standard, which is not free,
and NIST's CAVP set is a zip download rather than a document this
repository can vendor the way `rfcs/` vendors an RFC. So the known
answers in the Rust tests come from **python-cryptography**, which is
OpenSSL underneath, and this script is what produced them.

That is the arrangement docs/extending.md ("Where test vectors come
from") asks for when no published vector exists: generate from a
reference implementation on the machine, commit the script, and say in a
comment where it came from. Re-run this and the output should be byte
for byte what is already in `xts.rs`; if it is not, either OpenSSL
changed or somebody edited the vectors by hand, and both are worth
knowing.

The broad comparison is `pytests/test_xts.py`, which sweeps every length
against the same reference on every run. These pinned rows exist so that
`cargo test` on its own - with no Python at all - still fails if the mode
changes.

    python3 scripts/make_xts_vectors.py
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def xts(key: bytes, sector: int, data: bytes, encrypt: bool) -> bytes:
    tweak = sector.to_bytes(16, "little")
    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
    worker = cipher.encryptor() if encrypt else cipher.decryptor()
    return worker.update(data) + worker.finalize()


# Each row is chosen for something it is the only one to reach.
CASES = [
    # One block at sector 0: the smallest data unit there is, and the
    # only one where the tweak's endianness does not show.
    #
    # The two halves of the key differ, and must: OpenSSL refuses an XTS
    # key whose halves are equal ("In XTS mode duplicated keys are not
    # allowed"), because that collapses the tweak into the data cipher.
    ("one block, sector 0", bytes([0x11] * 16 + [0x22] * 16), 0, bytes(16)),
    # Sector 1 is the first place a big-endian tweak differs.
    ("two blocks, sector 1", bytes(range(32)), 1, bytes([0x44]) * 32),
    # A partial tail, so ciphertext stealing runs.
    ("three blocks and one byte, sector 2", bytes(range(32)), 2,
     bytes((i * 7 + 1) % 256 for i in range(49))),
    # AES-256-XTS: a 64 byte key, which is the length that looks wrong.
    ("aes-256-xts, four blocks, sector 0x0102030405060708",
     bytes(range(64)), 0x0102030405060708, bytes((i * 3) % 256 for i in range(64))),
    # A sector number above 2^64, which a u64 tweak cannot hold.
    ("aes-256-xts, two blocks, sector 2^70 + 5", bytes(range(64)),
     (1 << 70) + 5, bytes([0xee]) * 32),
]


def main() -> None:
    print("        let cases: &[(&str, &str, u128, &str, &str)] = &[")
    for name, key, sector, plaintext in CASES:
        ciphertext = xts(key, sector, plaintext, True)
        assert xts(key, sector, ciphertext, False) == plaintext
        print(f'            (')
        print(f'                "{name}",')
        print(f'                "{key.hex()}",')
        print(f'                {sector},')
        print(f'                "{plaintext.hex()}",')
        print(f'                "{ciphertext.hex()}",')
        print(f'            ),')
    print("        ];")


if __name__ == "__main__":
    main()
