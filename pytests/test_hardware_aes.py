"""`allcrypt.hardware_aes()` and the AES it describes.

The answer depends on how the module was built (`--features aes-ni`) and
on the processor, so the test asks only what holds either way: it is a
boolean, and AES gives the FIPS 197 answer whichever implementation is
underneath.
"""

import allcrypt


def test_it_is_a_boolean():
    assert isinstance(allcrypt.hardware_aes(), bool)


def test_aes_is_aes_either_way():
    # FIPS 197 appendix C.1, through a mode that takes the multi-block path
    # and one that takes the one-block path.
    key = bytes(range(16))
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    want = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    cipher = allcrypt.Cipher("aes", key)
    assert cipher.encrypt("ecb", block * 20) == want * 20
    assert cipher.encrypt("cbc", block, bytes(16)) == want
