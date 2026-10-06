"""OpenSSL entry points no Python binding exposes, through ctypes: what
`scripts/diff_check.py` and the tests compare against where
python-cryptography has nothing.

Only libcrypto's public EVP interface is used, from whatever libcrypto
the system has; nothing is built.
"""

import ctypes
import ctypes.util


def openssl_cts(name, variant, key, iv, data, encrypt=True):
    """OpenSSL 3's CBC-CTS (`AES-128-CBC-CTS` and the rest) through
    ctypes, since no Python binding exposes it. `variant` is CS1, CS2 or
    CS3, OpenSSL's `cts_mode` parameter. One-shot: OpenSSL's CTS does not
    stream."""
    lib = ctypes.CDLL(ctypes.util.find_library("crypto"))
    lib.EVP_CIPHER_fetch.restype = ctypes.c_void_p
    lib.EVP_CIPHER_fetch.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    lib.EVP_CIPHER_free.argtypes = [ctypes.c_void_p]
    lib.EVP_CipherInit_ex2.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p,
                                       ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
    lib.EVP_CipherUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                     ctypes.POINTER(ctypes.c_int), ctypes.c_char_p,
                                     ctypes.c_int]
    lib.EVP_CipherFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.POINTER(ctypes.c_int)]

    class OsslParam(ctypes.Structure):
        _fields_ = [("key", ctypes.c_char_p), ("data_type", ctypes.c_uint),
                    ("data", ctypes.c_void_p), ("data_size", ctypes.c_size_t),
                    ("return_size", ctypes.c_size_t)]
    cipher = lib.EVP_CIPHER_fetch(None, name.encode(), None)
    if not cipher:
        raise ValueError(f"this OpenSSL has no {name}")
    ctx = lib.EVP_CIPHER_CTX_new()
    value = ctypes.create_string_buffer(variant.encode())
    params = (OsslParam * 2)()
    # 4 is OSSL_PARAM_UTF8_STRING; the second entry is the terminator.
    params[0] = OsslParam(b"cts_mode", 4, ctypes.cast(value, ctypes.c_void_p), len(variant), 0)
    try:
        if lib.EVP_CipherInit_ex2(ctx, cipher, key, iv, 1 if encrypt else 0, params) != 1:
            raise ValueError(f"OpenSSL refused to set up {name} {variant}")
        out = ctypes.create_string_buffer(len(data) + 32)
        written = ctypes.c_int(0)
        if lib.EVP_CipherUpdate(ctx, out, ctypes.byref(written), data, len(data)) != 1:
            raise ValueError(f"OpenSSL's {name} {variant} refused {len(data)} bytes")
        n = written.value
        final = ctypes.c_int(0)
        if lib.EVP_CipherFinal_ex(ctx, ctypes.byref(out, n), ctypes.byref(final)) != 1:
            raise ValueError(f"OpenSSL's {name} {variant} failed to finish")
        return out.raw[:n + final.value]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)
        lib.EVP_CIPHER_free(cipher)


def openssl_kbkdf(mode, mac, algorithm, key, label, context, iv, length):
    """OpenSSL 3's SP 800-108 KBKDF (`EVP_KDF` "KBKDF"): `mode` COUNTER
    or FEEDBACK, `mac` HMAC (with `algorithm` a digest name) or CMAC
    (with a cipher name such as AES-128-CBC). `iv` is feedback mode's
    seed. OpenSSL's defaults are the fixed data this library uses: a
    32-bit counter, the zero separator and the length in bits."""
    lib = ctypes.CDLL(ctypes.util.find_library("crypto"))
    lib.EVP_KDF_fetch.restype = ctypes.c_void_p
    lib.EVP_KDF_fetch.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.EVP_KDF_CTX_new.restype = ctypes.c_void_p
    lib.EVP_KDF_CTX_new.argtypes = [ctypes.c_void_p]
    lib.EVP_KDF_CTX_free.argtypes = [ctypes.c_void_p]
    lib.EVP_KDF_free.argtypes = [ctypes.c_void_p]
    lib.EVP_KDF_derive.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
                                   ctypes.c_void_p]

    class OsslParam(ctypes.Structure):
        _fields_ = [("key", ctypes.c_char_p), ("data_type", ctypes.c_uint),
                    ("data", ctypes.c_void_p), ("data_size", ctypes.c_size_t),
                    ("return_size", ctypes.c_size_t)]
    keep = []

    def param(name, value, kind):
        buffer = ctypes.create_string_buffer(value, max(len(value), 1))
        keep.append(buffer)
        return OsslParam(name, kind, ctypes.cast(buffer, ctypes.c_void_p), len(value), 0)
    utf8, octets = 4, 5
    params = [param(b"mode", mode.encode(), utf8), param(b"mac", mac.encode(), utf8),
              param(b"digest" if mac == "HMAC" else b"cipher", algorithm.encode(), utf8),
              param(b"key", key, octets), param(b"salt", label, octets),
              param(b"info", context, octets)]
    if iv is not None:
        params.append(param(b"seed", iv, octets))
    array = (OsslParam * (len(params) + 1))(*params)
    kdf = lib.EVP_KDF_fetch(None, b"KBKDF", None)
    ctx = lib.EVP_KDF_CTX_new(kdf)
    try:
        out = ctypes.create_string_buffer(length)
        if lib.EVP_KDF_derive(ctx, out, length, array) != 1:
            raise ValueError(f"OpenSSL's KBKDF refused {mode} {mac} {algorithm}")
        return out.raw
    finally:
        lib.EVP_KDF_CTX_free(ctx)
        lib.EVP_KDF_free(kdf)
