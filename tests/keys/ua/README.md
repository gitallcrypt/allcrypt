# Ukrainian key containers

Read by `tests/test_ua_keys.rs` and `pytests/test_ua_keys.py`; what
dstu-engine's keylib found in each is in `vectors/ua_keys.vec`. Copied
by `scripts/check_ua_keys.py --record`, which checks every file taken
from another project against its git blob ID. None was edited.

- `Key-6.dat` (password `tect4`): IIT's key store holding a signing key
  and a key-agreement key, from dstu-engine's `tests/`
  (github.com/dstucrypt/dstu-engine, Apache License 2.0).
- From jkurwa's `test/data/` (github.com/dstucrypt/jkurwa, BSD licence):
  `STORE_A040.dat` and `.pem` (an encrypted PKCS#8, PBES2 with GOST
  28147 CFB and HMAC-GOST 34.311, password `password`); `Key40A0.cer`
  and `.pem`, `PRIV1.cer`, `Key6929.cer` and `KeyE54B.cer` (plain keys;
  KeyE54B's `d` is above the order); and the self-signed certificates
  `SELF_SIGNED1.cer` and `SELF_SIGNED_ENC_{40A0,6929,E54B}.cer`, whose
  subject key identifiers name those keys.
- `ours-*`: written by this library. `ours-mNNN.der` is a plain key on
  each named curve, those on even-numbered curves in the list with a
  second key in the attributes; `-pbes2.der` and `-key6.dat` are the
  same keys encrypted under the password `пароль`; `-long` under
  `парольпарольпарольпароль`, 48 bytes; `-empty` under the empty
  password.
