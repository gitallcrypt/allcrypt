# Ukrainian key stores

Read by `examples/products/keystore`'s offline tests; what dstu-engine's
keylib agreed they hold is in `../keystore-ua.vec`. Copied by
`scripts/check_ua_keys.py --record`, which checks every file taken from
another project against its git blob ID. None was edited.

- From dstu-engine's `tests/` (github.com/dstucrypt/dstu-engine, Apache
  License 2.0): `Key-6.pfx` (password `testplat2021`), a PKCS#12 holding
  two keys, MACed with HMAC-GOST 34.311; and `key.jks` (store password
  `123456`, key password `qwerty`), a JKS as PrivatBank issues them, its
  key zero-padded inside the protector and its certificates of type
  `X509`.
- `ours-*`: converted from those two by the key store example, under the
  password `пароль`: PKCS#12 with the GOST schemes, and JKS.
