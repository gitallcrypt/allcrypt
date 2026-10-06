# Wallet fixtures

Files other implementations wrote, read by `examples/products/wallet`'s
offline tests. None was edited.

- `trezor-vectors.json`: the BIP-39 test vectors of the reference
  implementation, `trezor/python-mnemonic` at
  b57a5ad77a981e743f4167ab2f7927a55c1e82a8 (MIT licence): entropy,
  mnemonic, seed under the passphrase "TREZOR", and the BIP-32 master
  key.
- `geth/`: keystore files from go-ethereum's `accounts/keystore/testdata`
  at c9a2bc73c847319a8faa57de59e42c0efc420682 (LGPL-3.0):
  `v3_test_vector.json` (the Web3 Secret Storage wiki's two vectors and
  30- and 31-byte keys), `v1_test_vector.json` and `v1-cb61d5a9.json`
  (version 1, password "g"), `very-light-scrypt.json` (empty password),
  and `aaa`, `zzz` and the `UTC--` file (password "foobar").
  `presale.json` is the presale wallet in `plain_test.go`'s
  `TestImportPreSaleKey` (password "foo").
- `wallet.vec`: what `scripts/check_wallet.py --record` kept from
  python-mnemonic and pycoin.
