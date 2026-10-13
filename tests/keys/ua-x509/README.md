# Ukrainian certificates

DSTU 4145-2002 certificates, read by `tests/test_dstu4145_x509.rs` and
`pytests/test_dstu4145_x509.py` against `vectors/dstu4145_x509.vec`;
`scripts/make_dstu4145_x509_vectors.py` writes all of them, and what
dstu-engine and li0ard made of each. jkurwa's self-signed certificates
are beside its keys in `tests/keys/ua/`.

- `czo-root-2017.cer`, `cao-2026.cer` and `czo-1.cer`: root
  certificates of Ukraine's central certifying authority, as the tests
  of li0ard/dstu (MIT licence) carry them in `src/dstu4145/x509.spec.ts`,
  each checked against its SHA-256.
- `ours-x509-*.cer`: certificates this library issued
  (`tools/src/bin/dstu4145_certs.rs`): `-mNNN-<le|be>-<hash>` is
  self-signed on that curve; `-ca-<tag>` and `-leaf-<tag>` are a chain,
  the `le-dke` CA with a DKE that is not the default.
