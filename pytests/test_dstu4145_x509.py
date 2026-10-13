"""DSTU 4145-2002 certificates through Python: the real ones and ours in
`tests/keys/ua-x509/`, whose signatures dstu-engine, li0ard or both verify
(`vectors/dstu4145_x509.vec`, written by
`scripts/make_dstu4145_x509_vectors.py`), read and verified as chains."""

import pathlib

import pytest

import allcrypt

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "keys" / "ua-x509"
ROWS = [dict(field.split("=", 1) for field in line.split()[1:])
        for line in (ROOT / "vectors" / "dstu4145_x509.vec").read_text().splitlines()
        if line.startswith("cert ")]
# Inside every certificate's validity but czo-1.cer's, 2005 to 2010.
NOW = 1_800_000_000
HASH_NAMES = {"gost34311": "GOST 34.311-95", "kupyna256": "Kupyna-256",
              "kupyna384": "Kupyna-384", "kupyna512": "Kupyna-512"}


def read(name):
    return (FIXTURES / name).read_bytes()


def test_the_rows_are_there():
    assert len(ROWS) == 19
    assert {r["source"] for r in ROWS} == {"both", "dstu-engine", "li0ard"}


@pytest.mark.parametrize("row", ROWS, ids=[r["file"] for r in ROWS])
def test_each_certificate_reads_and_verifies(row):
    info = allcrypt.Certificate(read(row["file"])).to_dict()
    assert info["signatureAlgorithm"] == f"DSTU 4145-2002 with {HASH_NAMES[row['hash']]}"
    assert info["publicKeyType"].startswith("DSTU 4145-2002 ")
    chain, roots = [read(row["file"])], [read(row["issuer"])]
    if row["file"] == row["issuer"]:
        chain = roots
    now = 1_200_000_000 if row["file"] == "czo-1.cer" else NOW
    if row["file"] == "czo-root-2017.cer":
        # Its certificatePolicies and qcStatements are marked critical,
        # and a verifier that does not process an extension marked so
        # refuses the certificate (RFC 5280 4.2); its signature verifies,
        # which tests/test_dstu4145_x509.rs checks on its own.
        with pytest.raises(allcrypt.CryptoError, match="2.5.29.32, 1.3.6.1.5.5.7.1.3"):
            allcrypt.verify_chain(chain, roots, now, purpose="any")
        return
    allcrypt.verify_chain(chain, roots, now, purpose="any")
    changed = bytearray(read(row["file"]))
    changed[-1] ^= 1
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.verify_chain([bytes(changed)], [bytes(changed)] if chain is roots else roots,
                              now, purpose="any")


def test_the_curve_is_named_when_it_is_one_of_the_ten():
    # The centre's roots give m431 whole; czo-1.cer with another base
    # point, which makes it a curve of its own.
    assert allcrypt.Certificate(read("czo-root-2017.cer")).to_dict()["publicKeyType"] == \
        "DSTU 4145-2002 dstu4145-m431"
    assert allcrypt.Certificate(read("czo-1.cer")).to_dict()["publicKeyType"] == \
        "DSTU 4145-2002 a custom curve over GF(2^431)"


def test_a_leaf_is_not_its_own_root():
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.verify_chain([read("ours-x509-leaf-be.cer")], [read("ours-x509-leaf-be.cer")],
                              NOW, purpose="any")
