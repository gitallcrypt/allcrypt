#!/bin/sh
# Builds /opt/crcwitness: other implementations of the CRCs, as witnesses
# for src/checksum/crc_catalogue.rs and vectors/crc.vec.
#
#   pycrc-bbb, pycrc-bbf, pycrc-tbl
#             pycrc 0.10.0's three algorithms, bit by bit, bit by bit
#             fast and table driven, under crc_python.py
#   crccheck  crccheck 1.3.0's CrcBase, under crc_python.py; its crc.py
#             transcribes the catalogue of parametrised CRC algorithms
#   crcmod    crcmod 1.7, its C extension, which pip compiles from the
#             source distribution, under crc_python.py: widths 8, 16,
#             24, 32 and 64, reflected in and out alike
#   rust-crc  the crc 3.4.0 crate at 128 bits, its three table sizes,
#             under rust_crc/;
#             its crc-catalog 2.5.0 dependency transcribes the catalogue
#             too
#
# The Python packages are installed from PyPI with their hashes required
# (requirements.txt); cargo fetches the crates, pinned with their checksums
# by rust_crc/Cargo.lock. selftest.py then requires the two transcriptions
# of the catalogue to agree and every witness to reproduce every entry's
# check value.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/crcwitness}
mkdir -p "$OUT"
python3 -m pip install -q --no-deps --require-hashes --target "$OUT/py" \
    -r "$HERE/requirements.txt"
cp "$HERE/crc_python.py" "$OUT/crc_python.py"
for w in pycrc-bbb pycrc-bbf pycrc-tbl crccheck crcmod; do
    printf '#!/bin/sh\nexec python3 -I "%s/crc_python.py" %s "%s/py"\n' "$OUT" "$w" "$OUT" \
        > "$OUT/$w"
    chmod +x "$OUT/$w"
done

rm -rf "$OUT/rust_crc"
cp -r "$HERE/rust_crc" "$OUT/rust_crc"
(cd "$OUT/rust_crc" && cargo build -q --release --locked)
cp "$OUT/rust_crc/target/release/crc-witness" "$OUT/rust-crc"
# crc-catalog's source, where cargo unpacked it, for the catalogue.
src=$(cd "$OUT/rust_crc" && cargo metadata --format-version 1 --locked \
    | python3 -c 'import json, sys; print(next(p["manifest_path"] for p in json.load(sys.stdin)["packages"] if p["name"] == "crc-catalog"))')
mkdir -p "$OUT/src"
cp "$(dirname "$src")/src/algorithm.rs" "$OUT/src/crc-catalog-algorithm.rs"

python3 "$HERE/selftest.py" "$OUT"
echo "$OUT"
