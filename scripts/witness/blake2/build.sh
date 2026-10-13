#!/bin/sh
# Builds /opt/blake2witness: driver.c against OpenSSL 3.5 (/opt/openssl35,
# built as docs/building.md says), whose BLAKE2B-512 and BLAKE2S-256 take
# an output length through the "size" parameter - OpenSSL 3.0's do not.
# Before reporting success the driver must agree with hashlib on "abc"
# at the full lengths; scripts/make_blake2_vectors.py compares the rest.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/blake2witness}
OPENSSL=${OPENSSL35:-/opt/openssl35}
mkdir -p "$OUT"
cc -O1 -w -I"$OPENSSL/include" -o "$OUT/blake2-witness" "$HERE/driver.c" \
    -L"$OPENSSL/lib" -Wl,-rpath,"$OPENSSL/lib" -lcrypto
got=$(printf 'blake2b 64 616263\nblake2s 32 616263\n' | "$OUT/blake2-witness")
want=$(python3 -I -c 'import hashlib; print(hashlib.blake2b(b"abc").hexdigest()); print(hashlib.blake2s(b"abc").hexdigest())')
[ "$got" = "$want" ] || { echo "the driver and hashlib disagree on abc"; exit 1; }
echo "$OUT"
