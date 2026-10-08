#!/bin/sh
# Builds /opt/dualecwitness/dualec: OpenSSL FIPS module 2.0.5's
# fips_drbg_ec.c, fetched unchanged from the tag, against OpenSSL 1.0.2's
# libcrypto (/opt/openssl102) through the stand-in headers in shim/.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/dualecwitness}
mkdir -p "$OUT"
curl -sSf -o "$OUT/fips_drbg_ec.c" \
    https://raw.githubusercontent.com/openssl/openssl/OpenSSL-fips-2_0_5/fips/rand/fips_drbg_ec.c
cc -O2 -std=gnu11 -w -I"$HERE/shim" -I/opt/openssl102/include \
    -o "$OUT/dualec" "$HERE/main.c" "$OUT/fips_drbg_ec.c" \
    /opt/openssl102/lib/libcrypto.a -ldl -lpthread
echo "$OUT/dualec"
