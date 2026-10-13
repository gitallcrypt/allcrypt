#!/bin/sh
# Builds /opt/dstuengine: dstu-engine, an OpenSSL engine for the
# Ukrainian standards with a library (keylib) that opens IIT's Key-6.dat,
# PKCS#12 and JKS key containers, and driver.c over keylib and the
# engine's certificate signatures. The 44 source files come from its
# GitHub repository, each checked against dstuengine.sha256, and build
# against the system's OpenSSL, which must have binary-field curves
# (OpenSSL 3.0 has). The engine is dstu.so; the driver loads it from
# DSTU_ENGINE.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/dstuengine}
BASE=https://raw.githubusercontent.com/dstucrypt/dstu-engine/main
mkdir -p "$OUT/src" "$OUT/obj"
cd "$OUT/src"
for f in $(cut -c67- "$HERE/dstuengine.sha256"); do
    mkdir -p "$(dirname "$f")"
    curl -sSfL -o "$f" "$BASE/$f"
done
sha256sum -c --quiet "$HERE/dstuengine.sha256"
for f in dstulib/*.c dstulib/gost/*.c engine/*.c keylib/*.c; do
    cc -c -fPIC -O1 -w -Idstulib -Iengine -Ikeylib -o "$OUT/obj/$(basename "$f" .c).o" "$f"
done
cd "$OUT/obj"
LIB="key.o asn1.o compress.o params.o gost89.o gosthash.o"
cc -shared -o "$OUT/dstu.so" dstu.o md.o cipher.o rbg.o pmeth.o ameth.o sign.o err.o $LIB \
    -lcrypto
cc -O1 -w -I"$OUT/src/dstulib" -I"$OUT/src/keylib" -o "$OUT/dstuengine-witness" \
    "$HERE/driver.c" key6.o iit_asn1.o jks.o pkcs12.o keystore.o utils.o \
    attrcurvespec_asn1.o $LIB -lcrypto
echo "$OUT"
