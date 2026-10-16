#!/bin/sh
# Builds /opt/widemac: three implementations of CMAC and EAX over the
# block ciphers wider than 128 bits, and the sources
# scripts/make_cmac_polynomials.py reads.
#
#   cryptopp/  Crypto++ 8.9.0 (weidai11/cryptopp, tag CRYPTOPP_8_9_0),
#              built whole as libcryptopp.a, under cryptopp_driver.cpp:
#              Threefish-256, -512 and -1024, SHACAL-2, and Kalyna with
#              256 and 512 bit blocks. cmac.cpp has its doubling
#              constants for 64 to 1024 bit blocks.
#   botan/     Botan 3.6.1 (randombit/botan, tag 3.6.1), a minimized
#              static build of CMAC, EAX, Threefish-512 and SHACAL-2,
#              under botan_driver.cpp. utils/poly_dbl/poly_dbl.cpp has its
#              polynomials, and src/tests/data its published CMAC and EAX
#              tests over Threefish-512.
#   bc/        Bouncy Castle 1.77's CMac.java and EAXBlockCipher.java
#              (bcgit/bc-java, tag r1rv77), for its polynomial table; the
#              engines run from the bcprov jar the system ships (1.77
#              here; BCPROV names another), under WideMacWitness.java:
#              everything above, and Rijndael with 160 to 256 bit blocks.
#
# Each source is a shallow clone pinned by its commit. Requests, one per
# line, are `cmac <cipher> <key> <message>` and `eax <cipher> <key>
# <nonce> <ad> <plaintext>`, hex with "-" for empty; see
# cryptopp_driver.cpp. Before reporting success every witness that has
# Threefish-512 must reproduce Botan's published CMAC and EAX tests, and
# the three must agree on SHACAL-2.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/widemac}
mkdir -p "$OUT/src"

fetch() {  # fetch DIR URL TAG COMMIT [SPARSE PATHS...]
    dir=$1 url=$2 tag=$3 commit=$4
    shift 4
    if [ ! -d "$OUT/src/$dir" ]; then
        if [ $# -gt 0 ]; then
            git clone -q --depth 1 --branch "$tag" --filter=blob:none --sparse "$url" "$OUT/src/$dir"
            git -C "$OUT/src/$dir" sparse-checkout set "$@"
        else
            git clone -q --depth 1 --branch "$tag" "$url" "$OUT/src/$dir"
        fi
    fi
    [ "$(git -C "$OUT/src/$dir" rev-parse HEAD)" = "$commit" ] || {
        echo "$dir is not at $commit"; exit 1; }
}
fetch cryptopp https://github.com/weidai11/cryptopp CRYPTOPP_8_9_0 \
    843d74c7c97f9e19a615b8ff3c0ca06599ca501b
fetch botan https://github.com/randombit/botan 3.6.1 \
    d1ad41eef0d7039f79ac89d180f0d697936b09f1
fetch bc https://github.com/bcgit/bc-java r1rv77 \
    f1367f0b89962b29460eea381a12063fa7cd2428 \
    core/src/main/java/org/bouncycastle/crypto/macs \
    core/src/main/java/org/bouncycastle/crypto/modes

JOBS=$(nproc 2>/dev/null || echo 2)
[ -f "$OUT/src/cryptopp/libcryptopp.a" ] || make -C "$OUT/src/cryptopp" -j"$JOBS" static >/dev/null
c++ -O1 -std=c++17 -I"$OUT/src/cryptopp" -o "$OUT/cryptopp-witness" \
    "$HERE/cryptopp_driver.cpp" "$OUT/src/cryptopp/libcryptopp.a"

if [ ! -f "$OUT/src/botan/libbotan-3.a" ]; then
    (cd "$OUT/src/botan" &&
     python3 configure.py --minimized-build \
         --enable-modules=cmac,eax,threefish_512,shacal2,ctr,hex \
         --disable-shared-library --without-documentation \
         --build-targets=static >/dev/null &&
     make -j"$JOBS" libs >/dev/null)
fi
c++ -O1 -std=c++20 -I"$OUT/src/botan/build/include/public" -o "$OUT/botan-witness" \
    "$HERE/botan_driver.cpp" "$OUT/src/botan/libbotan-3.a"

BCPROV=${BCPROV:-/usr/share/java/bcprov-1.77.jar}
mkdir -p "$OUT/java"
cp "$BCPROV" "$OUT/java/bcprov.jar"
javac -cp "$OUT/java/bcprov.jar" -d "$OUT/java" "$HERE/WideMacWitness.java"
printf '#!/bin/sh\nexec java -cp "%s/java/bcprov.jar:%s/java" WideMacWitness 2>/dev/null\n' "$OUT" "$OUT" \
    > "$OUT/bc-witness"
chmod +x "$OUT/bc-witness"

python3 "$HERE/selftest.py" "$OUT"
echo "$OUT"
