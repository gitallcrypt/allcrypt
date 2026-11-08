#!/bin/sh
# Builds /opt/xmsswitness: other implementations of XMSS and XMSS^MT
# (RFC 8391, SP 800-208), as witnesses for vectors/xmss.vec.
#
#   ref-xmss    The XMSS reference implementation by the RFC's authors
#               (XMSS/xmss-reference 171ccbd), which derives WOTS+ keys
#               as SP 800-208 requires, its plain xmss_core.c, under
#               ref_driver.c, against OpenSSL's SHA-2. Every parameter
#               set; signs and verifies.
#   botan-xmss  Botan 3.6.1 (randombit/botan, the 3.6.1 tag, d1ad41e),
#               a minimal static build with its xmss module, under
#               botan_driver.cpp, with SP 800-208's derivation. XMSS
#               only - Botan has no XMSS^MT; signs and verifies.
#   bc-xmss     Bouncy Castle 1.77's XMSS and XMSS^MT, from the jar the
#               system ships, under XmssWitness.java. RFC 8391's sets
#               only. It derives WOTS+ keys as RFC 8391 suggests, so it
#               signs `sign-rfc8391` requests - other keys from the same
#               seeds - and verifies.
#
# The reference's files are fetched from raw.githubusercontent.com by
# commit and checked against xmss-reference.sha256; Botan is cloned at its
# tag and the commit checked. selftest.py then holds the witnesses to the
# reference implementation's answers Botan's tests carry, vendored in
# vectors/botan_xmss/.
#
# CFLAGS_EXTRA goes to the reference's C compile - "-fsanitize=address,
# undefined -g" for a sanitizer run.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/xmsswitness}
JAR=${2:-/usr/share/java/bcprov-1.77.jar}
CFLAGS_EXTRA=${CFLAGS_EXTRA:-}
mkdir -p "$OUT/src/xmss-reference"

REF=https://raw.githubusercontent.com/XMSS/xmss-reference/171ccbd26f098542a67eb5d2b128281c80bd71a6
while read -r sum name; do
    f="$OUT/src/xmss-reference/$name"
    [ -f "$f" ] || curl -sSf -o "$f" "$REF/$name"
    echo "$sum  $f" | sha256sum -c --quiet -
done < "$HERE/xmss-reference.sha256"
(cd "$OUT/src/xmss-reference" && cc -O2 $CFLAGS_EXTRA -Wno-deprecated-declarations -I. \
    -o "$OUT/ref-xmss" "$HERE/ref_driver.c" \
    $(grep '\.c$' "$HERE/xmss-reference.sha256" | awk '{print $2}') -lcrypto)

if [ ! -f "$OUT/src/botan/libbotan-3.a" ]; then
    rm -rf "$OUT/src/botan"
    git clone -q --depth 1 --branch 3.6.1 https://github.com/randombit/botan.git \
        "$OUT/src/botan"
    [ "$(git -C "$OUT/src/botan" rev-parse HEAD)" = d1ad41eef0d7039f79ac89d180f0d697936b09f1 ]
    (cd "$OUT/src/botan" && ./configure.py --minimized-build \
        --enable-modules=xmss,sha2_32,sha2_64,shake,system_rng \
        --disable-shared-library --without-documentation > /dev/null &&
     make -j"$(nproc)" libs > /dev/null)
fi
c++ -std=c++20 -O2 -I"$OUT/src/botan/build/include/public" -o "$OUT/botan-xmss" \
    "$HERE/botan_driver.cpp" "$OUT/src/botan/libbotan-3.a" -lpthread

mkdir -p "$OUT/bc"
javac -nowarn -Xlint:none -d "$OUT/bc" -cp "$JAR" "$HERE/XmssWitness.java"
printf '#!/bin/sh\nexec java -cp "%s/bc:%s" XmssWitness 2>/dev/null\n' "$OUT" "$JAR" > "$OUT/bc-xmss"
chmod +x "$OUT/bc-xmss"

python3 "$HERE/selftest.py" "$OUT"
echo "$OUT"
