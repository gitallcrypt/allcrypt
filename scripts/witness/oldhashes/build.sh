#!/bin/sh
# Builds /opt/oldhashes: four C and C++ implementations of Tiger, HAVAL
# and Snefru, fetched once from GitHub at pinned commits and checked
# against oldhashes.sha256 (mhash is cloned whole and pinned by commit,
# because it has to be configured).
#
# - sphlib 3.0 (pornin/sphlib): Tiger, Tiger2 and the fifteen HAVALs,
#   with driver_sph.c: sph-witness.
# - RHash 1.4.6 (rhash/RHash, librhash): Tiger, Tiger2, Snefru-128 and
#   Snefru-256, with driver_rhash.c: rhash-witness.
# - mhash 0.9.9 (as vendored by Sembiance/mhash): the fifteen HAVALs,
#   Snefru-128 and Snefru-256, with driver_mhash.c: mhash-witness. Its
#   Tiger too, which writes each 64 bit word of the digest big endian.
# - Botan 1.10.17 (randombit/botan): Tiger at any length and pass count,
#   with driver_botan.cpp: botan-witness. Only src/hash/tiger and
#   src/hash/mdx_hash are fetched, and botan_shim stands in for the rest
#   of Botan's headers.
#
# PHP's ext/hash is the fifth, through driver.php and the system's php.
#
# Before reporting success every witness that has Tiger must agree with
# the others on an empty and a random input, and likewise for HAVAL-256 at
# five passes and Snefru-256; scripts/make_tiger_haval_snefru_vectors.py
# compares the rest.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/oldhashes}
SPHLIB=https://raw.githubusercontent.com/pornin/sphlib/15b6b8d8f3e4a43c58ba102d712fa6b8a3317035/c
RHASH=https://raw.githubusercontent.com/rhash/RHash/6562de382954d9893442b89b0e8b5c513eea6a88/librhash
BOTAN=https://raw.githubusercontent.com/randombit/botan/f7fe6beb5b3b6f944aa7bac491a3455e48ef6ebb/src/hash
MHASH=https://github.com/Sembiance/mhash
MHASH_COMMIT=f4f4ed092ac9272829aa40a27a4761efac4d88b7
mkdir -p "$OUT/src"
for f in $(cut -c67- "$HERE/oldhashes.sha256"); do
    case "$f" in
        sphlib/*) url=$SPHLIB/${f#sphlib/} ;;
        rhash/*) url=$RHASH/${f#rhash/} ;;
        botan/tiger.* | botan/tig_tab.cpp) url=$BOTAN/tiger/${f#botan/} ;;
        botan/mdx_hash.*) url=$BOTAN/mdx_hash/${f#botan/} ;;
    esac
    mkdir -p "$OUT/src/$(dirname "$f")"
    [ -f "$OUT/src/$f" ] || curl -sSfL -o "$OUT/src/$f" "$url"
done
(cd "$OUT/src" && sha256sum -c --quiet "$HERE/oldhashes.sha256")
if [ ! -d "$OUT/src/mhash" ]; then
    git clone -q "$MHASH" "$OUT/src/mhash"
    git -C "$OUT/src/mhash" checkout -q "$MHASH_COMMIT"
fi
[ "$(git -C "$OUT/src/mhash" rev-parse HEAD)" = "$MHASH_COMMIT" ] || { echo "mhash is not at $MHASH_COMMIT"; exit 1; }

S=$OUT/src
cc -O1 -w -I"$S/sphlib" -I"$HERE" -o "$OUT/sph-witness" "$HERE/driver_sph.c" \
    "$S/sphlib/tiger.c" "$S/sphlib/haval.c"
cc -O1 -w -I"$S/rhash" -I"$HERE" -o "$OUT/rhash-witness" "$HERE/driver_rhash.c" \
    "$S/rhash/tiger.c" "$S/rhash/tiger_sbox.c" "$S/rhash/snefru.c" "$S/rhash/byte_order.c"
M=$S/mhash/deps/mhash
if [ ! -f "$M/lib/.libs/libmhash.a" ]; then
    (cd "$M" && ./configure -q --disable-shared > /dev/null && make -s -C lib > /dev/null 2>&1)
fi
cc -O1 -w -I"$M/include" -I"$M/include/mutils" -I"$M/lib" -I"$M" -I"$HERE" -o "$OUT/mhash-witness" \
    "$HERE/driver_mhash.c" "$M/lib/.libs/libmhash.a"
mkdir -p "$S/botan-include/botan"
cp "$S/botan/tiger.h" "$S/botan/mdx_hash.h" "$S/botan-include/botan/"
c++ -O1 -w -std=c++11 -I"$S/botan-include" -I"$HERE/botan_shim" -I"$HERE" -o "$OUT/botan-witness" \
    "$HERE/driver_botan.cpp" "$S/botan/tiger.cpp" "$S/botan/tig_tab.cpp" "$S/botan/mdx_hash.cpp"
cp "$HERE/driver.php" "$OUT/"

: > "$OUT/empty"
head -c 1000 /dev/urandom > "$OUT/random"
ask() { echo "$2 $OUT/$3" | "$OUT/$1-witness"; }
for f in empty random; do
    t=$(ask sph tiger "$f")
    [ -n "$t" ] && [ "$t" != error ] || { echo "sphlib failed on $f"; exit 1; }
    [ "$(ask rhash tiger "$f")" = "$t" ] || { echo "RHash and sphlib disagree on Tiger of $f"; exit 1; }
    [ "$(ask botan tiger192_3 "$f")" = "$t" ] || { echo "Botan and sphlib disagree on Tiger of $f"; exit 1; }
    [ "$(echo "tiger192_3 $OUT/$f" | php "$OUT/driver.php")" = "$t" ] || { echo "PHP and sphlib disagree on Tiger of $f"; exit 1; }
    [ "$(ask rhash tiger2 "$f")" = "$(ask sph tiger2 "$f")" ] || { echo "RHash and sphlib disagree on Tiger2 of $f"; exit 1; }
    h=$(ask sph haval256_5 "$f")
    [ "$(ask mhash haval256_5 "$f")" = "$h" ] || { echo "mhash and sphlib disagree on HAVAL of $f"; exit 1; }
    [ "$(echo "haval256_5 $OUT/$f" | php "$OUT/driver.php")" = "$h" ] || { echo "PHP and sphlib disagree on HAVAL of $f"; exit 1; }
    s=$(ask rhash snefru256 "$f")
    [ "$(ask mhash snefru256 "$f")" = "$s" ] || { echo "mhash and RHash disagree on Snefru of $f"; exit 1; }
    [ "$(echo "snefru256 $OUT/$f" | php "$OUT/driver.php")" = "$s" ] || { echo "PHP and RHash disagree on Snefru of $f"; exit 1; }
done
echo "$OUT"
