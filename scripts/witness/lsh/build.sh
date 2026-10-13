#!/bin/sh
# Builds /opt/lshwitness: three implementations of LSH (KS X 3262),
# fetched once from GitHub at pinned commits and checked against
# lsh.sha256 (go-krypto is cloned whole and pinned by commit).
#
# - KISA's reference C, no_arch (the distribution's ZIP, as
#   noloader/cryptopp-test keeps it unpacked), with driver_kisa.c:
#   kisa-witness. Any whole number of bytes up to the width.
# - Crypto++ 8.9.0's lsh256.cpp and lsh512.cpp with the library files
#   they link against, its SIMD code compiled out, with
#   driver_cryptopp.cpp: cryptopp-witness. Any length, through its base
#   classes.
# - RyuaNerin/go-krypto's pure Go LSH, built with the system's go,
#   offline and with the purego tag, with go/driver.go: go-witness. The
#   six sizes the standard names.
#
# Before reporting success the three must agree on an empty and a random
# input at the six named sizes, and the first two at two others;
# scripts/make_lsh_vectors.py compares the rest.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/lshwitness}
KISA=https://raw.githubusercontent.com/noloader/cryptopp-test/dea05da60fec57ba3ca72d9ac95d405e66f47f0b/lsh/source/c/no_arch
CRYPTOPP=https://raw.githubusercontent.com/weidai11/cryptopp/CRYPTOPP_8_9_0
GOKRYPTO=6e7566c4c44e0af11b5f3811c4c15925a9955d31
mkdir -p "$OUT/src"
for f in $(cut -c67- "$HERE/lsh.sha256"); do
    case "$f" in
        kisa/*) url=$KISA/${f#kisa/} ;;
        cryptopp/*) url=$CRYPTOPP/${f#cryptopp/} ;;
    esac
    mkdir -p "$OUT/src/$(dirname "$f")"
    [ -f "$OUT/src/$f" ] || curl -sSfL -o "$OUT/src/$f" "$url"
done
(cd "$OUT/src" && sha256sum -c --quiet "$HERE/lsh.sha256")
if [ ! -d "$OUT/src/go-krypto" ]; then
    git clone -q https://github.com/RyuaNerin/go-krypto "$OUT/src/go-krypto"
    git -C "$OUT/src/go-krypto" checkout -q "$GOKRYPTO"
fi
[ "$(git -C "$OUT/src/go-krypto" rev-parse HEAD)" = "$GOKRYPTO" ] || { echo "go-krypto is not at $GOKRYPTO"; exit 1; }

SLURP=$HERE/../oldhashes
K=$OUT/src/kisa
cc -O1 -w -I"$K/include" -I"$K/src" -I"$SLURP" -o "$OUT/kisa-witness" "$HERE/driver_kisa.c" \
    "$K/src/lsh.c" "$K/src/lsh256.c" "$K/src/lsh512.c"
C=$OUT/src/cryptopp
objects=
for f in algparam allocate cpu cryptlib filters fips140 lsh256 lsh512 misc mqueue queue; do
    c++ -O2 -DNDEBUG -DCRYPTOPP_DISABLE_ASM -w -I"$C" -c "$C/$f.cpp" -o "$OUT/$f.o"
    objects="$objects $OUT/$f.o"
done
c++ -O2 -DNDEBUG -DCRYPTOPP_DISABLE_ASM -w -I"$C" -I"$SLURP" -c "$HERE/driver_cryptopp.cpp" \
    -o "$OUT/driver_cryptopp.o"
c++ -o "$OUT/cryptopp-witness" "$OUT/driver_cryptopp.o" $objects
mkdir -p "$OUT/go"
cp "$HERE/go/driver.go" "$OUT/go/"
printf 'module lshwitness\n\ngo 1.21\n\nrequire github.com/RyuaNerin/go-krypto v0.0.0\n\nreplace github.com/RyuaNerin/go-krypto => %s\n' \
    "$OUT/src/go-krypto" > "$OUT/go/go.mod"
(cd "$OUT/go" && GOFLAGS=-mod=mod GOPROXY=off go build -tags purego -o "$OUT/go-witness" .)

: > "$OUT/empty"
head -c 1000 /dev/urandom > "$OUT/random"
ask() { echo "$2 $OUT/$3" | "$OUT/$1-witness"; }
for f in empty random; do
    for name in lsh256_224 lsh256_256 lsh512_224 lsh512_256 lsh512_384 lsh512_512 lsh256_8 lsh512_200; do
        a=$(ask kisa $name $f)
        [ -n "$a" ] && [ "$a" != error ] || { echo "KISA's reference failed on $name of $f"; exit 1; }
        [ "$(ask cryptopp $name $f)" = "$a" ] || { echo "Crypto++ and KISA disagree on $name of $f"; exit 1; }
        case $name in lsh256_8 | lsh512_200) continue ;; esac
        [ "$(ask go $name $f)" = "$a" ] || { echo "go-krypto and KISA disagree on $name of $f"; exit 1; }
    done
done
echo "$OUT"
