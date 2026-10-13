#!/bin/sh
# Builds /opt/finalists: implementations of the SHA-3 finalists as their
# teams finally submitted them, fetched once from GitHub at pinned
# commits and checked against finalists.sha256 (the Go modules are
# cloned whole and pinned by commit).
#
# - sphlib 3.0 (pornin/sphlib): BLAKE, Grøstl and JH at 224, 256, 384
#   and 512 bits, and Skein-512 at those lengths, with driver_sph.c:
#   sph-witness.
# - The teams' own code as SUPERCOP carries it (floodyberry/supercop),
#   with the headers in supercop_shim: the BLAKE team's reference
#   (crypto_hash/blake256/ref and blake512/ref) with driver_ref.c,
#   ref-witness, which also has JH from the designer's bitsliced code
#   (round3jh256/simple and round3jh512/simple, the other two lengths
#   through jh_any.c); the Grøstl team's 32 bit code (groestl512/opt32,
#   every length through NIST's API) with driver_nist.c, groestl-witness;
#   the Skein team's code (skein512512/opt, which has all three widths at
#   any length) with driver_skein.c, skein-witness.
# - Bouncy Castle's SkeinDigest, any width and length, with
#   SkeinWitness.java against the bcprov jar the system ships (1.77 here;
#   BCPROV names another): bc-witness.
# - dchest/blake256 and dchest/blake512, pure Go, with go/driver.go and
#   the system's go, offline: go-witness.
#
# Before reporting success the three must agree on an empty and a random
# input at every size each has; scripts/make_finalist_vectors.py compares
# the rest.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/finalists}
SPHLIB=https://raw.githubusercontent.com/pornin/sphlib/15b6b8d8f3e4a43c58ba102d712fa6b8a3317035/c
SUPERCOP=https://raw.githubusercontent.com/floodyberry/supercop/a351f2c29235512a042d4b6989d241a67e86ad23/crypto_hash
mkdir -p "$OUT/src"
for f in $(cut -c67- "$HERE/finalists.sha256"); do
    case "$f" in
        sphlib/*) url=$SPHLIB/${f#sphlib/} ;;
        supercop/*) url=$SUPERCOP/${f#supercop/} ;;
    esac
    mkdir -p "$OUT/src/$(dirname "$f")"
    [ -f "$OUT/src/$f" ] || curl -sSfL -o "$OUT/src/$f" "$url"
done
(cd "$OUT/src" && sha256sum -c --quiet "$HERE/finalists.sha256")
clone() {
    if [ ! -d "$OUT/src/go/$1" ]; then
        git clone -q "https://github.com/dchest/$1" "$OUT/src/go/$1"
        git -C "$OUT/src/go/$1" checkout -q "$2"
    fi
    [ "$(git -C "$OUT/src/go/$1" rev-parse HEAD)" = "$2" ] || { echo "$1 is not at $2"; exit 1; }
}
clone blake256 4d634c0e4166989f1b2f405bdcc3176349fa3839
clone blake512 9668dfef2d239349500b23b60834fbf1817546fb

S=$OUT/src
SLURP=$HERE/../oldhashes
cc -O1 -w -I"$S/sphlib" -I"$SLURP" -o "$OUT/sph-witness" "$HERE/driver_sph.c" "$S/sphlib/blake.c" \
    "$S/sphlib/groestl.c" "$S/sphlib/jh.c" "$S/sphlib/skein.c"
cc -O1 -w -I"$S/supercop/skein512512/opt" -I"$SLURP" -o "$OUT/skein-witness" "$HERE/driver_skein.c" \
    "$S/supercop/skein512512/opt/skein.c" "$S/supercop/skein512512/opt/skein_block.c"
BCPROV=${BCPROV:-/usr/share/java/bcprov-1.77.jar}
mkdir -p "$OUT/java"
cp "$BCPROV" "$OUT/java/bcprov.jar"
javac -cp "$OUT/java/bcprov.jar" -d "$OUT/java" "$HERE/SkeinWitness.java"
printf '#!/bin/sh\nexec java -cp "%s/java/bcprov.jar:%s/java" SkeinWitness 2>/dev/null\n' "$OUT" "$OUT" \
    > "$OUT/bc-witness"
chmod +x "$OUT/bc-witness"
cc -O1 -w -DFAMILY='"groestl"' -I"$S/supercop/groestl512/opt32" -I"$HERE/supercop_shim" -I"$SLURP" \
    -o "$OUT/groestl-witness" "$HERE/driver_nist.c" "$S/supercop/groestl512/opt32/hash.c"
objects=
for impl in blake256:32 blake512:64; do
    word=${impl#*:}
    impl=${impl%:*}
    cc -O1 -w -c -I"$S/supercop/$impl/ref" -I"$HERE/supercop_shim" -Dcrypto_hash=${impl}_ref \
        -Dsigma=${impl}_sigma -Dcst=${impl}_cst -Dpadding=${impl}_padding \
        -DIMPL=$impl -DWORD=$word -o "$OUT/$impl-ref.o" "$HERE/ref_after.c"
    objects="$objects $OUT/$impl-ref.o"
done
cc -O1 -w -c -I"$S/supercop/round3jh256/simple" -I"$HERE/supercop_shim" -Dcrypto_hash=jh256_ref \
    -o "$OUT/jh256-ref.o" "$HERE/jh_any.c"
cc -O1 -w -c -I"$S/supercop/round3jh512/simple" -I"$HERE/supercop_shim" -Dcrypto_hash=jh512_ref \
    -Dc=jh512_c -Div=jh512_iv -DF8=jh512_F8 -o "$OUT/jh512-ref.o" "$S/supercop/round3jh512/simple/hash.c"
objects="$objects $OUT/jh256-ref.o $OUT/jh512-ref.o"
cc -O1 -w -I"$SLURP" -o "$OUT/ref-witness" "$HERE/driver_ref.c" $objects
mkdir -p "$OUT/go"
cp "$HERE/go/driver.go" "$OUT/go/"
cat > "$OUT/go/go.mod" <<EOF
module finalists

go 1.21

require (
	github.com/dchest/blake256 v0.0.0
	github.com/dchest/blake512 v0.0.0
)

replace github.com/dchest/blake256 => $S/go/blake256

replace github.com/dchest/blake512 => $S/go/blake512
EOF
for m in blake256 blake512; do
    [ -f "$S/go/$m/go.mod" ] || printf 'module github.com/dchest/%s\n\ngo 1.21\n' $m > "$S/go/$m/go.mod"
done
(cd "$OUT/go" && GOFLAGS=-mod=mod GOPROXY=off go build -o "$OUT/go-witness" .)

: > "$OUT/empty"
head -c 1000 /dev/urandom > "$OUT/random"
ask() { echo "$2 $OUT/$3" | "$OUT/$1-witness"; }
for f in empty random; do
    for name in blake224 blake256 blake384 blake512; do
        a=$(ask sph $name $f)
        [ -n "$a" ] && [ "$a" != error ] || { echo "sphlib failed on $name of $f"; exit 1; }
        [ "$(ask go $name $f)" = "$a" ] || { echo "Go and sphlib disagree on $name of $f"; exit 1; }
    done
    for name in jh224 jh256 jh384 jh512; do
        [ "$(ask ref $name $f)" = "$(ask sph $name $f)" ] || { echo "the JH code and sphlib disagree on $name of $f"; exit 1; }
    done
    for name in jh256 jh512; do
        [ "$(ask ref ${name}_derived $f)" = "$(ask ref $name $f)" ] || { echo "jh_any.c's $name starting value is not the file's"; exit 1; }
    done
    for name in skein256_256 skein512_256 skein1024_1024 skein512_1032; do
        a=$(ask skein $name $f)
        [ -n "$a" ] && [ "$a" != error ] || { echo "the Skein team's code failed on $name of $f"; exit 1; }
        [ "$(ask bc $name $f)" = "$a" ] || { echo "Bouncy Castle and the Skein team disagree on $name of $f"; exit 1; }
    done
    [ "$(ask sph skein512_256 $f)" = "$(ask skein skein512_256 $f)" ] || { echo "sphlib and the Skein team disagree on $f"; exit 1; }
    for name in groestl224 groestl256 groestl384 groestl512; do
        a=$(ask sph $name $f)
        [ -n "$a" ] && [ "$a" != error ] || { echo "sphlib failed on $name of $f"; exit 1; }
        [ "$(ask groestl $name $f)" = "$a" ] || { echo "the Grøstl team and sphlib disagree on $name of $f"; exit 1; }
    done
    for name in blake256 blake512 blake256_after_536870848 blake512_after_2305843009213693952; do
        [ "$(ask ref $name $f)" = "$(ask sph $name $f)" ] || { echo "the reference and sphlib disagree on $name of $f"; exit 1; }
    done
done
echo "$OUT"
