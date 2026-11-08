#!/bin/sh
# Builds /opt/isaacwitness: other implementations of ISAAC and ISAAC-64, as
# witnesses for vectors/isaac.vec.
#
#   ref-isaac        Bob Jenkins's rand.c, its portable version randport.c
#                    (1998), with rand.h and standard.h, as Rust 0.4
#                    vendored them (rust-lang/rust 39c0d35, src/rt/isaac/),
#                    under ref_isaac.c. ISAAC.
#   ref-isaac64      Jenkins's isaac64.c as Math::Int64 folds it into one
#                    header (salva/p5-Math-Int64 ce24e0d, isaac64.h), under
#                    ref_isaac64.c. ISAAC-64.
#   coreutils-isaac  coreutils's gl/lib/rand-isaac.c and rand-isaac.h
#   coreutils-isaac64  (coreutils/coreutils 37f0450), Colin Plumb's and
#                    Paul Eggert's rewrite, compiled once with
#                    ISAAC_BITS_LOG=5 and once with 6, under
#                    coreutils_isaac.c.
#   rust-isaac       The rand_isaac 0.3.0 crate, ISAAC and ISAAC-64, under
#                    rust_isaac/. cargo fetches it, pinned with its checksum
#                    by rust_isaac/Cargo.lock.
#   bc-isaac         Bouncy Castle 1.77's ISAACEngine, from the jar the
#                    system ships, under IsaacWitness.java. ISAAC, from
#                    block 1.
#
# The C sources are fetched from raw.githubusercontent.com by commit and
# checked against their SHA-256. Requests are the lines driver.h
# describes. selftest.py then requires the published values each witness
# can be checked against, and every witness to agree over random keys.
#
# CFLAGS_EXTRA goes to every C compile - "-fsanitize=address,undefined -g"
# for a sanitizer run.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/isaacwitness}
JAR=${2:-/usr/share/java/bcprov-1.77.jar}
CFLAGS_EXTRA=${CFLAGS_EXTRA:-}
mkdir -p "$OUT/src"

get() {  # get DIR URL SHA256 NAME
    mkdir -p "$OUT/src/$1"
    [ -f "$OUT/src/$1/$4" ] || curl -sSf -o "$OUT/src/$1/$4" "$2"
    echo "$3  $OUT/src/$1/$4" | sha256sum -c --quiet -
}
RUST=https://raw.githubusercontent.com/rust-lang/rust/39c0d3591e0326874b7263a621ce09ecd64f0eb2/src/rt/isaac
get jenkins "$RUST/randport.cpp" \
    a1c1465c57d01a6d62787d9ab08b02b2f273e9726b376cc7ba7ce3cce3be128a randport.c
get jenkins "$RUST/rand.h" \
    63eb6d8522b999a1afcb4a5366fb055f9eb99d18bbf03508b931e7ce8865551c rand.h
get jenkins "$RUST/standard.h" \
    11072596f760c0476dc629bd44b1cea833ab3ee129e6b6f76cf3317af1309760 standard.h
get math-int64 \
    https://raw.githubusercontent.com/salva/p5-Math-Int64/ce24e0d34f721cb528b4adfab5fe1ccd4b21872b/isaac64.h \
    4c0a7f8f4e0d67a277d05766225445a4594225849afae3b39827d5bd04f6a3b9 isaac64.h
CU=https://raw.githubusercontent.com/coreutils/coreutils/37f04509c999ae4c9043cb797b4fe3932f29d9a1/gl/lib
get coreutils "$CU/rand-isaac.c" \
    52cfd817dd887d25f81d7aef0b82a49b8a9c2f6e87c91af686c1ad472ba0c5c9 rand-isaac.c
get coreutils "$CU/rand-isaac.h" \
    0bc5bf0bff3ad40d7fba828d6486093303384a19e4ee3be8989736f86ef93474 rand-isaac.h
# rand-isaac.c includes gnulib's config.h; of it, rand-isaac.h needs one
# attribute macro.
printf '#define _GL_ATTRIBUTE_NONNULL(args) __attribute__ ((__nonnull__ args))\n' \
    > "$OUT/src/coreutils/config.h"

CC="cc -O2 -Wall $CFLAGS_EXTRA"
$CC -I"$HERE" -I"$OUT/src/jenkins" -o "$OUT/ref-isaac" "$HERE/ref_isaac.c"
$CC -I"$HERE" -I"$OUT/src/math-int64" -o "$OUT/ref-isaac64" "$HERE/ref_isaac64.c"
for log in 5 6; do
    bits=$((1 << log))
    name=coreutils-isaac; [ $bits = 64 ] && name=coreutils-isaac64
    $CC -DISAAC_BITS_LOG=$log -I"$HERE" -I"$OUT/src/coreutils" -o "$OUT/$name" \
        "$HERE/coreutils_isaac.c" "$OUT/src/coreutils/rand-isaac.c"
done

rm -rf "$OUT/rust_isaac"
cp -r "$HERE/rust_isaac" "$OUT/rust_isaac"
(cd "$OUT/rust_isaac" && cargo build -q --release --locked)
cp "$OUT/rust_isaac/target/release/isaac-witness" "$OUT/rust-isaac"

mkdir -p "$OUT/java"
javac -cp "$JAR" -d "$OUT/java" "$HERE/IsaacWitness.java"
printf '#!/bin/sh\nexec java -cp "%s:%s" IsaacWitness\n' "$JAR" "$OUT/java" > "$OUT/bc-isaac"
chmod +x "$OUT/bc-isaac"

python3 "$HERE/selftest.py" "$OUT"
echo "$OUT"
