#!/bin/sh
# Builds /opt/grainaeadwitness: other implementations of Grain-128AEADv2,
# as witnesses for vectors/grain128aead.vec, and of Grain-128AEAD v1.
#
#   rweather-grain  Rhys Weatherley's lwc-finalists (rweather/lwc-finalists,
#                   77b23e6), src/combined/grain-aead.c, internal-grain128.c
#                   and internal-util.c, under rweather_grain.c. Its
#                   test/kat/Grain-128AEAD.txt is the NIST final round's
#                   known-answer file, which selftest.py and the generator
#                   read.
#   rust-grain      The grain-128aeadv2 0.1.2 crate, under rust_grain/.
#                   cargo fetches it, pinned with its checksum by
#                   rust_grain/Cargo.lock.
#   bc-grain        Bouncy Castle 1.77's Grain128AEADEngine, from the jar
#                   the system ships, under GrainAeadWitness.java.
#                   Encryption only: 1.77's engine does not decrypt (its
#                   decryption mode treats the tag as ciphertext and checks
#                   nothing), and it writes the length of associated data
#                   of 256 bytes or more little endian. Both are fixed in
#                   1.81.
#
# And of Grain-128AEAD as it stood before the round 3 tweak, for
# vectors/grain128aead_v1.vec, each under grain_v1_driver.c through the
# NIST LWC interface:
#
#   ref-grain-v1       The designers' reference implementation
#                      (grain-128aead/grain-128aead, 94765ed),
#                      NIST/ref/grain128aead.c, one bit per array cell.
#                      Its NIST/ref/LWC_AEAD_KAT_128_96.txt is the
#                      designers' known-answer file, which selftest.py and
#                      the generator read.
#   opt-grain-v1       The designers' optimised implementation from the
#                      same commit, NIST/optimized/grain128aead_32p.c, 32
#                      clocks at a time.
#   rweather-grain-v1  Rhys Weatherley's round 2 lightweight-crypto
#                      (rweather/lightweight-crypto, fa4ec9a),
#                      src/combined/grain128.c and internal-grain128.c.
#
# Requests are the lines rweather_grain.c describes. selftest.py then
# requires every witness to reproduce the known-answer file and the
# witnesses to agree, Bouncy Castle only where its length bytes read the
# same either way and required to disagree everywhere else.
#
# CFLAGS_EXTRA goes to the C compile - "-fsanitize=address,undefined -g
# -DOFFSET=1" for a sanitizer run over misaligned buffers.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/grainaeadwitness}
JAR=${2:-/usr/share/java/bcprov-1.77.jar}
CFLAGS_EXTRA=${CFLAGS_EXTRA:-}
mkdir -p "$OUT/src"

fetch() {  # fetch DIR URL COMMIT
    if [ ! -d "$OUT/src/$1" ]; then
        git init -q "$OUT/src/$1"
        git -C "$OUT/src/$1" fetch -q --depth 1 "$2" "$3"
        git -C "$OUT/src/$1" checkout -q FETCH_HEAD
    fi
    [ "$(git -C "$OUT/src/$1" rev-parse HEAD)" = "$3" ] || { echo "$1 is not at $3"; exit 1; }
}
fetch lwc-finalists https://github.com/rweather/lwc-finalists \
    77b23e672543df736bdcc8577590e8957fe0c58c

fetch grain-128aead https://github.com/grain-128aead/grain-128aead \
    94765ed6433338a47d46eb19283c6bd7aebbda97
fetch lightweight-crypto https://github.com/rweather/lightweight-crypto \
    fa4ec9a021b9233263de77e7dd971de8c9761495

RW="$OUT/src/lwc-finalists/src/combined"
cc -O2 -Wall $CFLAGS_EXTRA -I"$RW" -o "$OUT/rweather-grain" "$HERE/rweather_grain.c" \
    "$RW/grain-aead.c" "$RW/internal-grain128.c" "$RW/internal-util.c"

G1="$OUT/src/grain-128aead/NIST"
cc -O2 $CFLAGS_EXTRA -I"$G1/ref" -o "$OUT/ref-grain-v1" "$HERE/grain_v1_driver.c" \
    "$G1/ref/grain128aead.c"
cc -O2 $CFLAGS_EXTRA -I"$G1/optimized" -o "$OUT/opt-grain-v1" "$HERE/grain_v1_driver.c" \
    "$G1/optimized/grain128aead_32p.c"
LC="$OUT/src/lightweight-crypto/src/combined"
cc -O2 -Wall $CFLAGS_EXTRA -DRWEATHER -I"$LC" -o "$OUT/rweather-grain-v1" \
    "$HERE/grain_v1_driver.c" "$LC/grain128.c" "$LC/internal-grain128.c" "$LC/aead-common.c"

rm -rf "$OUT/rust_grain"
cp -r "$HERE/rust_grain" "$OUT/rust_grain"
(cd "$OUT/rust_grain" && cargo build -q --release --locked)
cp "$OUT/rust_grain/target/release/grain-witness" "$OUT/rust-grain"

mkdir -p "$OUT/java"
javac -cp "$JAR" -d "$OUT/java" "$HERE/GrainAeadWitness.java"
printf '#!/bin/sh\nexec java -cp "%s:%s" GrainAeadWitness\n' "$JAR" "$OUT/java" > "$OUT/bc-grain"
chmod +x "$OUT/bc-grain"

python3 "$HERE/selftest.py" "$OUT"
echo "$OUT"
