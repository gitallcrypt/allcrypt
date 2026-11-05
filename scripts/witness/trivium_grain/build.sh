#!/bin/sh
# Builds /opt/hwwitness: other implementations of the eSTREAM
# hardware-profile ciphers Trivium, Grain v1 and Grain-128, as witnesses
# for vectors/trivium_grain.vec.
#
#   ref-trivium   The eSTREAM submission, De Cannière's trivium.c, as
#                 SUPERCOP carries it (floodyberry/supercop, a351f2c),
#                 under ../estream/ecrypt_driver.c. IVs of 4, 6, 8 and 10
#                 bytes.
#   go-trivium    pedroalbanese/trivium (3bc0ea4), Go, written from the
#                 specification's bit order; go_trivium/main.go converts.
#   ref-grainv1   The Grain v1 reference implementation, Hell's grain.c,
#                 as fanajib5/grain-v1-stream-cipher carries it (80f3828),
#                 cut at the main() that copy appends, under
#                 grain_ref_driver.c.
#   gstream-grainv1  Deian Stefan's word-wide Grain v1 from gSTREAM
#                 (deian/gSTREAM, 14a24b5, grain/optimized), under
#                 ../estream/ecrypt_driver.c.
#   bc-hw         Bouncy Castle 1.77's Grainv1Engine and Grain128Engine,
#                 from the jar the system ships, under HwStreamWitness.java.
#                 Bouncy Castle 1.86 changed Grain128Engine's output
#                 function to Grain-128a's and is not a witness for
#                 Grain-128 (docs/pitfalls.md, "Grain-128 is not
#                 Grain-128a").
#   rust-hw       The trivium 0.1.0 and grain128 0.1.0 crates - the second
#                 a port of the Grain-128 reference - under rust_hw/, from
#                 crates checked against crates.sha256 and built offline
#                 from a directory source.
#
# Requests, one per line, are `stream <cipher> <key hex> <iv hex>
# <length>`; ciphers trivium, grainv1 and grain128. The answer is the first
# <length> bytes of keystream in hex, or "error ...". selftest.py then
# requires every witness to reproduce the eSTREAM vectors in
# vectors/estream/ and the witnesses to agree.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/hwwitness}
JAR=${2:-/usr/share/java/bcprov-1.77.jar}
mkdir -p "$OUT/src"

fetch() {  # fetch DIR URL COMMIT
    if [ ! -d "$OUT/src/$1" ]; then
        git clone -q "$2" "$OUT/src/$1"
        git -C "$OUT/src/$1" checkout -q "$3"
    fi
    [ "$(git -C "$OUT/src/$1" rev-parse HEAD)" = "$3" ] || { echo "$1 is not at $3"; exit 1; }
}
fetch pedroalbanese-trivium https://github.com/pedroalbanese/trivium \
    3bc0ea456f6340d30db4adc248e73ba5c3a1a7a0
fetch fanajib5-grain https://github.com/fanajib5/grain-v1-stream-cipher \
    80f3828492798cda6126d5d4a8a13ebefebc6f84
fetch deian-gSTREAM https://github.com/deian/gSTREAM \
    14a24b5c2a4de36827a6a7af18c7ce1d68bb3649
SUPERCOP_COMMIT=a351f2c29235512a042d4b6989d241a67e86ad23
if [ ! -d "$OUT/src/supercop" ]; then
    git clone -q --filter=blob:none --sparse https://github.com/floodyberry/supercop \
        "$OUT/src/supercop"
    git -C "$OUT/src/supercop" sparse-checkout set crypto_stream/trivium include
    git -C "$OUT/src/supercop" checkout -q "$SUPERCOP_COMMIT"
fi
[ "$(git -C "$OUT/src/supercop" rev-parse HEAD)" = "$SUPERCOP_COMMIT" ] \
    || { echo "supercop is not at $SUPERCOP_COMMIT"; exit 1; }

CFLAGS_EXTRA=${CFLAGS_EXTRA:-}
DRIVER="$HERE/../estream/ecrypt_driver.c"

T="$OUT/src/supercop/crypto_stream/trivium/e/submissions/trivium/e"
cc -O1 -w $CFLAGS_EXTRA -DCIPHER='"trivium"' -I"$T" -I"$OUT/src/supercop/include" \
    -o "$OUT/ref-trivium" "$DRIVER" "$T"/*.c

G="$OUT/src/deian-gSTREAM/grain/optimized"
cc -O1 -w $CFLAGS_EXTRA -DCIPHER='"grainv1"' -I"$G" -o "$OUT/gstream-grainv1" \
    "$DRIVER" "$G/grain.c"

mkdir -p "$OUT/src/grain-ref"
sed '/^int main(/,$d' "$OUT/src/fanajib5-grain/Grain v1/grain.c" > "$OUT/src/grain-ref/grain_cipher.c"
cp "$OUT/src/fanajib5-grain/Grain v1/grain.h" "$OUT/src/grain-ref/grain.h"
cc -O1 -w $CFLAGS_EXTRA -I"$OUT/src/grain-ref" -o "$OUT/ref-grainv1" "$HERE/grain_ref_driver.c"

rm -rf "$OUT/go_trivium"
mkdir -p "$OUT/go_trivium/trivium"
cp "$HERE/go_trivium/main.go" "$OUT/go_trivium/main.go"
cp "$OUT/src/pedroalbanese-trivium/trivium.go" "$OUT/go_trivium/trivium/trivium.go"
printf 'module hwwitness\n\ngo 1.21\n' > "$OUT/go_trivium/go.mod"
(cd "$OUT/go_trivium" && go build -o "$OUT/go-trivium" .)

cp "$JAR" "$OUT/bcprov.jar"
mkdir -p "$OUT/java"
javac -cp "$OUT/bcprov.jar" -d "$OUT/java" "$HERE/HwStreamWitness.java"
printf '#!/bin/sh\nexec java -cp "%s/bcprov.jar:%s/java" HwStreamWitness\n' "$OUT" "$OUT" > "$OUT/bc-hw"
chmod +x "$OUT/bc-hw"

mkdir -p "$OUT/crates" "$OUT/vendor"
while read -r sum file; do
    [ -f "$OUT/crates/$file" ] || curl -sf -o "$OUT/crates/$file" \
        "https://static.crates.io/crates/${file%-[0-9]*}/$file"
    echo "$sum  $OUT/crates/$file" | sha256sum -c --quiet -
    name=${file%.crate}
    if [ ! -d "$OUT/vendor/$name" ]; then
        tar xzf "$OUT/crates/$file" -C "$OUT/vendor"
        printf '{"files":{},"package":"%s"}\n' "$sum" > "$OUT/vendor/$name/.cargo-checksum.json"
    fi
done < "$HERE/crates.sha256"
rm -rf "$OUT/rust_hw"
cp -r "$HERE/rust_hw" "$OUT/rust_hw"
mkdir -p "$OUT/rust_hw/.cargo"
printf '[source.crates-io]\nreplace-with = "vendored"\n[source.vendored]\ndirectory = "%s/vendor"\n' \
    "$OUT" > "$OUT/rust_hw/.cargo/config.toml"
(cd "$OUT/rust_hw" && cargo build -q --release --offline)
cp "$OUT/rust_hw/target/release/hw-stream-witness" "$OUT/rust-hw"

python3 "$HERE/selftest.py" "$OUT"
echo "$OUT"
