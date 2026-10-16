#!/bin/sh
# Builds /opt/estreamwitness: other implementations of the eSTREAM
# software-profile ciphers - Rabbit, HC-128, SOSEMANUK - and HC-256, as
# witnesses for vectors/estream.vec.
#
#   ref-*       The eSTREAM submissions themselves, as SUPERCOP carries them
#               (floodyberry/supercop, a351f2c, crypto_stream/ and the
#               ECRYPT headers in include/), each under ecrypt_driver.c:
#               HC-128 in its 200606, 200701a and 200701b versions, HC-256
#               in 200511 and 200701, Rabbit's reference and SOSEMANUK's
#               submission. A cipher's versions are separate builds, so
#               each is a code path of its own.
#   cryptopp-stream  Crypto++ 8.9.0 (weidai11/cryptopp, tag CRYPTOPP_8_9_0),
#               built whole as libcryptopp.a, under cryptopp_stream.cpp:
#               Rabbit with and without an IV, HC-128, HC-256 and
#               SOSEMANUK. Its HC-256 reads each key and IV word rotated
#               (selftest.py says so, and that it is not a witness for it).
#   ltc-stream  libtomcrypt's develop branch (libtom/libtomcrypt, 6c6d510),
#               whose Rabbit and SOSEMANUK are in no release, under
#               ltc_stream.c.
#   bc-stream   Bouncy Castle 1.77's HC128Engine and HC256Engine, from the
#               jar the system ships, under StreamWitness.java.
#   rust-stream RustCrypto's rabbit 0.5.0 and hc-256 0.6.0, under
#               rust_stream/, from crates checked against crates.sha256 and
#               built offline from a directory source.
#
# Requests, one per line, are `stream <cipher> <key hex> <iv hex>
# <length>`, "-" for an empty IV; ciphers rabbit (no IV), rabbit-iv,
# hc128, hc256 and sosemanuk. The answer is the first <length> bytes of
# keystream in hex, or "error ...". selftest.py then requires every
# witness to reproduce the published vectors and the witnesses to agree.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/estreamwitness}
JAR=${2:-/usr/share/java/bcprov-1.77.jar}
mkdir -p "$OUT/src"

fetch() {  # fetch DIR URL REF COMMIT
    if [ ! -d "$OUT/src/$1" ]; then
        git clone -q "$2" "$OUT/src/$1"
        git -C "$OUT/src/$1" checkout -q "$3"
    fi
    [ "$(git -C "$OUT/src/$1" rev-parse HEAD)" = "$4" ] || { echo "$1 is not at $4"; exit 1; }
}
fetch cryptopp https://github.com/weidai11/cryptopp CRYPTOPP_8_9_0 \
    843d74c7c97f9e19a615b8ff3c0ca06599ca501b
fetch libtomcrypt https://github.com/libtom/libtomcrypt \
    6c6d5104de66f3ca0dfd7b68540ef86869982b07 6c6d5104de66f3ca0dfd7b68540ef86869982b07
SUPERCOP_COMMIT=a351f2c29235512a042d4b6989d241a67e86ad23
if [ ! -d "$OUT/src/supercop" ]; then
    git clone -q --filter=blob:none --sparse https://github.com/floodyberry/supercop \
        "$OUT/src/supercop"
    git -C "$OUT/src/supercop" sparse-checkout set crypto_stream include
    git -C "$OUT/src/supercop" checkout -q "$SUPERCOP_COMMIT"
fi
[ "$(git -C "$OUT/src/supercop" rev-parse HEAD)" = "$SUPERCOP_COMMIT" ] \
    || { echo "supercop is not at $SUPERCOP_COMMIT"; exit 1; }

JOBS=$(nproc 2>/dev/null || echo 2)
CFLAGS_EXTRA=${CFLAGS_EXTRA:-}

S="$OUT/src/supercop/crypto_stream"
ecrypt() {  # ecrypt NAME CIPHER DIR
    cc -O1 -w $CFLAGS_EXTRA -DCIPHER="\"$2\"" -I"$3" -I"$OUT/src/supercop/include" \
        -o "$OUT/$1" "$HERE/ecrypt_driver.c" "$3"/*.c
}
ecrypt ref-hc128-200606 hc128 "$S/hc128/e/hc-128/200606/e"
ecrypt ref-hc128-200701a hc128 "$S/hc128/e/hc-128/200701a/e"
ecrypt ref-hc128-200701b hc128 "$S/hc128/e/hc-128/200701b/e"
ecrypt ref-hc256-200511 hc256 "$S/hc256/e/hc-256/200511/e"
ecrypt ref-hc256-200701 hc256 "$S/hc256/e/hc-256/200701/e"
ecrypt ref-rabbit rabbit "$S/rabbit/e/ref/e"
ecrypt ref-sosemanuk sosemanuk "$S/sosemanuk/e/submissions/sosemanuk/e"

[ -f "$OUT/src/cryptopp/libcryptopp.a" ] || make -C "$OUT/src/cryptopp" -j"$JOBS" static >/dev/null
c++ -O1 -std=c++17 $CFLAGS_EXTRA -I"$OUT/src/cryptopp" -o "$OUT/cryptopp-stream" \
    "$HERE/cryptopp_stream.cpp" "$OUT/src/cryptopp/libcryptopp.a"

[ -f "$OUT/src/libtomcrypt/libtomcrypt.a" ] || make -C "$OUT/src/libtomcrypt" -j"$JOBS" >/dev/null
cc -O1 $CFLAGS_EXTRA -I"$OUT/src/libtomcrypt/src/headers" -o "$OUT/ltc-stream" \
    "$HERE/ltc_stream.c" "$OUT/src/libtomcrypt/libtomcrypt.a"

cp "$JAR" "$OUT/bcprov.jar"
mkdir -p "$OUT/java"
javac -cp "$OUT/bcprov.jar" -d "$OUT/java" "$HERE/StreamWitness.java"
printf '#!/bin/sh\nexec java -cp "%s/bcprov.jar:%s/java" StreamWitness\n' "$OUT" "$OUT" > "$OUT/bc-stream"
chmod +x "$OUT/bc-stream"

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
rm -rf "$OUT/rust_stream"
cp -r "$HERE/rust_stream" "$OUT/rust_stream"
mkdir -p "$OUT/rust_stream/.cargo"
printf '[source.crates-io]\nreplace-with = "vendored"\n[source.vendored]\ndirectory = "%s/vendor"\n' \
    "$OUT" > "$OUT/rust_stream/.cargo/config.toml"
(cd "$OUT/rust_stream" && cargo build -q --release --offline)
cp "$OUT/rust_stream/target/release/stream-witness" "$OUT/rust-stream"

python3 "$HERE/selftest.py" "$OUT"
echo "$OUT"
