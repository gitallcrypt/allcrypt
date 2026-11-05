#!/bin/sh
# Builds /opt/gostwrapwitness: gost-engine's CryptoPro key wrap and
# diversification (RFC 4357 sections 6.3 and 6.5), as a witness for
# vectors/gost_keywrap.vec.
#
#   gost-keywrap  gost89.c and gost_keywrap.c from gost-engine/engine
#               (e0a500a), unchanged, under driver.c; gost89.c needs only
#               OpenSSL's headers and libcrypto for OPENSSL_cleanse and
#               RAND_bytes, which the wrap does not call.
#
# CFLAGS_EXTRA adds flags, for a sanitizer build.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/gostwrapwitness}
COMMIT=e0a500ab877ba72cb14026a24d462dd923b90ced
mkdir -p "$OUT/src"
if [ ! -d "$OUT/src/engine" ]; then
    git clone -q https://github.com/gost-engine/engine "$OUT/src/engine"
    git -C "$OUT/src/engine" checkout -q "$COMMIT"
fi
[ "$(git -C "$OUT/src/engine" rev-parse HEAD)" = "$COMMIT" ] || { echo "engine is not at $COMMIT"; exit 1; }
E="$OUT/src/engine"
cc -O1 -w ${CFLAGS_EXTRA:-} -I"$E" -o "$OUT/gost-keywrap" "$HERE/driver.c" "$E/gost89.c" \
    "$E/gost_keywrap.c" -lcrypto
echo "$OUT"
