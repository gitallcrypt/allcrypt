#!/bin/sh
# Builds /opt/siphashwitness: three implementations of SipHash, and the
# designers' HalfSipHash.
#
# - The designers' reference code (veorq/SipHash), fetched once from
#   GitHub at a pinned commit and checked against siphash.sha256. It
#   fixes its round counts when compiled, so each of siphash.c and
#   halfsiphash.c is compiled once per pair - 1-3, 2-4, 3-5 and 4-8 -
#   with its function renamed, for driver_ref.c: ref-witness.
# - OpenSSL 3.5's SIPHASH EVP_MAC, with its c-rounds, d-rounds and size
#   parameters (/opt/openssl35, built as docs/building.md says), with
#   driver_openssl.c: openssl-witness.
# - Bouncy Castle's SipHash and SipHash128, through the bcprov jar the
#   system ships (1.77 here; BCPROV names another), with
#   SipHashWitness.java: bc-witness.
#
# Requests are KIND-C-D-BYTES:KEY PATH; see driver_ref.c. Before
# reporting success the three must agree on an empty and a random
# message at every pair, both lengths;
# scripts/make_siphash_vectors.py compares the rest.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/siphashwitness}
OPENSSL=${OPENSSL35:-/opt/openssl35}
SIPHASH=https://raw.githubusercontent.com/veorq/SipHash/32d067603b93b47828700880649198e0bfbbcffa
mkdir -p "$OUT/src"
for f in $(cut -c67- "$HERE/siphash.sha256"); do
    [ -f "$OUT/src/$f" ] || curl -sSfL -o "$OUT/src/$f" "$SIPHASH/$f"
done
(cd "$OUT/src" && sha256sum -c --quiet "$HERE/siphash.sha256")

SLURP=$HERE/../oldhashes
objects=
for pair in 1:3 2:4 3:5 4:8; do
    c=${pair%:*}
    d=${pair#*:}
    for kind in siphash halfsiphash; do
        cc -O1 -w -c -DcROUNDS=$c -DdROUNDS=$d -D$kind=${kind}_${c}_$d \
            -o "$OUT/$kind-$c-$d.o" "$OUT/src/$kind.c"
        objects="$objects $OUT/$kind-$c-$d.o"
    done
done
cc -O1 -w -I"$SLURP" -o "$OUT/ref-witness" "$HERE/driver_ref.c" $objects
cc -O1 -w -I"$OPENSSL/include" -I"$SLURP" -o "$OUT/openssl-witness" "$HERE/driver_openssl.c" \
    -L"$OPENSSL/lib" -Wl,-rpath,"$OPENSSL/lib" -lcrypto
BCPROV=${BCPROV:-/usr/share/java/bcprov-1.77.jar}
mkdir -p "$OUT/java"
cp "$BCPROV" "$OUT/java/bcprov.jar"
javac -cp "$OUT/java/bcprov.jar" -d "$OUT/java" "$HERE/SipHashWitness.java"
printf '#!/bin/sh\nexec java -cp "%s/java/bcprov.jar:%s/java" SipHashWitness 2>/dev/null\n' "$OUT" "$OUT" \
    > "$OUT/bc-witness"
chmod +x "$OUT/bc-witness"

: > "$OUT/empty"
head -c 1000 /dev/urandom > "$OUT/random"
key=000102030405060708090a0b0c0d0e0f
for f in empty random; do
    for pair in 1-3 2-4 3-5 4-8; do
        for bytes in 8 16; do
            request="siphash-$pair-$bytes:$key $OUT/$f"
            a=$(echo "$request" | "$OUT/ref-witness")
            [ -n "$a" ] && [ "$a" != error ] || { echo "the reference failed on $request"; exit 1; }
            [ "$(echo "$request" | "$OUT/openssl-witness")" = "$a" ] || { echo "OpenSSL and the reference disagree on $request"; exit 1; }
            [ "$(echo "$request" | "$OUT/bc-witness")" = "$a" ] || { echo "Bouncy Castle and the reference disagree on $request"; exit 1; }
        done
    done
done
echo "$OUT"
