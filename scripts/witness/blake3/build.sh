#!/bin/sh
# Builds /opt/blake3witness: three implementations of BLAKE3, the first
# two fetched once from GitHub (BLAKE3-team/BLAKE3, tag 1.8.7) and
# checked against blake3.sha256.
#
# - The team's C implementation, portable code only (no SIMD), with
#   driver_c.c: c-witness.
# - The team's reference implementation, reference_impl.rs, which
#   follows the specification's structure, compiled by the system's
#   rustc with driver_ref.rs: ref-witness.
# - Bouncy Castle's Blake3Digest, through the bcprov jar the system ships
#   (1.77 here; BCPROV names another), with Blake3Witness.java:
#   bc-witness.
#
# Requests are MODE/LENGTH/SEEK PATH; see driver_c.c. Before reporting
# success the three must agree on an empty and a random input in every
# mode; scripts/make_blake3_vectors.py compares the rest.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/blake3witness}
BLAKE3=https://raw.githubusercontent.com/BLAKE3-team/BLAKE3/f3149ec5bb5449af877ba20377a11008ff499fa2
mkdir -p "$OUT/src"
for f in $(cut -c67- "$HERE/blake3.sha256"); do
    mkdir -p "$OUT/src/$(dirname "$f")"
    [ -f "$OUT/src/$f" ] || curl -sSfL -o "$OUT/src/$f" "$BLAKE3/$f"
done
(cd "$OUT/src" && sha256sum -c --quiet "$HERE/blake3.sha256")

C=$OUT/src/c
cc -O1 -w -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512 \
    -DBLAKE3_USE_NEON=0 -I"$C" -I"$HERE/../oldhashes" -o "$OUT/c-witness" "$HERE/driver_c.c" \
    "$C/blake3.c" "$C/blake3_dispatch.c" "$C/blake3_portable.c"
mkdir -p "$OUT/ref"
cp "$HERE/driver_ref.rs" "$OUT/ref/main.rs"
cp "$OUT/src/reference_impl/reference_impl.rs" "$OUT/ref/"
rustc -O --edition 2021 -o "$OUT/ref-witness" "$OUT/ref/main.rs"
BCPROV=${BCPROV:-/usr/share/java/bcprov-1.77.jar}
mkdir -p "$OUT/java"
cp "$BCPROV" "$OUT/java/bcprov.jar"
javac -cp "$OUT/java/bcprov.jar" -d "$OUT/java" "$HERE/Blake3Witness.java"
printf '#!/bin/sh\nexec java -cp "%s/java/bcprov.jar:%s/java" Blake3Witness 2>/dev/null\n' "$OUT" "$OUT" \
    > "$OUT/bc-witness"
chmod +x "$OUT/bc-witness"

: > "$OUT/empty"
head -c 5000 /dev/urandom > "$OUT/random"
key=$(printf 'whats the Elvish word for friend' | od -An -tx1 | tr -d ' \n')
context=$(printf 'allcrypt witness check' | od -An -tx1 | tr -d ' \n')
for f in empty random; do
    for mode in hash "keyed=$key" "derive=$context"; do
        request="$mode/131/0 $OUT/$f"
        a=$(echo "$request" | "$OUT/c-witness")
        [ -n "$a" ] && [ "$a" != error ] || { echo "the C implementation failed on $request"; exit 1; }
        [ "$(echo "$request" | "$OUT/ref-witness")" = "$a" ] || { echo "the reference and C disagree on $request"; exit 1; }
        [ "$(echo "$request" | "$OUT/bc-witness")" = "$a" ] || { echo "Bouncy Castle and C disagree on $request"; exit 1; }
    done
done
echo "$OUT"
