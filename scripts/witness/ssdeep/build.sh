#!/bin/sh
# Builds /opt/ssdeepwitness: three implementations of context triggered
# piecewise hashing, fetched once from GitHub at pinned commits and
# checked against ssdeep.sha256.
#
# - libfuzzy, ssdeep 2.14.1's fuzzy.c and the five files it needs
#   (ssdeep-project/ssdeep, tag release-2.14.1), compiled with
#   driver.c: ssdeep-witness.
# - ppdeep (elceef/ppdeep), a pure-Python ssdeep that hashes the input
#   once per block size, as spamsum did: ppdeep_driver.py.
# - ctph.js 0.0.5 (huwenshuo/ctph.js), which is what CyberChef's CTPH
#   runs, under node: driver.js.
#
# Before reporting success libfuzzy and ppdeep must agree on an empty
# and a random input, and ctph.js must answer for both;
# scripts/make_ssdeep_vectors.py compares the rest.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/ssdeepwitness}
SSDEEP=https://raw.githubusercontent.com/ssdeep-project/ssdeep/c05c1c5555d92542b26500b9c47cac418dba3b8e
PPDEEP=https://raw.githubusercontent.com/elceef/ppdeep/2dab5af26e8a9b3f897ba3d6fc1e76086160c8bd
CTPH=https://raw.githubusercontent.com/huwenshuo/ctph.js/5398fc6efa6619737e4decb618a517dd6ddd42a9
mkdir -p "$OUT/src"
for f in $(cut -c67- "$HERE/ssdeep.sha256"); do
    case "$f" in
        ssdeep/*) url=$SSDEEP/${f#ssdeep/} ;;
        ppdeep/*) url=$PPDEEP/${f#ppdeep/} ;;
        ctph.js/*) url=$CTPH/${f#ctph.js/} ;;
    esac
    mkdir -p "$OUT/src/$(dirname "$f")"
    [ -f "$OUT/src/$f" ] || curl -sSfL -o "$OUT/src/$f" "$url"
done
(cd "$OUT/src" && sha256sum -c --quiet "$HERE/ssdeep.sha256")

cc -O1 -w -I"$OUT/src/ssdeep" -include stdint.h -o "$OUT/ssdeep-witness" "$HERE/driver.c" \
    "$OUT/src/ssdeep/fuzzy.c" "$OUT/src/ssdeep/edit_dist.c"
cp "$HERE/ppdeep_driver.py" "$HERE/driver.js" "$OUT/"

: > "$OUT/empty"
head -c 100000 /dev/urandom > "$OUT/random"
for f in empty random; do
    a=$(echo "hash $OUT/$f" | "$OUT/ssdeep-witness")
    b=$(echo "hash $OUT/$f" | python3 -I "$OUT/ppdeep_driver.py" "$OUT/src/ppdeep")
    c=$(echo "hash $OUT/$f" | node "$OUT/driver.js" "$OUT/src/ctph.js/ctph.js")
    [ "$a" = "$b" ] || { echo "libfuzzy and ppdeep disagree on $f: $a, $b"; exit 1; }
    [ -n "$c" ] && [ "$c" != error ] || { echo "ctph.js failed on $f"; exit 1; }
done
echo "$OUT"
