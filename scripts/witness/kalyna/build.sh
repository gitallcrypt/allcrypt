#!/bin/sh
# Builds /opt/kalyna: the Kalyna (DSTU 7624:2014) reference
# implementation by the cipher's authors (Roman-Oliynykov/Kalyna-reference
# on GitHub), its files fetched once and checked against their SHA-256,
# compiled with driver.c in place of its own main. Its main.c is fetched
# too, for the standard's example vectors it carries.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/kalyna}
BASE=https://raw.githubusercontent.com/Roman-Oliynykov/Kalyna-reference/master
mkdir -p "$OUT"
for f in kalyna.c kalyna.h tables.c tables.h transformations.h main.c; do
    curl -sSfL -o "$OUT/$f" "$BASE/$f"
done
cd "$OUT"
echo "ea6d7eb630faad5979a92000835e0249f8c8227d2b9a748eca5381bf96c41d4e  kalyna.c
9a2ca883689689fe8f6650bca7b3f4e95eb2a42dda8dd75789996258497e93bb  kalyna.h
43a827bcce4c347a0d133e44dcd868dcf6d44af2c559be56dcd92b14af387bec  tables.c
3ae601025b7e345cd001b46af88108f12b271a0fd950dc744e6ac9f972e155f4  tables.h
c80e9db308ec7d5da008a96329c9d245a38c1b6d19a6ab4b436d6eaf10c94392  transformations.h
6edbb68e33a92097d883d193b6b929a57f3f6747ac489d343cc3fe337cf17072  main.c" | sha256sum -c
cc -O2 -w -I. -o kalyna-witness kalyna.c tables.c "$HERE/driver.c"
echo "$OUT"
