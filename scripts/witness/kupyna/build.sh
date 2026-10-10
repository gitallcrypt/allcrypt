#!/bin/sh
# Builds /opt/kupyna: the Kupyna (DSTU 7564:2014) reference
# implementation by the hash's authors (Roman-Oliynykov/Kupyna-reference
# on GitHub), its files fetched once and checked against their SHA-256,
# compiled with driver.c in place of its own main. Its main.c is fetched
# too, for the standard's example hashes it carries.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/kupyna}
BASE=https://raw.githubusercontent.com/Roman-Oliynykov/Kupyna-reference/master
mkdir -p "$OUT"
for f in kupyna.c kupyna.h tables.c tables.h main.c; do
    curl -sSfL -o "$OUT/$f" "$BASE/$f"
done
cd "$OUT"
echo "72e026c9f174b2bf45b3680d3c362fa0acf4b2ec25bba48ce5cec585ddae371c  kupyna.c
01b414ae233fe5a8e9f15833291d7d49d9c16b7c9db24b1a504a2793a420faf9  kupyna.h
da542c58a4569c9846169da3d7d0d9db1f60d707404e1957fbc9110c7fee364a  tables.c
082b43d3a5223e0b05350d0b5dd881fd97c23336a7bfbf792d17356dcbac839e  tables.h
6675b2f18330d97fbd47ce5d9d587fcab20b82ff2aa96d237fb0a112d1cd7398  main.c" | sha256sum -c
cc -O2 -w -I. -o kupyna-witness kupyna.c tables.c "$HERE/driver.c"
echo "$OUT"
