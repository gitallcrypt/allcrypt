#!/bin/sh
# Builds /opt/cryptonite: the DSTU 7624 (Kalyna) part of PrivatBank's
# cryptonite, a C library of the Ukrainian standards, with driver.c over
# its modes. The 30 files it needs come from src/cryptonite/c in its
# GitHub repository, each checked against cryptonite.sha256. shim/
# stands in for the one header the repository keeps elsewhere
# (pthread_internal.h).
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/cryptonite}
BASE=https://raw.githubusercontent.com/privat-it/cryptonite/master/src/cryptonite/c
mkdir -p "$OUT/src"
cd "$OUT/src"
for f in $(cut -c67- "$HERE/cryptonite.sha256"); do
    curl -sSfL -o "$f" "$BASE/$f"
done
sha256sum -c --quiet "$HERE/cryptonite.sha256"
cc -O1 -w -DCRYPTONITE_EXPORT= -I"$HERE/shim" -I. -o "$OUT/cryptonite-witness" \
    "$HERE/driver.c" ./*.c -lpthread
echo "$OUT"
