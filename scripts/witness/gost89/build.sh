#!/bin/sh
# Builds /opt/gost89: four files of the gost89 package (Ilya Petrov's
# JavaScript GOST 28147-89, GOST 34.311-95 and DSTU key wrap, the code
# behind the dstucrypt tools for Ukrainian keys), fetched once from its
# GitHub repository and checked against their SHA-256. It needs only
# Node's own Buffer. driver.js runs it.
set -e
OUT=${1:-/opt/gost89}
BASE=https://raw.githubusercontent.com/dstucrypt/gost89/master/lib
mkdir -p "$OUT/lib"
for f in gost89.js dstu.js hash.js keywrap.js; do
    curl -sSfL -o "$OUT/lib/$f" "$BASE/$f"
done
cd "$OUT/lib"
echo "27ce74f44dd94a5bd4ec9c7cda1f85fe9ce2ba3ca0beec04b444668a8c255f55  gost89.js
ef16dc2b31819bb6cf965abcc54e04ad1654a4f26ea8776d33386ab089af7990  dstu.js
1c6dbb8b068969ee8dfca3d426d38f904432bc71ff15d2f4e7fb8097e33c68e5  hash.js
0050be7835dafbf501e58b9da45a69850c02a07628ba30cb45b4f079d4e55efb  keywrap.js" | sha256sum -c
echo "$OUT"
