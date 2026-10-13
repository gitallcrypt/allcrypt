#!/bin/sh
# Builds /opt/checksumwitness: the checksums from implementations the
# system already has, and Fletcher's and FNV from others fetched once
# from GitHub at pinned commits and checked against checksums.sha256.
#
# - PHP's ext/hash, with driver.php: php-witness. crc32 (PHP's crc32b),
#   crc32c, adler32, and fnv1 and fnv1a at 32 and 64 bits.
# - Go's standard library, built with the system's go, offline, with
#   go/driver.go: go-witness. crc32, crc32c, adler32, and fnv1 and fnv1a
#   at 32, 64 and 128 bits.
# - java.util.zip, with ChecksumWitness.java: java-witness. crc32,
#   crc32c and adler32.
# - zlib and the SSE 4.2 CRC32 instruction, with driver_c.c: c-witness.
#   crc32 and adler32 from zlib; crc32c from the instruction, so the
#   build needs a processor that has it.
# - The C of the R package fletcher (chrislongros/fletcher), its three
#   functions cut out of the R glue, with driver_fletcher.c:
#   rpkg-witness. fletcher16, fletcher32 and fletcher64.
# - rfinnie's hashlib-additional, its one module, run by the system's
#   python3 with driver_hashlib_additional.py: py-witness. The same three,
#   and fnv0, fnv1 and fnv1a at every size - though its FNV-1 and FNV-1a
#   at 512 bits are wrong, so the vectors script leaves them out.
# - jbangelo's fletcher crate, compiled with the system's rustc, with
#   rust/driver.rs: rust-witness. The three Fletchers.
# - hugoalh's fnv-es, run by node with its type annotations stripped,
#   with driver_fnves.mjs: fnves-witness. fnv0, fnv1 and fnv1a at every
#   size.
# - tjwebb's fnv-plus, run by node, with driver_fnvplus.cjs:
#   fnvplus-witness. fnv1 and fnv1a at every size.
#
# Before reporting success the witnesses must agree on the catalogue's
# check input, "123456789"; scripts/make_checksum_vectors.py compares
# the rest.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/checksumwitness}
RPKG=https://raw.githubusercontent.com/chrislongros/fletcher/2339f7e281c89bc93fb292b7d2dcf93c9757aea8
HASHLIB=https://raw.githubusercontent.com/rfinnie/python-hashlib-additional/ac2bd5e9f20de19c257b246821593471ab762e5f
FLETCHERRS=https://raw.githubusercontent.com/jbangelo/fletcher/2d941b4c26061fd3b057485723d4df92315a757d
FNVES=https://raw.githubusercontent.com/hugoalh/fnv-es/93430810c7f1d6f060d7bc20bd589e7dc9d5fd08
FNVPLUS=https://raw.githubusercontent.com/tjwebb/fnv-plus/1e2ce68a07cb7dd4c3c85364f3d8d96c95919474
mkdir -p "$OUT/go" "$OUT/src"
grep -q sse4_2 /proc/cpuinfo || { echo "this processor has no SSE 4.2"; exit 1; }
for f in $(cut -c67- "$HERE/checksums.sha256"); do
    case "$f" in
        rpkg/*) url=$RPKG/${f#rpkg/} ;;
        hashlib-additional/*) url=$HASHLIB/${f#hashlib-additional/} ;;
        fletcher-rs/*) url=$FLETCHERRS/${f#fletcher-rs/} ;;
        fnv-es/*) url=$FNVES/${f#fnv-es/} ;;
        fnv-plus/*) url=$FNVPLUS/${f#fnv-plus/} ;;
    esac
    mkdir -p "$OUT/src/$(dirname "$f")"
    [ -f "$OUT/src/$f" ] || curl -sSfL -o "$OUT/src/$f" "$url"
done
(cd "$OUT/src" && sha256sum -c --quiet "$HERE/checksums.sha256")

printf '#!/bin/sh\nexec php %s/driver.php\n' "$HERE" > "$OUT/php-witness"
cc -O1 -msse4.2 -w -I"$HERE/../oldhashes" -o "$OUT/c-witness" "$HERE/driver_c.c" -lz
cp "$HERE/go/driver.go" "$OUT/go/"
printf 'module checksumwitness\n\ngo 1.21\n' > "$OUT/go/go.mod"
(cd "$OUT/go" && GOFLAGS=-mod=mod GOPROXY=off go build -o "$OUT/go-witness" .)
javac -d "$OUT" "$HERE/ChecksumWitness.java"
printf '#!/bin/sh\nexec java -cp %s ChecksumWitness\n' "$OUT" > "$OUT/java-witness"

# The R package's three functions, from the first comment above them to
# the R entry point after them.
sed -n '/^\/\* 8-bit blocks/,/^SEXP C_fletcher/p' "$OUT/src/rpkg/src/fletcher.c" | sed '$d' \
    > "$OUT/fletcher_rpkg.h"
cc -O1 -w -I"$HERE/../oldhashes" -I"$OUT" -o "$OUT/rpkg-witness" "$HERE/driver_fletcher.c"
printf '#!/bin/sh\nexec python3 -I %s/driver_hashlib_additional.py %s/src/hashlib-additional/hashlib_additional/__init__.py\n' \
    "$HERE" "$OUT" > "$OUT/py-witness"
rustc -O --edition 2015 --crate-type rlib --crate-name fletcher \
    -o "$OUT/libfletcher.rlib" "$OUT/src/fletcher-rs/src/lib.rs"
rustc -O --edition 2021 --extern fletcher="$OUT/libfletcher.rlib" \
    -o "$OUT/rust-witness" "$HERE/rust/driver.rs"
printf '#!/bin/sh\nexec node --experimental-strip-types --no-warnings %s/driver_fnves.mjs %s/src/fnv-es/base.ts\n' \
    "$HERE" "$OUT" > "$OUT/fnves-witness"
printf '#!/bin/sh\nexec node %s/driver_fnvplus.cjs %s/src/fnv-plus/index.js\n' "$HERE" "$OUT" \
    > "$OUT/fnvplus-witness"
chmod +x "$OUT/php-witness" "$OUT/java-witness" "$OUT/py-witness" "$OUT/fnves-witness" \
    "$OUT/fnvplus-witness"

printf 123456789 > "$OUT/check"
check() {
    name=$1; shift
    answers=$(for w in "$@"; do echo "$name $OUT/check" | "$OUT/$w-witness"; done | sort -u)
    [ "$(echo "$answers" | wc -l)" = 1 ] || { echo "the witnesses disagree on $name: $answers"; exit 1; }
    echo "$name $answers"
}
for name in crc32 crc32c adler32; do check $name php go java c; done
for name in fletcher16 fletcher32 fletcher64; do check $name rpkg py rust; done
for bits in 32 64; do
    check fnv0_$bits fnves py
    for v in 1 1a; do check fnv${v}_$bits php go fnves fnvplus py; done
done
for v in 1 1a; do check fnv${v}_128 go fnves fnvplus py; done
for bits in 256 1024; do for v in 0 1 1a; do check fnv${v}_$bits fnves py; done; done
check fnv0_128 fnves py
check fnv0_512 fnves py
for v in 1 1a; do
    for bits in 256 512 1024; do check fnv${v}_$bits fnves fnvplus; done
done
echo "$OUT"
