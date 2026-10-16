#!/bin/sh
# Builds /opt/murmur3witness: MurmurHash3 from six implementations, the
# sources fetched once from GitHub at pinned commits and checked against
# murmur3.sha256.
#
# - PHP's ext/hash, with driver.php: php-witness. murmur3_32,
#   murmur3_x86_128 and murmur3_x64_128 (PHP's murmur3a, murmur3c and
#   murmur3f), from PMurHash, an incremental implementation written
#   apart from the reference.
# - SMHasher's MurmurHash3.cpp (aappleby/smhasher), the reference,
#   compiled with the system's c++, with driver_ref.cpp: ref-witness.
#   All three, in one piece: it has no streaming interface.
# - The murmur3 crate 0.5.2 (stusmall/murmur3), compiled with the
#   system's rustc, with rust/driver.rs: rust-witness. All three.
# - murmurhash3js 3.0.1 (pid/murmurHash3js), run by node, with
#   driver_js.cjs: js-witness. All three, in one piece.
# - Two Go packages, compiled with the system's go, offline, for
#   GOARCH=386, with go/driver.go: spaolacci-witness
#   (spaolacci/murmur3) and twmb-witness (twmb/murmur3 1.1.8, whose
#   amd64 assembly that build leaves out). murmur3_32 and
#   murmur3_x64_128.
#
# Before reporting success the witnesses must agree on the empty input;
# scripts/make_murmur3_vectors.py compares the rest.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/murmur3witness}
GH=https://raw.githubusercontent.com
SMHASHER=$GH/aappleby/smhasher/07bb4de10a63e8cc2e1724865454eba635742383
SPAOLACCI=$GH/spaolacci/murmur3/539464a789e9b9f01bc857458ffe2c5c1a2ed382
TWMB=$GH/twmb/murmur3/3fcd9c20f2443ea2612fca5675f4cf6849e809b9
STUSMALL=$GH/stusmall/murmur3/2c39087f094ae982a463e1cda9cf4d483a09192b
JS=$GH/pid/murmurHash3js/695d91ab10e2f30827c15b69f58fee2421dee859
mkdir -p "$OUT/go" "$OUT/src"
for f in $(cut -c67- "$HERE/murmur3.sha256"); do
    case "$f" in
        smhasher/*) url=$SMHASHER/${f#smhasher/} ;;
        spaolacci/*) url=$SPAOLACCI/${f#spaolacci/} ;;
        twmb/*) url=$TWMB/${f#twmb/} ;;
        stusmall/*) url=$STUSMALL/${f#stusmall/} ;;
        murmurhash3js/*) url=$JS/${f#murmurhash3js/} ;;
    esac
    mkdir -p "$OUT/src/$(dirname "$f")"
    [ -f "$OUT/src/$f" ] || curl -sSfL -o "$OUT/src/$f" "$url"
done
(cd "$OUT/src" && sha256sum -c --quiet "$HERE/murmur3.sha256")

printf '#!/bin/sh\nexec php %s/driver.php\n' "$HERE" > "$OUT/php-witness"
c++ -O1 -w -I"$OUT/src/smhasher/src" -o "$OUT/ref-witness" "$HERE/driver_ref.cpp" \
    "$OUT/src/smhasher/src/MurmurHash3.cpp"
rustc -O --edition 2018 --crate-type rlib --crate-name murmur3 -A warnings \
    -o "$OUT/libmurmur3.rlib" "$OUT/src/stusmall/src/lib.rs"
rustc -O --edition 2021 --extern murmur3="$OUT/libmurmur3.rlib" \
    -o "$OUT/rust-witness" "$HERE/rust/driver.rs"
printf '#!/bin/sh\nexec node %s/driver_js.cjs %s/src/murmurhash3js/lib/murmurHash3js.js\n' \
    "$HERE" "$OUT" > "$OUT/js-witness"

printf 'module github.com/spaolacci/murmur3\n\ngo 1.11\n' > "$OUT/src/spaolacci/go.mod"
printf 'module github.com/twmb/murmur3\n\ngo 1.11\n' > "$OUT/src/twmb/go.mod"
cp "$HERE/go/driver.go" "$OUT/go/"
cat > "$OUT/go/go.mod" <<GOMOD
module murmur3witness

go 1.22

require (
	github.com/spaolacci/murmur3 v0.0.0
	github.com/twmb/murmur3 v0.0.0
)

replace github.com/spaolacci/murmur3 => $OUT/src/spaolacci
replace github.com/twmb/murmur3 => $OUT/src/twmb
GOMOD
(cd "$OUT/go" && GOARCH=386 GOFLAGS=-mod=mod GOPROXY=off go build -o "$OUT/go-witness" .)
for w in spaolacci twmb; do
    printf '#!/bin/sh\nexec %s/go-witness %s\n' "$OUT" "$w" > "$OUT/$w-witness"
done
chmod +x "$OUT/php-witness" "$OUT/js-witness" "$OUT/spaolacci-witness" "$OUT/twmb-witness"

# The empty input, seed one (seed zero gives zero), from each witness that has the name.
: > "$OUT/empty"
check() {
    name=$1; shift
    for w in "$@"; do
        echo "$name seed:00000001 $OUT/empty" | "$OUT/$w-witness"
    done | sort -u | wc -l | grep -qx 1 || { echo "the witnesses disagree on $name"; exit 1; }
}
check murmur3_32 php ref rust js spaolacci twmb
check murmur3_x86_128 php ref rust js
check murmur3_x64_128 php ref rust js spaolacci twmb
echo "built $OUT"
