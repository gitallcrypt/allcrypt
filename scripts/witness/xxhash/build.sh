#!/bin/sh
# Builds /opt/xxhashwitness: xxHash from seven implementations, the
# sources fetched once from GitHub at pinned commits and checked against
# xxhash.sha256.
#
# - PHP's ext/hash, with driver.php: php-witness. xxh32, xxh64, xxh3 and
#   xxh128, seeded, and xxh3 and xxh128 with a secret. PHP bundles the
#   reference code, so this is the reference again, through another
#   build and another interface.
# - The reference xxhash.h 0.8.3 (Cyan4973/xxHash), with driver_c.c:
#   c-witness. All four, seeded or with a secret.
# - twox-hash 2.1.5 (shepmaster/twox-hash), Rust, compiled with the
#   system's rustc and its scalar XXH3 path, with rust/driver.rs:
#   twox-witness. All four, seeded or with a secret.
# - Four Go packages, compiled with the system's go, offline, for
#   GOARCH=386 so that each takes its portable path, with go/driver.go:
#   oneofone-witness (xxh32, xxh64), cespare-witness (xxh64),
#   pierrec-witness (xxh32, xxh64) and zeebo-witness (xxh3 and xxh128),
#   all seeded.
#
# Before reporting success the witnesses must agree on the empty input;
# scripts/make_xxhash_vectors.py compares the rest.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/xxhashwitness}
GH=https://raw.githubusercontent.com
REF=$GH/Cyan4973/xxHash/e626a72bc2321cd320e953a0ccf1584cad60f363
TWOX=$GH/shepmaster/twox-hash/0222275b9e2faaa0a09eead8057753609ff891d1
ZEEBO=$GH/zeebo/xxh3/84cc04fc61771ea2a564c57277a19f83217a84ff
CESPARE=$GH/cespare/xxhash/998dce232f17418a7a5721ecf87ca714025a3243
ONEOFONE=$GH/OneOfOne/xxhash/73388e8298b5e5a3611e6b62c2fc41b1b108491e
PIERREC=$GH/pierrec/xxHash/36da3d21705c750db3ecfad1e46dc667baeb0ca9
mkdir -p "$OUT/go" "$OUT/src"
for f in $(cut -c67- "$HERE/xxhash.sha256"); do
    case "$f" in
        ref/*) url=$REF/${f#ref/} ;;
        twox/*) url=$TWOX/${f#twox/} ;;
        zeebo/*) url=$ZEEBO/${f#zeebo/} ;;
        cespare/*) url=$CESPARE/${f#cespare/} ;;
        oneofone/*) url=$ONEOFONE/${f#oneofone/} ;;
        pierrec/*) url=$PIERREC/${f#pierrec/} ;;
    esac
    mkdir -p "$OUT/src/$(dirname "$f")"
    [ -f "$OUT/src/$f" ] || curl -sSfL -o "$OUT/src/$f" "$url"
done
(cd "$OUT/src" && sha256sum -c --quiet "$HERE/xxhash.sha256")

printf '#!/bin/sh\nexec php %s/driver.php\n' "$HERE" > "$OUT/php-witness"
cc -O1 -w -I"$OUT/src/ref" -o "$OUT/c-witness" "$HERE/driver_c.c"

rustc -O --edition 2021 --crate-type rlib --crate-name twox_hash \
    --cfg 'feature="std"' --cfg 'feature="alloc"' --cfg 'feature="xxhash32"' \
    --cfg 'feature="xxhash64"' --cfg 'feature="xxhash3_64"' --cfg 'feature="xxhash3_128"' \
    --cfg _internal_xxhash3_force_scalar -A warnings \
    -o "$OUT/libtwox_hash.rlib" "$OUT/src/twox/src/lib.rs"
rustc -O --edition 2021 --extern twox_hash="$OUT/libtwox_hash.rlib" \
    -o "$OUT/twox-witness" "$HERE/rust/driver.rs"

# Each package gets the go.mod naming it; the fetched trees have none.
printf 'module github.com/zeebo/xxh3\n\ngo 1.22\n' > "$OUT/src/zeebo/go.mod"
printf 'module github.com/cespare/xxhash/v2\n\ngo 1.11\n' > "$OUT/src/cespare/go.mod"
printf 'module github.com/OneOfOne/xxhash\n\ngo 1.11\n' > "$OUT/src/oneofone/go.mod"
printf 'module github.com/pierrec/xxHash\n\ngo 1.11\n' > "$OUT/src/pierrec/go.mod"
cp "$HERE/go/driver.go" "$OUT/go/"
cat > "$OUT/go/go.mod" <<EOF
module xxhashwitness

go 1.22

require (
	github.com/OneOfOne/xxhash v0.0.0
	github.com/cespare/xxhash/v2 v2.0.0
	github.com/pierrec/xxHash v0.0.0
	github.com/zeebo/xxh3 v0.0.0
)

replace github.com/OneOfOne/xxhash => $OUT/src/oneofone
replace github.com/cespare/xxhash/v2 => $OUT/src/cespare
replace github.com/pierrec/xxHash => $OUT/src/pierrec
replace github.com/zeebo/xxh3 => $OUT/src/zeebo
EOF
(cd "$OUT/go" && GOARCH=386 GOFLAGS=-mod=mod GOPROXY=off go build -o "$OUT/go-witness" .)
for w in oneofone cespare pierrec zeebo; do
    printf '#!/bin/sh\nexec %s/go-witness %s\n' "$OUT" "$w" > "$OUT/$w-witness"
done
chmod +x "$OUT/php-witness" "$OUT/oneofone-witness" "$OUT/cespare-witness" \
    "$OUT/pierrec-witness" "$OUT/zeebo-witness"

# The empty input, seed zero, from each witness that has the name.
: > "$OUT/empty"
check() {
    name=$1; shift
    for w in "$@"; do
        echo "$name seed:0000000000000000 $OUT/empty" | "$OUT/$w-witness"
    done | sort -u | wc -l | grep -qx 1 || { echo "the witnesses disagree on $name"; exit 1; }
}
check xxh32 php c twox oneofone pierrec
check xxh64 php c twox oneofone cespare pierrec
check xxh3 php c twox zeebo
check xxh128 php c twox zeebo
echo "built $OUT"
