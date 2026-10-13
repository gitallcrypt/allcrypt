#!/bin/sh
# Builds /opt/strumok: two witnesses for Strumok (DSTU 8845:2019), from
# sources fetched once and checked against strumok.sha256.
#
#   strumok-uapki    UAPKI's dstu8845.c with the few library files it
#                    links against (specinfo-ua/UAPKI, commit c3b069f),
#                    by uapki_driver.c
#   strumok-uacrypt  uacrypt's hazmat/strumok.rs (user137/uacrypt, commit
#                    995198e) on its own, by the crate in uacrypt/, with
#                    zeroize/ standing in for the zeroize crate; built
#                    with cargo --offline, needing nothing fetched
#
# uacrypt's tests/strumok.rs is fetched too, for the standard's examples
# it transcribes. Before reporting success, published.py requires both
# programs to reproduce every published keystream (it lists them).
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/strumok}
UAPKI=https://raw.githubusercontent.com/specinfo-ua/UAPKI/c3b069f3db13ea67360f7d48739c3189374e5d3c/library/uapkic
UACRYPT=https://raw.githubusercontent.com/user137/uacrypt/995198e5cf322327849b4d28f191fda94cc625fb/crates/dstu-core
mkdir -p "$OUT/src/uapki/include" "$OUT/src/uapki/src" "$OUT/src/uacrypt/src/hazmat" \
    "$OUT/src/uacrypt/tests"
cd "$OUT/src"
for f in $(cut -c67- "$HERE/strumok.sha256"); do
    case "$f" in
        uapki/*) base=$UAPKI ;;
        uacrypt/*) base=$UACRYPT ;;
    esac
    [ -f "$f" ] || curl -sSfL -o "$f" "$base/${f#*/}"
done
sha256sum -c --quiet "$HERE/strumok.sha256"

cc -O2 -w -Iuapki/include -Iuapki/src -o "$OUT/strumok-uapki" "$HERE/uapki_driver.c" \
    uapki/src/dstu8845.c uapki/src/byte-array.c uapki/src/byte-utils-internal.c

rm -rf "$OUT/rust"
mkdir -p "$OUT/rust"
cp -r "$HERE/uacrypt" "$HERE/zeroize" "$OUT/rust/"
cp uacrypt/src/hazmat/strumok.rs "$OUT/rust/uacrypt/src/strumok.rs"
(cd "$OUT/rust/uacrypt" && cargo build --offline --release --quiet \
    --target-dir "$OUT/rust/target")
cp "$OUT/rust/target/release/strumok-uacrypt" "$OUT/strumok-uacrypt"

python3 -I "$HERE/published.py" --check "$OUT"
echo "$OUT"
