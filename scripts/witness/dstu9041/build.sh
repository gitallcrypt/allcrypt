#!/bin/sh
# Builds /opt/dstu9041: two witnesses for DSTU 9041:2020, from sources
# fetched once and checked against dstu9041.sha256.
#
#   dstu9041-uacrypt  uacrypt's hazmat/dstu9041 (user137/uacrypt, commit
#                     995198e) with the modules it uses - Kalyna, its key
#                     wrap, Kupyna, their tables - by the crate in
#                     uacrypt/, against subtle 2.6.1's one source file
#                     (dalek-cryptography/subtle) and zeroize/ standing
#                     in for the zeroize crate; built with cargo
#                     --offline, needing nothing fetched
#   src/li0ard/       li0ard's TypeScript dstu9041 (li0ard/dstu, commit
#                     6c277c8) with the files of @noble/curves and
#                     @noble/hashes 2.4.0 it imports (paulmillr's
#                     repositories, their TypeScript sources), run by bun
#                     through li0ard/driver.ts, copied in beside it
#
# uacrypt's transcriptions of the standard's worked examples and li0ard's
# tests of them are fetched too. Before reporting success, published.py
# requires both witnesses to reproduce both examples.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/dstu9041}
UACRYPT=https://raw.githubusercontent.com/user137/uacrypt/995198e5cf322327849b4d28f191fda94cc625fb/crates/dstu-core
SUBTLE=https://raw.githubusercontent.com/dalek-cryptography/subtle/2.6.1/src
LI0ARD=https://raw.githubusercontent.com/li0ard/dstu/6c277c8906588a11f0d21a844347e83574ca325a/src
CURVES=https://raw.githubusercontent.com/paulmillr/noble-curves/2.4.0/src
HASHES=https://raw.githubusercontent.com/paulmillr/noble-hashes/2.4.0/src
for f in $(cut -c67- "$HERE/dstu9041.sha256"); do
    case "$f" in
        uacrypt/hazmat/*) url=$UACRYPT/src/${f#uacrypt/} ;;
        uacrypt/vectors/*) url=$UACRYPT/tests/vectors/dstu9041/${f#uacrypt/vectors/} ;;
        subtle/*) url=$SUBTLE/${f#subtle/} ;;
        li0ard/src/*) url=$LI0ARD/${f#li0ard/src/} ;;
        li0ard/node_modules/@noble/curves/*) url=$CURVES/${f#li0ard/node_modules/@noble/curves/} ;;
        li0ard/node_modules/@noble/hashes/*) url=$HASHES/${f#li0ard/node_modules/@noble/hashes/} ;;
    esac
    mkdir -p "$OUT/src/$(dirname "$f")"
    [ -f "$OUT/src/$f" ] || curl -sSfL -o "$OUT/src/$f" "$url"
done
cd "$OUT/src"
sha256sum -c --quiet "$HERE/dstu9041.sha256"

# The TypeScript: ES modules, as their package.json files would say.
for d in li0ard li0ard/node_modules/@noble/curves li0ard/node_modules/@noble/hashes; do
    echo '{"type": "module"}' > "$d/package.json"
done
cp "$HERE/li0ard/driver.ts" li0ard/driver.ts

rm -rf "$OUT/rust"
mkdir -p "$OUT/rust"
cp -r "$HERE/uacrypt" "$HERE/subtle" "$HERE/zeroize" "$OUT/rust/"
(cd "$OUT/rust/uacrypt" && cargo build --offline --release --quiet \
    --target-dir "$OUT/rust/target")
cp "$OUT/rust/target/release/dstu9041-uacrypt" "$OUT/dstu9041-uacrypt"

python3 -I "$HERE/published.py" --check "$OUT"
echo "$OUT"
