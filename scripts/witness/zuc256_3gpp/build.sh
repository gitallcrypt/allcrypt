#!/bin/sh
# Builds a witness for 3GPP's ZUC-256 and 256-NEA6, 256-NIA6 and
# 256-NCA6: the reference code in TS 35.246 V20.0.0's Annex A, taken from
# the vendored text (rfcs/35246-k00.txt) - every line from its first
# #define to Annex B, the blank lines the Word file's paragraphs put
# between them left out, nothing else changed - under driver.cpp.
#
#   sh scripts/witness/zuc256_3gpp/build.sh /opt/zuc256witness
#
# Writes PREFIX/annex_a.cpp, PREFIX/zuc256-3gpp and a sanitizer build,
# PREFIX/zuc256-3gpp-san (-fsanitize=address,undefined). Annex A's
# xor128 reads its operands through u64 pointers, which UBSan reports as
# a misaligned load as soon as the caller's buffers are at an odd
# address (driver argument 1); the sanitizer build leaves out that one
# check, -fno-sanitize=alignment, so that a run on misaligned buffers
# finds anything else. The vectors come from the plain build. Needs g++
# (C++17).
set -eu
PREFIX=${1:?usage: build.sh PREFIX}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
mkdir -p "$PREFIX"
awk '/^#define ZUC256_INIT_ROUND_CLOCKS/ { take = 1 }
     /^Annex B/ { take = 0 }
     take && NF' "$ROOT/rfcs/35246-k00.txt" > "$PREFIX/annex_a.cpp"
grep -q '^int NCA6_256($' "$PREFIX/annex_a.cpp"
g++ -std=c++17 -O1 -I"$PREFIX" -o "$PREFIX/zuc256-3gpp" "$HERE/driver.cpp"
g++ -std=c++17 -O1 -g -fsanitize=address,undefined -fno-sanitize=alignment \
    -fno-sanitize-recover=all -I"$PREFIX" \
    -o "$PREFIX/zuc256-3gpp-san" "$HERE/driver.cpp"
echo "built $PREFIX/zuc256-3gpp and $PREFIX/zuc256-3gpp-san"
