#!/bin/sh
# Builds a witness for TurboSHAKE and KangarooTwelve: the Keccak team's
# XKCP K12 (github.com/XKCP/K12, f95b0b7), its portable C Keccak-p[1600]
# (the plain64 target: no assembly, no SIMD), under driver.c, which includes KangarooTwelve.c to reach
# its static TurboSHAKE functions. With pycryptodome 3.24.1 for
# TurboSHAKE128/256 and KT128 (it has no KT256):
#
#   sh scripts/witness/k12/build.sh /opt/k12witness
#   pip install --target /opt/k12witness pycryptodome==3.24.1
#   python3 scripts/make_turboshake_k12_vectors.py
#
# Writes PREFIX/k12-witness and PREFIX/k12-witness-san
# (-fsanitize=address,undefined). XKCP's opt64.c XORs input into the
# state through uint64_t pointers on a little-endian machine unless
# NO_MISALIGNED_ACCESSES is defined, which UBSan reports as a misaligned
# load as soon as the input is at an odd address; the sanitizer build
# keeps XKCP's default path and leaves out that one check,
# -fno-sanitize=alignment, so that a run on misaligned buffers finds
# anything else. Needs git and a C compiler.
set -eu
PREFIX=${1:?usage: build.sh PREFIX}
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$PREFIX"
if [ ! -d "$PREFIX/K12" ]; then
    git clone -q https://github.com/XKCP/K12 "$PREFIX/K12"
fi
git -C "$PREFIX/K12" checkout -q f95b0b7
K="$PREFIX/K12/lib"
for flags in "-O2" "-O1 -g -fsanitize=address,undefined -fno-sanitize=alignment -fno-sanitize-recover=all"; do
    out="$PREFIX/k12-witness"
    case "$flags" in *sanitize*) out="$PREFIX/k12-witness-san" ;; esac
    # XKCP's plain64 target: opt64.c compiled under Plain64's header,
    # which names its functions for the generic interface.
    # shellcheck disable=SC2086
    cc $flags -I"$K" -I"$K/Plain64" -o "$out" "$HERE/driver.c" \
        "$K/Optimized64/KeccakP-1600-opt64.c" "$K/Plain64/KeccakP-1600-plain64.c"
done
echo "built $PREFIX/k12-witness and $PREFIX/k12-witness-san"
