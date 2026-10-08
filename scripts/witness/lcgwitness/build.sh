#!/bin/sh
# Builds /opt/lcgwitness: the rand() of three C libraries compiled from
# their own source, PCG's 64 bit LCG step, libstdc++'s minstd engines and
# the JDK's java.util.Random, behind one command line each. Every source
# is fetched at a pinned tag and checked against its hash, so a change
# upstream stops the build rather than changing the vectors.
#
#   musl 1.2.5        src/prng/rand.c                 (kraj/musl mirror)
#   newlib 4.4.0      newlib/libc/stdlib/rand.c       (mirror/newlib-cygwin)
#   Wine 9.0          dlls/msvcrt/misc.c, srand/rand  (MSVC's rand, as Wine
#                                                      reimplements it)
#   pcg-c             include/pcg_variants.h          (Knuth's MMIX LCG)
#                     pcg-c has no release tag; the hash pins the file.
#
# The C library sources are compiled unchanged, with srand/rand renamed
# by the preprocessor and, for newlib and Wine, the per-thread state they
# reach through a macro supplied by shim/.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/lcgwitness}
mkdir -p "$OUT"
fetch() {
    curl -sSf -o "$OUT/$1" "$2"
    echo "$3  $OUT/$1" | sha256sum -c --quiet
}
fetch musl_rand.c https://raw.githubusercontent.com/kraj/musl/v1.2.5/src/prng/rand.c \
    83ac507f40f71ce90477290ca255dffb91e4256226616e46fa044ad1b136c24d
fetch newlib_rand.c https://raw.githubusercontent.com/mirror/newlib-cygwin/newlib-4.4.0/newlib/libc/stdlib/rand.c \
    8620bd35c5b317964fd687e16e4e09880df41658942b515e1fa343075dd4d88a
fetch wine_misc.c https://raw.githubusercontent.com/wine-mirror/wine/wine-9.0/dlls/msvcrt/misc.c \
    b1ae79b2236c4a4a79ac990c8aabade962d7c8e105d23e9d07c14507792c20ee
fetch pcg_variants.h https://raw.githubusercontent.com/imneme/pcg-c/master/include/pcg_variants.h \
    d0fad6e1818868e565299859da9539073d63ea0c18101974f863b2abffdd546d
# Wine's two functions, from srand's definition to the end of rand's.
sed -n '/^void CDECL srand(/,/^int CDECL rand_s(/p' "$OUT/wine_misc.c" | sed '$d' \
    > "$OUT/wine_rand.c"
grep -q 'random_seed \* 214013 + 2531011' "$OUT/wine_rand.c"

cc -O2 -std=c11 -w -c -o "$OUT/musl_rand.o" -Dsrand=musl_srand -Drand=musl_rand \
    "$OUT/musl_rand.c"
cc -O2 -std=c11 -w -c -o "$OUT/newlib_rand.o" -I"$HERE/shim" \
    -Dsrand=newlib_srand -Drand=newlib_rand "$OUT/newlib_rand.c"
cc -O2 -std=c11 -w -c -o "$OUT/wine_rand.o" -include "$HERE/shim/wine_shim.h" \
    -Dsrand=wine_srand -Drand=wine_rand "$OUT/wine_rand.c"
c++ -O2 -std=c++17 -w -I"$OUT" -o "$OUT/lcgwitness" "$HERE/main.cpp" \
    "$OUT/musl_rand.o" "$OUT/newlib_rand.o" "$OUT/wine_rand.o"
javac -d "$OUT" "$HERE/JavaRandomWitness.java"
echo "$OUT/lcgwitness"
