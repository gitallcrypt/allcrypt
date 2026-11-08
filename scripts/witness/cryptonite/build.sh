#!/bin/sh
# Builds /opt/cryptonite: the DSTU 7624 (Kalyna), DSTU 7564 (Kupyna),
# GOST 28147-89 / 34.311-95 and DSTU 4145-2002 parts of PrivatBank's
# cryptonite, a C library of the Ukrainian standards, with driver.c over
# them; and its key-container library with storage.c over that, as
# cryptonite-storage. The 54 files it needs come from
# src/cryptonite/c in its
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

# The key containers - PKCS#8, PBES2 and PKCS#12 - for storage.c: the
# storage library and the asn1 and pkix ones under it, some 700 files,
# from the repository at one commit rather than file by file. Its own
# top-level CMakeLists.txt adds the test directories, which are not
# fetched, and builds with -Werror, so a small one of ours builds the
# five modules from the checkout as it is.
COMMIT=3618d340d22e27a6becf97d89c453f8e64068a39
R="$OUT/repo"
if [ ! -d "$R" ]; then
    git init -q "$R"
    git -C "$R" config core.sparseCheckout true
    printf 'src/pthread/\nsrc/cryptonite/\nsrc/asn1/\nsrc/pkix/\nsrc/storage/\nLICENSE\n' \
        > "$R/.git/info/sparse-checkout"
    git -C "$R" fetch -q --depth 1 --filter=blob:none https://github.com/privat-it/cryptonite "$COMMIT"
    git -C "$R" checkout -q FETCH_HEAD
fi
[ "$(git -C "$R" rev-parse HEAD)" = "$COMMIT" ] || { echo "cryptonite is not at $COMMIT"; exit 1; }
S="$OUT/storage-build"
mkdir -p "$S"
cat > "$S/CMakeLists.txt" <<CMAKE
cmake_minimum_required(VERSION 3.5)
project(cryptonite_storage C)
add_definitions(-DCRYPTONITE_EXPORT=extern)
add_compile_options(-w -O1)
foreach(module pthread cryptonite asn1 pkix storage)
    add_subdirectory($R/src/\${module} \${module})
endforeach()
add_executable(cryptonite-storage $HERE/storage.c)
target_link_libraries(cryptonite-storage storage pkix asn1 cryptonite pthread_impl pthread)
CMAKE
cmake -S "$S" -B "$S/build" > /dev/null
cmake --build "$S/build" -j2 > /dev/null
cp "$S/build/cryptonite-storage" "$OUT/cryptonite-storage"
echo "$OUT"
