#!/bin/sh
# Builds /opt/macwitness: other implementations of the MACs, as witnesses
# for vectors/pmac.vec, vectors/vmac.vec and vectors/chaskey.vec.
#
#   ltc-pmac    libtomcrypt 1.18.2 (libtom/libtomcrypt, tag v1.18.2), the
#               whole library built with -DLTC_NO_FAST, under ltc_pmac.c:
#               PMAC over AES, DES, 3DES and Blowfish. Built *without*
#               LTC_FAST because its PMAC's fast path takes 16 bytes as a
#               block whatever the cipher's block is, which gives a wrong
#               tag over any 64 bit cipher once a message passes 16 bytes;
#               ltc-pmac-fast is the default build, kept to show it.
#   go-pmac     miscreant.go's pmac package (miscreant/miscreant.go,
#               26d3763), under go_pmac/: AES only. Its published vectors,
#               vectors/aes_pmac.tjson, are Rogaway's PMAC-AES-128 tests.
#   rust-pmac   RustCrypto's pmac 0.7.1 with aes 0.8.4, des 0.8.1 and
#               blowfish 0.9.1, under rust_pmac/. The crates come from
#               static.crates.io, each checked against crates.sha256, and
#               build offline from a directory source.
#
#   cryptopp-vmac  Crypto++ 8.9.0 (weidai11/cryptopp, tag CRYPTOPP_8_9_0),
#               built whole as libcryptopp.a, under cryptopp_vmac.cpp: VMAC
#               over AES, Twofish, Serpent, Camellia, ARIA, SEED and SM4,
#               both tags. TestVectors/vmac.txt has its published tests.
#   kernel-vmac The Linux kernel's crypto/vmac.c at v6.6, fetched from
#               GitHub and checked against its SHA-256: the part from
#               VMAC_TAG_LEN to the end of vmac_final, unchanged, compiled
#               in user space with kvmac_shim.h standing in for the kernel
#               and OpenSSL's AES for the cipher, under kvmac_driver.c.
#               vmac64: AES-128, the 64 bit tag, a 16 byte nonce.
#
#   go-chaskey  dgryski/go-chaskey (013fc2e), under go_chaskey/: Chaskey
#               and Chaskey-12. go-chaskey is its amd64 assembly and
#               go-chaskey-purego the portable Go, two code paths. Its test
#               file carries the reference implementation's 64 published
#               tags for each round count.
#   rust-chaskey  sacundim/chaskey (774cbea), under rust_chaskey/: all three
#               round counts, 16 being Chaskey-LTS, writing the message in
#               growing pieces; and its Even-Mansour block cipher over the
#               same permutations. Its two dependencies, byteorder 0.5.3 and
#               rustc-serialize 0.3.25, come from crates.sha256.
#   volexity-chaskey  volexity/chaskey-lts (64a22f7), pure Python, under
#               volexity_chaskey.py: its Chaskey-LTS block cipher, a reading
#               of the 16 round permutation that goes through no MAC.
#
# Each git source is pinned by its commit. Requests, one per line, are
# `pmac <cipher> <key hex> <message hex>`, `vmac <cipher> <key hex>
# <nonce hex> <message hex> <tag bytes>`, `chaskey <rounds> <key hex>
# <message hex>` and `cipher <rounds> <key hex> <block hex>`, "-" for
# empty; the answer is the tag or block in hex or "error ...". selftest.py
# then requires every witness to reproduce the published vectors and the
# witnesses to agree.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/macwitness}
mkdir -p "$OUT/src"

fetch() {  # fetch DIR URL REF COMMIT
    if [ ! -d "$OUT/src/$1" ]; then
        git clone -q "$2" "$OUT/src/$1"
        git -C "$OUT/src/$1" checkout -q "$3"
    fi
    [ "$(git -C "$OUT/src/$1" rev-parse HEAD)" = "$4" ] || { echo "$1 is not at $4"; exit 1; }
}
fetch libtomcrypt https://github.com/libtom/libtomcrypt v1.18.2 \
    7e7eb695d581782f04b24dc444cbfde86af59853
fetch miscreant.go https://github.com/miscreant/miscreant.go \
    26d376326b756ad22784895e59c6c4f93c40d9af 26d376326b756ad22784895e59c6c4f93c40d9af
fetch cryptopp https://github.com/weidai11/cryptopp CRYPTOPP_8_9_0 \
    843d74c7c97f9e19a615b8ff3c0ca06599ca501b
fetch go-chaskey https://github.com/dgryski/go-chaskey \
    013fc2e4d86d0fac111f910361da3da30bed6754 013fc2e4d86d0fac111f910361da3da30bed6754
fetch chaskey https://github.com/sacundim/chaskey \
    774cbea008c4c6b14ee58b0ad9b8df9d45d6248c 774cbea008c4c6b14ee58b0ad9b8df9d45d6248c
fetch chaskey-lts https://github.com/volexity/chaskey-lts \
    64a22f7992101cc7aa6c133e7f63ec0b2165306b 64a22f7992101cc7aa6c133e7f63ec0b2165306b

JOBS=$(nproc 2>/dev/null || echo 2)
for variant in nofast fast; do
    tree="$OUT/src/libtomcrypt-$variant"
    if [ ! -f "$tree/libtomcrypt.a" ]; then
        rm -rf "$tree"
        cp -r "$OUT/src/libtomcrypt" "$tree"
        if [ $variant = nofast ]; then
            make -C "$tree" -j"$JOBS" CFLAGS="-DLTC_NO_FAST" >/dev/null
        else
            make -C "$tree" -j"$JOBS" >/dev/null
        fi
    fi
done
cc -O1 -DLTC_NO_FAST -I"$OUT/src/libtomcrypt-nofast/src/headers" -o "$OUT/ltc-pmac" \
    "$HERE/ltc_pmac.c" "$OUT/src/libtomcrypt-nofast/libtomcrypt.a"
cc -O1 -I"$OUT/src/libtomcrypt-fast/src/headers" -o "$OUT/ltc-pmac-fast" \
    "$HERE/ltc_pmac.c" "$OUT/src/libtomcrypt-fast/libtomcrypt.a"

[ -f "$OUT/src/cryptopp/libcryptopp.a" ] || make -C "$OUT/src/cryptopp" -j"$JOBS" static >/dev/null
c++ -O1 -std=c++17 -I"$OUT/src/cryptopp" -o "$OUT/cryptopp-vmac" \
    "$HERE/cryptopp_vmac.cpp" "$OUT/src/cryptopp/libcryptopp.a"

VMAC_C_SHA256=b6992cec30672bf4188f873d5cf2693d36b24588cf11b96038ba472152e6a7f6
mkdir -p "$OUT/src/linux"
[ -f "$OUT/src/linux/vmac.c" ] || curl -sf -o "$OUT/src/linux/vmac.c" \
    https://raw.githubusercontent.com/torvalds/linux/v6.6/crypto/vmac.c
echo "$VMAC_C_SHA256  $OUT/src/linux/vmac.c" | sha256sum -c --quiet -
sed -n '/^#define VMAC_TAG_LEN/,/^static int vmac_init_tfm/p' "$OUT/src/linux/vmac.c" \
    | sed '$d' > "$OUT/src/linux/vmac_core.c"
cc -O1 -Wall -Wno-deprecated-declarations -I"$HERE" -I"$OUT/src/linux" -o "$OUT/kernel-vmac" \
    "$HERE/kvmac_driver.c" -lcrypto

rm -rf "$OUT/go_pmac"
cp -r "$HERE/go_pmac" "$OUT/go_pmac"
(cd "$OUT/go_pmac" && GOFLAGS=-mod=mod GOPROXY=off go build -o "$OUT/go-pmac" .)

mkdir -p "$OUT/crates" "$OUT/vendor"
while read -r sum file; do
    [ -f "$OUT/crates/$file" ] || curl -sf -o "$OUT/crates/$file" \
        "https://static.crates.io/crates/${file%-[0-9]*}/$file"
    echo "$sum  $OUT/crates/$file" | sha256sum -c --quiet -
    name=${file%.crate}
    if [ ! -d "$OUT/vendor/$name" ]; then
        tar xzf "$OUT/crates/$file" -C "$OUT/vendor"
        printf '{"files":{},"package":"%s"}\n' "$sum" > "$OUT/vendor/$name/.cargo-checksum.json"
    fi
done < "$HERE/crates.sha256"
rm -rf "$OUT/rust_pmac"
cp -r "$HERE/rust_pmac" "$OUT/rust_pmac"
mkdir -p "$OUT/rust_pmac/.cargo"
printf '[source.crates-io]\nreplace-with = "vendored"\n[source.vendored]\ndirectory = "%s/vendor"\n' \
    "$OUT" > "$OUT/rust_pmac/.cargo/config.toml"
(cd "$OUT/rust_pmac" && cargo build -q --release --offline)
cp "$OUT/rust_pmac/target/release/pmac-witness" "$OUT/rust-pmac"

# go-chaskey predates modules; the copy built here gets a go.mod, which
# is the only change to it.
rm -rf "$OUT/go_chaskey" "$OUT/src/go-chaskey-mod"
cp -r "$OUT/src/go-chaskey" "$OUT/src/go-chaskey-mod"
rm -rf "$OUT/src/go-chaskey-mod/.git"
printf 'module github.com/dgryski/go-chaskey\n\ngo 1.16\n' > "$OUT/src/go-chaskey-mod/go.mod"
cp -r "$HERE/go_chaskey" "$OUT/go_chaskey"
(cd "$OUT/go_chaskey" && GOFLAGS=-mod=mod GOPROXY=off go build -o "$OUT/go-chaskey" . \
    && GOFLAGS=-mod=mod GOPROXY=off go build -tags purego -o "$OUT/go-chaskey-purego" .)

rm -rf "$OUT/rust_chaskey"
cp -r "$HERE/rust_chaskey" "$OUT/rust_chaskey"
mkdir -p "$OUT/rust_chaskey/.cargo"
printf '[source.crates-io]\nreplace-with = "vendored"\n[source.vendored]\ndirectory = "%s/vendor"\n' \
    "$OUT" > "$OUT/rust_chaskey/.cargo/config.toml"
(cd "$OUT/rust_chaskey" && cargo build -q --release --offline)
cp "$OUT/rust_chaskey/target/release/chaskey-witness" "$OUT/rust-chaskey"

cp "$HERE/volexity_chaskey.py" "$OUT/volexity_chaskey.py"
printf '#!/bin/sh\nexec python3 -I "%s/volexity_chaskey.py" "%s/src/chaskey-lts/src"\n' \
    "$OUT" "$OUT" > "$OUT/volexity-chaskey"
chmod +x "$OUT/volexity-chaskey"

python3 "$HERE/selftest.py" "$OUT"
echo "$OUT"
