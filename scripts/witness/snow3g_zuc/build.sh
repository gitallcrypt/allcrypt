#!/bin/sh
# Builds /opt/gppwitness: other implementations of SNOW 3G, ZUC-128 and
# ZUC-256 and the 3GPP modes over them, as witnesses for
# vectors/snow3g_zuc.vec.
#
#   ref-snow3g    The SNOW 3G reference implementation - Initialize,
#                 GenerateKeystream, f8 and f9 from the ETSI/SAGE
#                 specifications' annexes - as CryptoMobile carries it
#                 (mitshell/CryptoMobile, 0857cbb, C_alg/SNOW_3G.c), under
#                 ref_snow3g.c. UEA2, UIA2 and 128-EIA1.
#   ref-kasumi    The KASUMI reference implementation with f8 and f9, 3GPP
#                 TS 35.202 and TS 35.201 annex 2, CryptoMobile's
#                 C_alg/Kasumi.c, under ref_kasumi.c: UEA1 and UIA1. For a
#                 sanitizer run add -fno-sanitize=alignment: its key
#                 schedule reads the key through a misaligned union pointer.
#   ref-zuc       The ZUC reference implementation with EEA3 and EIA3 from
#                 the same annexes, CryptoMobile's C_alg/ZUC.c, under
#                 ref_zuc.c.
#   ipsecmb       Intel's intel-ipsec-mb 2.0.3 (1ef1461), a static build of
#                 its lib/, under ipsecmb.c: KASUMI's UEA1 and UIA1, SNOW
#                 3G, ZUC-128 and ZUC-256,
#                 every mode, the ZUC-256 MAC at all three tag sizes.
#   gmssl-zuc     GmSSL (guanzhi/GmSSL, 24ae482), src/zuc.c and
#                 src/zuc_modes.c, under gmssl_zuc.c: ZUC-128, ZUC-256,
#                 EEA3, EIA3 and both MACs.
#   go-free5gc    free5gc's NAS security algorithms (free5gc/nas, ff5ea67,
#                 internal/algo), copied beside go_free5gc/main.go as the
#                 package gppwitness/algo with its imports pointed there and
#                 nothing else changed: SNOW 3G, ZUC-128, NEA1, NEA3, NIA1
#                 and NIA3. Needs go, and github.com/aead/cmac, which
#                 GOPROXY=direct fetches from GitHub.
#   bc-zuc        Bouncy Castle 1.77's Zuc128Engine, Zuc256Engine,
#                 Zuc128Mac and Zuc256Mac, from the jar the system ships,
#                 under ZucWitness.java.
#   rust-zuc      The zuc 0.4.1 crate, under rust_3gpp/.
#   rust-oxirush  oxirush-security 0.3.0, under rust_3gpp/: SNOW 3G,
#                 ZUC-128, NEA1, NEA3, NIA1 and NIA3. The crates are fetched
#                 by cargo, pinned with their checksums by
#                 rust_3gpp/Cargo.lock.
#
# Requests are the lines driver.h describes. selftest.py then requires
# every witness to reproduce the published test data its implementation
# covers, and the witnesses to agree over random inputs.
#
# CFLAGS_EXTRA goes to every C compile - "-fsanitize=address,undefined -g
# -DOFFSET=1" for a sanitizer run over misaligned buffers.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/gppwitness}
JAR=${2:-/usr/share/java/bcprov-1.77.jar}
CFLAGS_EXTRA=${CFLAGS_EXTRA:-}
mkdir -p "$OUT/src"

fetch() {  # fetch DIR URL COMMIT
    if [ ! -d "$OUT/src/$1" ]; then
        git init -q "$OUT/src/$1"
        git -C "$OUT/src/$1" fetch -q --depth 1 "$2" "$3"
        git -C "$OUT/src/$1" checkout -q FETCH_HEAD
    fi
    [ "$(git -C "$OUT/src/$1" rev-parse HEAD)" = "$3" ] || { echo "$1 is not at $3"; exit 1; }
}
fetch mitshell-CryptoMobile https://github.com/mitshell/CryptoMobile \
    0857cbbf140c05c54688bdb2076c25eb8f3ddb89
fetch ipsecmb-tagged https://github.com/intel/intel-ipsec-mb \
    1ef14617d9415ac79d261c06b7ec98143e43ad42
fetch guanzhi-GmSSL https://github.com/guanzhi/GmSSL \
    24ae482701a7b124826c382fffc55c19f76d475d
fetch free5gc-nas https://github.com/free5gc/nas \
    ff5ea67383b7b5841247aab712889890b4c67d55

CM="$OUT/src/mitshell-CryptoMobile/C_alg"
cc -O1 -w $CFLAGS_EXTRA -I"$CM" -o "$OUT/ref-snow3g" "$HERE/ref_snow3g.c"
cc -O1 -w $CFLAGS_EXTRA -I"$CM" -o "$OUT/ref-zuc" "$HERE/ref_zuc.c"
cc -O1 -w $CFLAGS_EXTRA -I"$CM" -o "$OUT/ref-kasumi" "$HERE/ref_kasumi.c"

G="$OUT/src/guanzhi-GmSSL"
cc -O1 -w $CFLAGS_EXTRA -I"$G/include" -o "$OUT/gmssl-zuc" "$HERE/gmssl_zuc.c" \
    "$G/src/zuc.c" "$G/src/zuc_modes.c" "$G/src/hex.c" "$G/src/debug.c"

L="$OUT/src/ipsecmb-tagged/lib"
[ -f "$L/libIPSec_MB.a" ] || make -s -C "$L" -j"$(nproc)" SHARED=n > "$OUT/ipsecmb-build.log" 2>&1
cc -O1 -w $CFLAGS_EXTRA -I"$L" -o "$OUT/ipsecmb" "$HERE/ipsecmb.c" "$L/libIPSec_MB.a"

rm -rf "$OUT/go_free5gc"
mkdir -p "$OUT/go_free5gc/algo/snow3g" "$OUT/go_free5gc/algo/zuc"
A="$OUT/src/free5gc-nas/internal/algo"
for f in nea.go nia.go snow3g/snow3g.go zuc/zuc.go; do
    sed 's#github.com/free5gc/nas/internal/algo#gppwitness/algo#' "$A/$f" > "$OUT/go_free5gc/algo/$f"
done
cp "$HERE/go_free5gc/main.go" "$OUT/go_free5gc/main.go"
printf 'module gppwitness\n\ngo 1.21\n\nrequire github.com/aead/cmac v0.0.0-20160719120800-7af84192f0b1\n' \
    > "$OUT/go_free5gc/go.mod"
grep '^github.com/aead/cmac ' "$OUT/src/free5gc-nas/go.sum" > "$OUT/go_free5gc/go.sum"
(cd "$OUT/go_free5gc" && GOPROXY=direct GOFLAGS=-mod=mod go build -o "$OUT/go-free5gc" .)

cp "$JAR" "$OUT/bcprov.jar"
mkdir -p "$OUT/java"
javac -cp "$OUT/bcprov.jar" -d "$OUT/java" "$HERE/ZucWitness.java"
printf '#!/bin/sh\nexec java -cp "%s/bcprov.jar:%s/java" ZucWitness\n' "$OUT" "$OUT" \
    > "$OUT/bc-zuc"
chmod +x "$OUT/bc-zuc"

rm -rf "$OUT/rust_3gpp"
cp -r "$HERE/rust_3gpp" "$OUT/rust_3gpp"
rm -rf "$OUT/rust_3gpp/target"
(cd "$OUT/rust_3gpp" && cargo build -q --release --locked)
cp "$OUT/rust_3gpp/target/release/zuc_crate" "$OUT/rust-zuc"
cp "$OUT/rust_3gpp/target/release/oxirush" "$OUT/rust-oxirush"

python3 "$HERE/selftest.py" "$OUT"
echo "$OUT"
