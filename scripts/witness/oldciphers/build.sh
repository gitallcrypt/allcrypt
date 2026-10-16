#!/bin/sh
# Builds /opt/oldciphers: witnesses for the older block ciphers, from
# sources fetched once and checked against oldciphers.sha256.
#
#   libtomcrypt/  libtomcrypt 1.18.2's cipher files (libtom/libtomcrypt,
#                 tag v1.18.2), compiled against shim/tomcrypt.h instead
#                 of the rest of the library, by ltc_driver.c, and its
#                 tomcrypt_cipher.h, for the default round counts its
#                 tests leave out
#   cryptopp/     Crypto++ 8.9.0's cipher files with the few library files
#                 they link against (weidai11/cryptopp, tag CRYPTOPP_8_9_0),
#                 by cryptopp_driver.cpp, and TestData/ with validat4.cpp,
#                 for its tests and the round counts they are run at
#   botan/        Botan 1.10.17's cipher files (randombit/botan, tag
#                 1.10.17), compiled against shim/botan by
#                 botan_driver.cpp, and checks/validate.dat, for its tests
#   mcrypt/       libmcrypt 2.5.8's algorithm modules (winlibs/libmcrypt,
#                 tag libmcrypt-2.5.8) with its lib/mcrypt_modules.h,
#                 compiled against shim/mcrypt/libdefs.h by mcrypt_driver.c
#   go-krypto/    RyuaNerin/go-krypto, cloned whole and pinned by commit
#                 (the one scripts/witness/lsh uses); its pure Go LEA and
#                 HIGHT, by go/driver.go, and the files the scripts read
#                 listed in the manifest too
#   linux/        the Linux kernel's Speck (torvalds/linux, tag v4.19, the
#                 last with it): crypto/speck.c and include/crypto/speck.h,
#                 compiled against shim/linux/kernel.h by the NESSIE
#                 witness's linux_driver.c
#   inmcm/        inmcm/Simon_Speck_Ciphers's Python Simon and Speck, at a
#                 pinned commit, by inmcm_driver.py, and its tests, for the
#                 paper's vectors at every size
#   lwbc/         jedisct1/rust-lwbc's Speck and Simon at a pinned commit,
#                 built with cargo, offline - it has no dependencies -
#                 under lwbc_driver.rs, which gives it the designers' byte
#                 order
#   skein3fish/   wernerd/Skein3Fish's C Threefish, at a pinned commit: the
#                 Skein team's Threefish, unrolled, with a block cipher
#                 interface and decryption, by skein3fish_driver.c
#   presentgo/    Nirusu/PRESENT.go's PRESENT at a pinned commit, by
#                 go/driver.go, with a go.mod of its own written here (its
#                 own names a test library), and its tests for their
#                 published vectors
#   kurtfu/       kurtfu/present's C PRESENT at a pinned commit, compiled
#                 against shim/present/conf.h - the configuration file it
#                 asks to be edited - once per key size, by
#                 present_kurtfu_driver.c
#   opentitan/    lowRISC/opentitan's Python PRESENT (Present.py), at a
#                 pinned commit, by opentitan_driver.py
#   feal/         zilijonas/FEAL-NX's Java, with NTT's FEAL-NX test data that
#                 repository carries (test-vectors.txt, in Shift JIS), by
#                 FealWitness.java, and Donaldduck8's Python FEAL-NX, each
#                 at a pinned commit, by feal_driver.py
#   project79068/ Project Nayuki's cryptography library's SHACAL test, at a
#                 pinned commit, for its two published SHACAL-1 vectors; the
#                 library needs classes its repository does not have, so
#                 it is not a witness here
#
# And the system's OpenSSL libcrypto (3.0.13 here): its SHA1_Transform,
# with Crypto++'s SHA1::Transform, by shacal1_driver.cpp.
#   reference/    a designer's or a single author's code where it is the
#                 second implementation: Crypt::Misty1 1.1.3's _misty1.c
#                 (gitpan/Crypt-Misty1), by misty1_reference_driver.c, and
#                 the LOKI97 designers' reference C as Crypt::Loki97 1.0.1
#                 carries it (gitpan/Crypt-Loki97, _loki97.c, with the
#                 module's tests t/01.t to t/06.t), by
#                 loki97_reference_driver.c. That code keeps each 32-bit
#                 half of its 64-bit words in an `unsigned long`, which is
#                 64 bits wide here and makes it a different cipher - its
#                 own self-test fails - so it is compiled from a copy
#                 with that one declaration made `unsigned int`, the
#                 width it was written for
#   bc/           Bouncy Castle's engines, through OldCipherWitness.java,
#                 compiled against the bcprov jar the system ships (1.77
#                 here; pass another as the second argument), and the
#                 engines' sources at the matching tag (bcgit/bc-java,
#                 r1rv77), which scripts/make_*_tables.py read
#
# One program per implementation, named <cipher>-<source>, speaking
# ../nessie/driver.h's request format; the drivers here are the NESSIE
# witness's with a round count, taken from the environment's ROUNDS.
# Before reporting success, selftest.py requires every program to
# reproduce the published vectors the projects carry.
#
#   skipjack           libtomcrypt, Bouncy Castle
#   skipjack-reversed  Crypto++, Botan: Skipjack with the key, the block
#                      and the result each read in reverse byte order
#   safer-k64, safer-k128, safer-sk64
#                      libtomcrypt, Crypto++
#   safer-sk128        libtomcrypt, Crypto++, Botan
#   square             Crypto++, Botan
#   kasumi             libtomcrypt, Botan
#   misty1             Botan, Crypt::Misty1 (reference)
#   saferplus          libtomcrypt
#   saferplus-reversed-words
#                      libmcrypt: SAFER+ with the 32-bit words of the key,
#                      the block and the result each in reverse order
#   threeway           Crypto++, libmcrypt
#   loki97             the designers' reference
#   loki97-mcrypt      libmcrypt: LOKI97 with every 32-bit word of the key,
#                      the block and the result byte-swapped, and the key
#                      zero-padded to 32 bytes
#   lea                Crypto++, go-krypto
#   hight              Crypto++, go-krypto
#   speck64, speck128  Crypto++, the Linux kernel, inmcm, and lwbc at 64
#                      bits with a 16 byte key
#   simon64, simon128  Crypto++, inmcm, and lwbc at 64 bits with a 16
#                      byte key
#   speck32, speck48, speck96, simon32, simon48, simon96
#                      inmcm, lwbc - which has one key length at each, 8,
#                      12 and 18 bytes
#   present            PRESENT.go, kurtfu/present, OpenTitan: the key of 10
#                      or 16 bytes, and kurtfu's read with every byte string
#                      reversed, which its driver undoes
#   feal-nx            zilijonas/FEAL-NX, Donaldduck8's Python: at the round
#                      count in ROUNDS, 32 when it is unset; both take
#                      FEAL-N's 8 byte key too, as FEAL-NX's with its right
#                      half zero
#   shacal1            Crypto++, OpenSSL: SHA-1's compression function less
#                      its feed-forward, which encrypts only
#   threefish256, threefish512, threefish1024
#                      Crypto++, Bouncy Castle, Skein3Fish: the key, or the
#                      key followed by the 16 byte tweak
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
NESSIE=$HERE/../nessie
OUT=${1:-/opt/oldciphers}
JAR=${2:-/usr/share/java/bcprov-1.77.jar}
LTC=https://raw.githubusercontent.com/libtom/libtomcrypt/v1.18.2/src
BOTAN=https://raw.githubusercontent.com/randombit/botan/1.10.17
CPP=https://raw.githubusercontent.com/weidai11/cryptopp/CRYPTOPP_8_9_0
BC=https://raw.githubusercontent.com/bcgit/bc-java/r1rv77/core/src/main/java/org/bouncycastle/crypto/engines
MISTY1=https://raw.githubusercontent.com/gitpan/Crypt-Misty1/master
LOKI97=https://raw.githubusercontent.com/gitpan/Crypt-Loki97/master
GOKRYPTO=6e7566c4c44e0af11b5f3811c4c15925a9955d31
LINUX=https://raw.githubusercontent.com/torvalds/linux/v4.19
INMCM=https://raw.githubusercontent.com/inmcm/Simon_Speck_Ciphers/9eec98160fa27e73a6f3938c1af988caddb158a9/Python/simonspeckciphers
MCRYPT=https://raw.githubusercontent.com/winlibs/libmcrypt/libmcrypt-2.5.8
LWBC=https://raw.githubusercontent.com/jedisct1/rust-lwbc/049f6cd5f9b086960f8880607870cbaddfd40e92
SKEIN3FISH=https://raw.githubusercontent.com/wernerd/Skein3Fish/00e925444c2c174ead3a16005b7d00a468990386/c/src
PRESENTGO=https://raw.githubusercontent.com/Nirusu/PRESENT.go/797caefdfbe8f648c925fbb3c790ca0118f55d8a
KURTFU=https://raw.githubusercontent.com/kurtfu/present/2ba82b54b90975193ef8fec70a032e56ffd7394e
OPENTITAN=https://raw.githubusercontent.com/lowRISC/opentitan/cfcefae2db13015b6178c40044d9f1c93070bb8c/util/design/lib
FEALJAVA=https://raw.githubusercontent.com/zilijonas/FEAL-NX/fb8b9ea60cc3432f2878066f90026a71f8d0e720
FEALPY=https://raw.githubusercontent.com/Donaldduck8/FEAL-NX-Python-Implementation/e146009755f59202c241f43b572065765afd5019
P79068=https://raw.githubusercontent.com/nayuki/Project79068-Cryptography-Library/8ab0a4b5261d0b3f0f688b803180ce1e5c20f094/test/p79068/crypto/cipher
mkdir -p "$OUT/src/libtomcrypt" "$OUT/src/botan/botan" "$OUT/src/cryptopp" "$OUT/src/bc" \
    "$OUT/src/reference" "$OUT/src/reference/t" "$OUT/src/mcrypt" "$OUT/src/linux" \
    "$OUT/src/inmcm" "$OUT/src/skein3fish" "$OUT/src/project79068" \
    "$OUT/src/presentgo" "$OUT/src/kurtfu" "$OUT/src/opentitan" "$OUT/obj/kurtfu" \
    "$OUT/src/feal" "$OUT/feal" "$OUT/src/lwbc" "$OUT/obj/lwbc-crate/src" \
    "$OUT/obj/lwbc-driver/src" \
    "$OUT/kinc/crypto" "$OUT/kinc/linux" "$OUT/kinc/asm" \
    "$OUT/bc" "$OUT/obj"
cd "$OUT/src"
if [ ! -d go-krypto ]; then
    git clone -q https://github.com/RyuaNerin/go-krypto go-krypto
    git -C go-krypto checkout -q "$GOKRYPTO"
fi
[ "$(git -C go-krypto rev-parse HEAD)" = "$GOKRYPTO" ] || { echo "go-krypto is not at $GOKRYPTO"; exit 1; }
for f in $(cut -c67- "$HERE/oldciphers.sha256"); do
    case "$f" in
        libtomcrypt/tomcrypt_cipher.h) base=$LTC/headers ;;
        libtomcrypt/safer*) base=$LTC/ciphers/safer ;;
        libtomcrypt/*) base=$LTC/ciphers ;;
        botan/validate.dat) base=$BOTAN/checks ;;
        botan/safer_sk.*) base=$BOTAN/src/block/safer ;;
        botan/sqr_tab.cpp) base=$BOTAN/src/block/square ;;
        botan/*) name=${f#botan/}; base=$BOTAN/src/block/${name%.*} ;;
        cryptopp/*.dat) base=$CPP/TestData ;;
        cryptopp/*.txt) base=$CPP/TestVectors ;;
        cryptopp/*) base=$CPP ;;
        bc/*) base=$BC ;;
        reference/_misty1.c) base=$MISTY1 ;;
        reference/_loki97.c|reference/t/*) base=$LOKI97 ;;
        linux/speck.c) base=$LINUX/crypto ;;
        linux/speck.h) base=$LINUX/include/crypto ;;
        inmcm/simon.py) base=$INMCM/simon ;;
        inmcm/speck.py) base=$INMCM/speck ;;
        inmcm/test_simonspeck.py) base=$INMCM/tests ;;
        lwbc/Cargo.toml) base=$LWBC ;;
        lwbc/*) base=$LWBC/src ;;
        mcrypt/mcrypt_modules.h) base=$MCRYPT/lib ;;
        skein3fish/*.h) base=$SKEIN3FISH/include ;;
        skein3fish/*) base=$SKEIN3FISH ;;
        project79068/*) base=$P79068 ;;
        presentgo/*) base=$PRESENTGO ;;
        kurtfu/test_main.c) base=$KURTFU/test ;;
        kurtfu/*.c) base=$KURTFU/src ;;
        kurtfu/*.h) base=$KURTFU/include ;;
        opentitan/*) base=$OPENTITAN ;;
        feal/FEAL_NX.py) base=$FEALPY ;;
        feal/*) base=$FEALJAVA ;;
        mcrypt/*) base=$MCRYPT/modules/algorithms ;;
        # From the checkout above; the manifest check below covers them.
        go-krypto/*) continue ;;
    esac
    [ -f "$f" ] || curl -sSfL -o "$f" "$base/${f#*/}"
done
sha256sum -c --quiet "$HERE/oldciphers.sha256"
ltc() {
    name=$1 desc=$2 source=$3
    shift 3
    cc -O1 -w -I"$HERE/shim" -I"$NESSIE" -I"$OUT/src/libtomcrypt" -DDESC="$desc" \
        -DSOURCE="\"$source\"" "$@" -o "$OUT/$name" "$HERE/ltc_driver.c"
}
ltc skipjack-libtomcrypt skipjack_desc skipjack.c
for v in k64 k128 sk64 sk128; do
    ltc safer-$v-libtomcrypt safer_${v}_desc safer.c
done
ltc kasumi-libtomcrypt kasumi_desc kasumi.c
ltc saferplus-libtomcrypt saferp_desc saferp.c
mcrypt() {
    cc -O1 -w -I"$HERE/shim/mcrypt" -I"$NESSIE" -I"$OUT/src/mcrypt" -DSOURCE="\"$2\"" \
        -o "$OUT/$1" "$HERE/mcrypt_driver.c"
}
mcrypt saferplus-reversed-words-mcrypt saferplus.c
mcrypt threeway-mcrypt 3-way.c
mcrypt loki97-mcrypt-mcrypt loki97.c
# Botan's headers are included as <botan/name.h>.
botan() {
    cp "$OUT/src/botan/$3.h" "$OUT/src/botan/botan/$3.h"
    name=$1 class=$2 file=$3
    shift 3
    c++ -std=c++11 -O1 -w -I"$HERE/shim/botan" -I"$NESSIE" -I"$OUT/src/botan" \
        -DCLASS="$class" -DHEADER="<botan/$file.h>" "$@" -o "$OUT/$name" \
        "$HERE/botan_driver.cpp" "$OUT/src/botan/$file.cpp"
}
botan skipjack-reversed-botan Skipjack skipjack
botan safer-sk128-botan SAFER_SK safer_sk -DROUNDS_CTOR
botan square-botan Square square "$OUT/src/botan/sqr_tab.cpp"
botan kasumi-botan KASUMI kasumi
botan misty1-botan MISTY1 misty1
cc -O1 -w -I"$NESSIE" -I"$OUT/src/reference" -o "$OUT/misty1-reference" \
    "$HERE/misty1_reference_driver.c"
# The kernel's Speck: its own crypto/speck.h, the other headers it names
# as empty files, and the NESSIE driver over each of its two algorithms.
cp "$OUT/src/linux/speck.h" "$OUT/kinc/crypto/speck.h"
for h in asm/unaligned.h linux/bitops.h linux/crypto.h linux/init.h linux/module.h \
         linux/types.h; do
    : > "$OUT/kinc/$h"
done
for alg in "speck128 0" "speck64 1"; do
    set -- $alg
    cc -O1 -w -include "$HERE/shim/linux/kernel.h" -I"$OUT/kinc" -I"$NESSIE" -I"$OUT/src/linux" \
        -DALG="speck_algs[$2]" -DSOURCE='"speck.c"' -o "$OUT/$1-kernel" "$NESSIE/linux_driver.c"
done
# Skein3Fish: one program per block size.
for bits in 256 512 1024; do
    cc -O1 -w -I"$NESSIE" -I"$OUT/src/skein3fish" -DBITS=$bits -o "$OUT/threefish$bits-skein3fish" \
        "$HERE/skein3fish_driver.c" "$OUT/src/skein3fish/threefishApi.c" \
        "$OUT/src/skein3fish/threefish256Block.c" "$OUT/src/skein3fish/threefish512Block.c" \
        "$OUT/src/skein3fish/threefish1024Block.c"
done
# The Python reference, by its driver; one wrapper per cipher.
cp "$HERE/inmcm_driver.py" "$OUT/inmcm_driver.py"
for cipher in "speck32 speck 32" "speck48 speck 48" "speck64 speck 64" "speck96 speck 96" \
              "speck128 speck 128" "simon32 simon 32" "simon48 simon 48" "simon64 simon 64" \
              "simon96 simon 96" "simon128 simon 128"; do
    set -- $cipher
    printf '#!/bin/sh\nexec python3 -I "%s/inmcm_driver.py" "%s/src/inmcm" %s %s\n' \
        "$OUT" "$OUT" "$2" "$3" > "$OUT/$1-inmcm"
    chmod +x "$OUT/$1-inmcm"
done
# lwbc, as a crate laid out from the fetched files, and the driver as a
# crate that depends on it by path.
cp "$OUT/src/lwbc/Cargo.toml" "$OUT/obj/lwbc-crate/Cargo.toml"
for f in "$OUT"/src/lwbc/*.rs; do cp "$f" "$OUT/obj/lwbc-crate/src/"; done
cp "$HERE/lwbc_driver.rs" "$OUT/obj/lwbc-driver/src/main.rs"
printf '[package]\nname = "lwbc-driver"\nversion = "0.0.0"\nedition = "2021"\n\n[dependencies]\nlwbc = { path = "%s" }\n\n[workspace]\n' \
    "$OUT/obj/lwbc-crate" > "$OUT/obj/lwbc-driver/Cargo.toml"
(cd "$OUT/obj/lwbc-driver" && CARGO_TARGET_DIR="$OUT/obj/lwbc-target" cargo build --offline -q --release)
cp "$OUT/obj/lwbc-target/release/lwbc-driver" "$OUT/lwbc-driver"
for cipher in speck32 speck48 speck64 speck96 simon32 simon48 simon64 simon96; do
    printf '#!/bin/sh\nexec "%s/lwbc-driver" %s\n' "$OUT" "$cipher" > "$OUT/$cipher-lwbc"
    chmod +x "$OUT/$cipher-lwbc"
done
# The one change to the LOKI97 reference, made on a copy and required to
# have happened exactly once.
sed 's/unsigned long l,r;/unsigned int l,r;/' "$OUT/src/reference/_loki97.c" > "$OUT/obj/_loki97.c"
[ "$(grep -c 'unsigned int l,r;' "$OUT/obj/_loki97.c")" = 1 ] || {
    echo "_loki97.c: its ULONG64 declaration was not found"; exit 1; }
cc -O1 -w -I"$NESSIE" -I"$OUT/obj" -o "$OUT/loki97-reference" "$HERE/loki97_reference_driver.c"
# Crypto++'s assembly paths are compiled out, so its portable C++ is the
# witness on every machine.
for f in algparam allocate cryptlib filters fips140 misc mqueue queue safer skipjack square \
         squaretb gf256 3way lea hight speck simon threefish sha iterhash cpu; do
    c++ -O2 -DNDEBUG -DCRYPTOPP_DISABLE_ASM -w -I"$OUT/src/cryptopp" \
        -c "$OUT/src/cryptopp/$f.cpp" -o "$OUT/obj/$f.o"
done
# cryptopp NAME CLASS FILE [MORE...]: the driver over CLASS from FILE.h,
# linked with FILE's object and any MORE the class needs; a MORE that
# starts with - is a flag for the driver's compilation instead.
cryptopp() {
    name=$1 class=$2 file=$3
    shift 3
    more="" flags=""
    for f in "$@"; do
        case "$f" in
            -*) flags="$flags $f" ;;
            *) more="$more $OUT/obj/$f.o" ;;
        esac
    done
    c++ -O2 -DNDEBUG -DCRYPTOPP_DISABLE_ASM -w -I"$OUT/src/cryptopp" -I"$NESSIE" -DCLASS="$class" \
        -DHEADER="\"$file.h\"" $flags -c "$HERE/cryptopp_driver.cpp" -o "$OUT/obj/driver-$class.o"
    c++ -o "$OUT/$name" "$OUT/obj/driver-$class.o" "$OUT/obj/$file.o" $more "$OUT"/obj/algparam.o \
        "$OUT"/obj/allocate.o "$OUT"/obj/cryptlib.o "$OUT"/obj/filters.o "$OUT"/obj/fips140.o \
        "$OUT"/obj/misc.o "$OUT"/obj/mqueue.o "$OUT"/obj/queue.o
}
cryptopp skipjack-reversed-cryptopp SKIPJACK skipjack
# One class for both key lengths; the length picks the variant.
cryptopp safer-k64-cryptopp SAFER_K safer
cryptopp safer-sk64-cryptopp SAFER_SK safer
cp "$OUT/safer-k64-cryptopp" "$OUT/safer-k128-cryptopp"
cp "$OUT/safer-sk64-cryptopp" "$OUT/safer-sk128-cryptopp"
cryptopp square-cryptopp Square square squaretb gf256
cryptopp threeway-cryptopp ThreeWay 3way
cryptopp lea-cryptopp LEA lea
cryptopp hight-cryptopp HIGHT hight
# One class per block size; the key length picks the variant.
cryptopp speck64-cryptopp SPECK64 speck
cryptopp speck128-cryptopp SPECK128 speck
cryptopp simon64-cryptopp SIMON64 simon
cryptopp simon128-cryptopp SIMON128 simon
# The key alone or with the tweak after it.
for bits in 256 512 1024; do
    cryptopp threefish$bits-cryptopp Threefish$bits threefish -DTWEAKED
done
# kurtfu/present, once per key size, its two functions renamed for each;
# its assertions are its own assert.h, which its include directory puts
# before the system's.
for size in 80 128; do
    def=""
    [ $size = 128 ] && def=-DKEY128
    cc -O1 -w $def -I"$HERE/shim/present" -I"$OUT/src/kurtfu" -Dpresent_encrypt=present${size}_encrypt \
        -Dpresent_decrypt=present${size}_decrypt -c "$OUT/src/kurtfu/present.c" \
        -o "$OUT/obj/kurtfu/present$size.o"
done
cc -O1 -w -I"$OUT/src/kurtfu" -c "$OUT/src/kurtfu/assert.c" -o "$OUT/obj/kurtfu/assert.o"
cc -O1 -w -I"$NESSIE" -o "$OUT/present-kurtfu" "$HERE/present_kurtfu_driver.c" \
    "$OUT/obj/kurtfu/present80.o" "$OUT/obj/kurtfu/present128.o" "$OUT/obj/kurtfu/assert.o"
# OpenTitan's Python PRESENT, by its driver.
cp "$HERE/opentitan_driver.py" "$OUT/opentitan_driver.py"
printf '#!/bin/sh\nexec python3 -I "%s/opentitan_driver.py" "%s/src/opentitan"\n' "$OUT" "$OUT" \
    > "$OUT/present-opentitan"
chmod +x "$OUT/present-opentitan"
# FEAL-NX: the Java with its witness class, and the Python by its driver.
javac -nowarn -d "$OUT/feal" "$HERE/FealWitness.java" "$OUT/src/feal/fealnx.java"
printf '#!/bin/sh\nexec java -cp "%s/feal" FealWitness 2>/dev/null\n' "$OUT" > "$OUT/feal-nx-zilijonas"
cp "$HERE/feal_driver.py" "$OUT/feal_driver.py"
printf '#!/bin/sh\nexec python3 -I "%s/feal_driver.py" "%s/src/feal"\n' "$OUT" "$OUT" \
    > "$OUT/feal-nx-donaldduck8"
chmod +x "$OUT/feal-nx-zilijonas" "$OUT/feal-nx-donaldduck8"
# SHACAL-1 from the two SHA-1 compression functions.
c++ -O2 -DNDEBUG -DCRYPTOPP_DISABLE_ASM -DCRYPTOPP -w -I"$OUT/src/cryptopp" -I"$NESSIE" \
    -o "$OUT/shacal1-cryptopp" "$HERE/shacal1_driver.cpp" "$OUT"/obj/sha.o "$OUT"/obj/iterhash.o \
    "$OUT"/obj/cpu.o "$OUT"/obj/algparam.o "$OUT"/obj/allocate.o "$OUT"/obj/cryptlib.o \
    "$OUT"/obj/filters.o "$OUT"/obj/fips140.o "$OUT"/obj/misc.o "$OUT"/obj/mqueue.o "$OUT"/obj/queue.o
c++ -O1 -w -I"$NESSIE" -o "$OUT/shacal1-openssl" "$HERE/shacal1_driver.cpp" -lcrypto
# go-krypto's pure Go, offline, against the checkout.
mkdir -p "$OUT/go"
cp "$HERE/go/driver.go" "$OUT/go/"
printf 'module github.com/Nirusu/PRESENT.go\n\ngo 1.15\n' > "$OUT/src/presentgo/go.mod"
printf 'module oldcipherswitness\n\ngo 1.21\n\nrequire (\n\tgithub.com/RyuaNerin/go-krypto v0.0.0\n\tgithub.com/Nirusu/PRESENT.go v0.0.0\n)\n\nreplace github.com/RyuaNerin/go-krypto => %s\n\nreplace github.com/Nirusu/PRESENT.go => %s\n' \
    "$OUT/src/go-krypto" "$OUT/src/presentgo" > "$OUT/go/go.mod"
(cd "$OUT/go" && GOFLAGS=-mod=mod GOPROXY=off go build -tags purego -o "$OUT/go/driver" .)
for cipher in lea hight; do
    printf '#!/bin/sh\nexec "%s/go/driver" %s\n' "$OUT" "$cipher" > "$OUT/$cipher-gokrypto"
    chmod +x "$OUT/$cipher-gokrypto"
done
printf '#!/bin/sh\nexec "%s/go/driver" present\n' "$OUT" > "$OUT/present-presentgo"
chmod +x "$OUT/present-presentgo"
cp "$JAR" "$OUT/bc/bcprov.jar"
javac -cp "$OUT/bc/bcprov.jar" -d "$OUT/bc" "$HERE/OldCipherWitness.java"
for cipher in skipjack threefish256 threefish512 threefish1024; do
    printf '#!/bin/sh\nexec java -cp "%s/bc/bcprov.jar:%s/bc" OldCipherWitness %s 2>/dev/null\n' \
        "$OUT" "$OUT" "$cipher" > "$OUT/$cipher-bc"
    chmod +x "$OUT/$cipher-bc"
done
python3 "$HERE/selftest.py" "$OUT"
echo "$OUT"
