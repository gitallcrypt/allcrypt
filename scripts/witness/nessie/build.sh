#!/bin/sh
# Builds /opt/nessie: witnesses for the NESSIE block ciphers, from
# sources fetched once and checked against nessie.sha256.
#
#   libtomcrypt/  libtomcrypt 1.18.2's cipher files (libtom/libtomcrypt,
#                 tag v1.18.2), compiled against shim/tomcrypt.h instead
#                 of the rest of the library, by ltc_driver.c
#   linux/        the Linux kernel's crypto/ modules (torvalds/linux, tag
#                 v6.6), compiled against shim/kernel.h by linux_driver.c,
#                 and crypto/testmgr.h, for its test vectors
#   cryptopp/     Crypto++ 8.9.0's cipher files with the few library files
#                 they link against (weidai11/cryptopp, tag CRYPTOPP_8_9_0),
#                 by cryptopp_driver.cpp, and TestVectors/, for its tests
#   botan3/       Botan 3.6.1's src/tests/data/block/ test files
#   botan/        Botan 1.10.17's cipher files (randombit/botan, tag
#                 1.10.17), compiled against shim/botan by
#                 botan_driver.cpp, and checks/validate.dat, for its tests
#   bc/           Bouncy Castle's engines, through NessieWitness.java,
#                 compiled against the bcprov jar the system ships (1.77
#                 here; pass another as the second argument)
#   reference/    the designers' reference code, where a copy survives:
#                 Anubis's as Crypt::Anubis 1.0.4 ships it (gitpan/
#                 Crypt-Anubis), through its NESSIE API by
#                 reference_driver.c
#
# One program per implementation, named <cipher>-<source>; driver.h has
# the request format. Before reporting success, selftest.py requires
# every program to reproduce the published vectors the projects carry.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/nessie}
JAR=${2:-/usr/share/java/bcprov-1.77.jar}
LTC=https://raw.githubusercontent.com/libtom/libtomcrypt/v1.18.2/src/ciphers
LINUX=https://raw.githubusercontent.com/torvalds/linux/v6.6/crypto
REFERENCE=https://raw.githubusercontent.com/gitpan/Crypt-Anubis/master
BOTAN=https://raw.githubusercontent.com/randombit/botan/1.10.17
BOTAN3=https://raw.githubusercontent.com/randombit/botan/3.6.1/src/tests/data/block
CPP=https://raw.githubusercontent.com/weidai11/cryptopp/CRYPTOPP_8_9_0
mkdir -p "$OUT/src/libtomcrypt" "$OUT/src/linux" "$OUT/src/reference" "$OUT/src/botan/botan" \
    "$OUT/src/cryptopp" "$OUT/src/botan3" "$OUT/kinc/crypto" "$OUT/kinc/linux" "$OUT/kinc/asm" \
    "$OUT/bc" "$OUT/obj"
cd "$OUT/src"
for f in $(cut -c67- "$HERE/nessie.sha256"); do
    case "$f" in
        libtomcrypt/*) base=$LTC ;;
        linux/*) base=$LINUX ;;
        reference/*) base=$REFERENCE ;;
        botan/validate.dat) base=$BOTAN/checks ;;
        botan/*) name=${f#botan/}; base=$BOTAN/src/block/${name%.*} ;;
        botan3/*) base=$BOTAN3 ;;
        cryptopp/*.txt) base=$CPP/TestVectors ;;
        cryptopp/*) base=$CPP ;;
    esac
    [ -f "$f" ] || curl -sSfL -o "$f" "$base/${f#*/}"
done
sha256sum -c --quiet "$HERE/nessie.sha256"
# The kernel headers the modules include, as empty files: shim/kernel.h
# is passed with -include and defines what they would have.
for h in crypto/algapi.h linux/init.h linux/module.h linux/mm.h asm/byteorder.h \
         linux/types.h; do
    : > "$OUT/kinc/$h"
done
ltc() {
    name=$1 desc=$2 source=$3
    shift 3
    cc -O1 -w -I"$HERE/shim" -I"$OUT/src/libtomcrypt" -DDESC="$desc" -DSOURCE="\"$source\"" \
        "$@" -o "$OUT/$name" "$HERE/ltc_driver.c"
}
linux() {
    cc -O1 -w -I"$OUT/kinc" -include "$HERE/shim/kernel.h" -I"$OUT/src/linux" \
        -DALG="$2" -DSOURCE="\"$3\"" -o "$OUT/$1" "$HERE/linux_driver.c"
}
reference() {
    cc -O1 -w -I"$HERE/shim/reference" -I"$OUT/src/reference" -Dmain=reference_main \
        -DSOURCE="\"$2\"" -o "$OUT/$1" "$HERE/reference_driver.c"
}
ltc khazad-libtomcrypt khazad_desc khazad.c
linux khazad-linux khazad_alg khazad.c
# The tweaked Anubis, which libtomcrypt builds only when asked.
ltc anubis-libtomcrypt anubis_desc anubis.c -DLTC_ANUBIS_TWEAK
linux anubis-linux anubis_alg anubis.c
reference anubis-reference _anubis.c
# Botan's headers are included as <botan/name.h>.
cp "$OUT/src/botan/noekeon.h" "$OUT/src/botan/botan/noekeon.h"
botan() {
    c++ -std=c++11 -O1 -w -I"$HERE/shim/botan" -I"$OUT/src/botan" -DCLASS="$2" \
        -DHEADER="<botan/$3.h>" -o "$OUT/$1" "$HERE/botan_driver.cpp" "$OUT/src/botan/$3.cpp"
}
ltc noekeon-libtomcrypt noekeon_desc noekeon.c
botan noekeon-indirect-botan Noekeon noekeon
cp "$JAR" "$OUT/bc/bcprov.jar"
javac -cp "$OUT/bc/bcprov.jar" -d "$OUT/bc" "$HERE/NessieWitness.java"
# Crypto++'s assembly paths are compiled out, so its portable C++ is the
# witness on every machine.
for f in algparam allocate cryptlib filters fips140 misc mqueue queue shacal2; do
    c++ -O2 -DNDEBUG -DCRYPTOPP_DISABLE_ASM -w -I"$OUT/src/cryptopp" \
        -c "$OUT/src/cryptopp/$f.cpp" -o "$OUT/obj/$f.o"
done
cryptopp() {
    c++ -O2 -DNDEBUG -DCRYPTOPP_DISABLE_ASM -w -I"$OUT/src/cryptopp" -I"$HERE" -DCLASS="$2" \
        -DHEADER="\"$3.h\"" -c "$HERE/cryptopp_driver.cpp" -o "$OUT/obj/driver-$3.o"
    c++ -o "$OUT/$1" "$OUT/obj/driver-$3.o" "$OUT/obj/$3.o" "$OUT"/obj/algparam.o \
        "$OUT"/obj/allocate.o "$OUT"/obj/cryptlib.o "$OUT"/obj/filters.o "$OUT"/obj/fips140.o \
        "$OUT"/obj/misc.o "$OUT"/obj/mqueue.o "$OUT"/obj/queue.o
}
cryptopp shacal2-cryptopp SHACAL2 shacal2
for cipher in noekeon noekeon-indirect shacal2; do
    printf '#!/bin/sh\nexec java -cp "%s/bc/bcprov.jar:%s/bc" NessieWitness %s 2>/dev/null\n' \
        "$OUT" "$OUT" "$cipher" > "$OUT/$cipher-bc"
    chmod +x "$OUT/$cipher-bc"
done
python3 "$HERE/selftest.py" "$OUT"
echo "$OUT"
