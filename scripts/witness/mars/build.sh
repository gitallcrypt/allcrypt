#!/bin/sh
# Builds /opt/mars: two MARS witnesses, from sources fetched once and
# checked against their SHA-256.
#
#   mars-cryptopp  Crypto++ 8.9.0's mars.cpp with the few library files it
#                  links against (weidai11/cryptopp, tag CRYPTOPP_8_9_0)
#   mars-botan     Botan 1.10.17's src/block/mars (randombit/botan, tag
#                  1.10.17), the last Botan with MARS, compiled against
#                  the shim in botan_shim/ instead of the rest of Botan
#
# Crypto++'s TestVectors/mars.txt is fetched with them; it carries the
# tweaked key schedule's published vectors and six Monte Carlo tests, and
# both witnesses must reproduce every one of them before this script
# reports success. driver_common.h has the request format.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/mars}
CPP=https://raw.githubusercontent.com/weidai11/cryptopp/CRYPTOPP_8_9_0
BOTAN=https://raw.githubusercontent.com/randombit/botan/1.10.17/src/block/mars
mkdir -p "$OUT/cryptopp" "$OUT/botan/botan"
cd "$OUT/cryptopp"
for f in \
    aes.h \
    algparam.cpp \
    algparam.h \
    allocate.cpp \
    allocate.h \
    argnames.h \
    config.h \
    config_align.h \
    config_asm.h \
    config_cpu.h \
    config_cxx.h \
    config_dll.h \
    config_int.h \
    config_misc.h \
    config_ns.h \
    config_os.h \
    config_ver.h \
    cpu.h \
    cryptlib.cpp \
    cryptlib.h \
    filters.cpp \
    filters.h \
    fips140.cpp \
    fips140.h \
    fltrimpl.h \
    hkdf.h \
    hmac.h \
    integer.h \
    iterhash.h \
    mars.cpp \
    mars.h \
    marss.cpp \
    misc.cpp \
    misc.h \
    mqueue.cpp \
    mqueue.h \
    osrng.h \
    ossig.h \
    pch.h \
    queue.cpp \
    queue.h \
    randpool.h \
    rijndael.h \
    rng.h \
    secblock.h \
    secblockfwd.h \
    seckey.h \
    sha.h \
    simple.h \
    smartptr.h \
    stdcpp.h \
    trap.h \
    words.h \
    ; do
    curl -sSfL -o "$f" "$CPP/$f"
done
curl -sSfL -o mars.txt "$CPP/TestVectors/mars.txt"
echo "\
fbd98402a8ddab54389a433c5685356bf3d3ad2ae37747c242a593667379a683  aes.h
21507624ed28b946e58c22e55b2821a053490b06d449d2f6948493a23e1c300a  algparam.cpp
a0c1352f81ca19aee1329e00af0e8e298131851a5449ecd042e370a73d8d09d4  algparam.h
1a933d1ec1a8245817464c28c00762371039d0caf210e76cdbeff16a626948b2  allocate.cpp
6fbcf40f97fb72c1523bb597d28337623997bc5610f235b9d440b22289b6f970  allocate.h
4fa6995e67001c2b744d64e2f7f36629cf489be21f1ff242fbc13da43df59769  argnames.h
641a512721c40a6778dfcc143b611c6204f38916bae55d391e2c74c18b70b2f6  config.h
3a3f596ac05567c75b79d736319e561cf5ea01e06573d78bd479fb8673492bb3  config_align.h
b1486213b61a024b0cfe6918d5760ec97d22448a0f280a692ad252df365ee1f3  config_asm.h
0126771f1c78c6532275407261e9c2dd7888e6365ccda0ebb582d936f8c0bbe3  config_cpu.h
0a5042e6ea886e2c38a9626585deb1409a56dbcd35a522e877b648fb9042a366  config_cxx.h
5f5f25287fc9a0bd49230edebaf6377b64f8020aa04d843cdd1a5449dd34c5e4  config_dll.h
99a41cf87cb25c898fe438f4ba1e9dbe209e652a0328bacc1adf5d6e4ff848b6  config_int.h
1918df9919402f747b862bffd1235f4087be76d48d34d4e3b9ee2820ed526823  config_misc.h
c4bc5ebf250efea647afb1873fb89f6b9dc540485f6f569f8b868cd9e8994ef9  config_ns.h
7a876d8032295b3e813dcafd2ea6788c527985c8464273e23d7c4d07c6b5c0c6  config_os.h
9a0db3ff548ba011097a62546a03f12aabe3c4a42925bbbb53668ad047bcd095  config_ver.h
7aefc7004658da82cebc7e7b9aba8b282464325d84051d29c7d4867acc00bb3f  cpu.h
8969994d41454d0691fff848fbb77a8afdae0f16e04fb3f6d16dfa1469fe3051  cryptlib.cpp
12eb02d2bdf953ffd90d0c8ddcaf800dcb3e1890b8f0ea93b533b4087e82785c  cryptlib.h
a6950603d3b4ca9edb128673898dd6a61d4274e0ea2d70ce77e7d0fcf338b404  filters.cpp
783038cf6411bcddcd92c0b900cbfbb4c9038dbfe828ae8fda444313215cf4a9  filters.h
fbf6cc4cf9b53828828c2de7e9963c9a82ef4f43fcf8819b61c0f2369774eae1  fips140.cpp
cb4042de79c44789f6730c331dab5cb2ad6d10730e24557084f363c0daf71f34  fips140.h
a985b68b2480dfeeaf9d6eb39baf117191fb1d9cbbe42199f33b7a00a851dce6  fltrimpl.h
1ccedcd401635ac077d895f147ef142645ad7216205d4adf46899e35e8222b5b  hkdf.h
f8becd33fc708ac1bbcc1929d34fb0f8f7f7b7592f52bc5d8e985d862c0e8cbb  hmac.h
524baaeae6f5d23b9c07c13c3b34f1c89971d40357385a40b6346886f8b40d84  integer.h
397298f1eadcfe7165f8b86670a7879641244e7a48aab62fe910dd3fc6eb3ff5  iterhash.h
87e5d61c8b54025479bfe50ca4a8228cb3ed87a79c4a1bde749e61981acbfcf1  mars.cpp
446094ab5a35051ca32cda9af496b2968736c7c15d15520037a70304bf6ad382  mars.h
2003ac72500d317833125b61f7baf5b2e47a84771b27c7180235b0ef6b402e84  marss.cpp
a3728752463001070a44838ad61e9aa651d29770422148125665a5c5dd720307  misc.cpp
13de68cfefceff3cc97f980a61b56931cff5bccac9eece0a6d6ab2bc98daa44d  misc.h
5e4a1cf20b60dc8e41298acf4bf68a0acd511e64755d07ca5846baef40d27f64  mqueue.cpp
dd95c25b41b7f750346585e648e4c59a2d585058df808f466a5e763c2a2e1a55  mqueue.h
eba8e5d21f62a4b2f4ff0b5b94c93d7b7ff95d54e15dd082f19a1f2cf4e331cb  osrng.h
3b702f8b2f37eed7e1c8cd9a3da3d1fd11d16d1cd7f13b80e459d5e4da5f87e0  ossig.h
d629cfec26c9317f637137f137550f6f8138292acfd677baf0a986a1db80056b  pch.h
723cf6825c8ce9b742182e6c47dec88161c443e001f6141d9254acf07294e3e4  queue.cpp
7a223d51a78bea39e6a7bdd02ae58cabfdda561e81e461550d240c47f8bd0264  queue.h
1d29d8662ebab0da03dc7782e886df16656549ae7c89983c53d89f4779e6785b  randpool.h
d82187fd5e08a45a74e9aac8a0b9197856ff879d072cdad8b204e6915fbabb4a  rijndael.h
40f2532cf14e950080bb1ba1383c52a2e5af0ab09779de89524f066735b6fa2b  rng.h
7d83f568a249e674772fddeea33d4c1bf7b403a880aac82298ebf4729f597d7d  secblock.h
472e5d0fa333257c3b8254e5fddbcbaa803dae920f65d64542219c0b3b8400cf  secblockfwd.h
54204f1ae34214150d0087043c19e25e83abe010837ef214a232891598501cfa  seckey.h
9d9cb08b466b520a21a9549ce438aba5f4c0479e46240a4c4f9160a930962d7c  sha.h
41a165d3b4ffce87755b28b878e08503d571558cffe5877b7e00cb84226ef373  simple.h
a2d6f834c9e2890943a203ce7397976d8618e62c3d56f6a6afa456ffdc22e879  smartptr.h
35f068b2521c8ee31eeb1ea2810a352148a2854f47683363f914be4f090ef750  stdcpp.h
a82a30348451a7d113ddea392d03b834085802dd05c12c265546d3b90599403f  trap.h
1b90ca646c5fa044f4b6c43a998bd5a65aca0963dcd94295b7cf642cb98eef64  words.h
5d30444892b2c9b7c0989e75e71cc5d41812a16ab752761bb2d0ed80c15cd620  mars.txt
" | sha256sum -c --quiet
for f in algparam allocate cryptlib filters fips140 mars marss misc mqueue queue; do
    c++ -O2 -DNDEBUG -w -I. -c "$f.cpp"
done
c++ -O2 -DNDEBUG -w -I. -I"$HERE" -c "$HERE/driver_cryptopp.cpp" -o driver.o
c++ -o "$OUT/mars-cryptopp" algparam.o allocate.o cryptlib.o filters.o fips140.o \
    mars.o marss.o misc.o mqueue.o queue.o driver.o

cd "$OUT/botan"
curl -sSfL -o mars.cpp "$BOTAN/mars.cpp"
curl -sSfL -o botan/mars.h "$BOTAN/mars.h"
echo "\
34c4111cde581a6788bf6a320b68cdfbbe3aa6c43f15b662e6ae4a1c1d087c86  mars.cpp
abd1313ee55ed2729ae60af86fb886fc62d74f020ad0cb561f67a6f3ab105791  botan/mars.h" \
    | sha256sum -c --quiet
c++ -O2 -w -I. -I"$HERE/botan_shim" -I"$HERE" -o "$OUT/mars-botan" mars.cpp "$HERE/driver_botan.cpp"

python3 -I "$HERE/selftest.py" "$OUT/cryptopp/mars.txt" "$OUT/mars-cryptopp" "$OUT/mars-botan"
echo "$OUT"
