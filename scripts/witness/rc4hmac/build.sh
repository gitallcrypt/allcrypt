#!/bin/sh
# Builds /opt/rc4hmacwitness: other implementations of Kerberos's
# RC4-HMAC (RFC 4757), as witnesses for vectors/rc4_hmac.vec.
#
#   mit-krb5   MIT Kerberos 1.21.3's libk5crypto through
#              scripts/witness/krb5witness/main.c, linked against the
#              installation in $KRB5 (default /opt/krb5; docs/building.md,
#              "Kerberos", builds it - from the release tarball, or from
#              the krb5-1.21.3-final tag of github.com/krb5/krb5 after
#              autoreconf -fi). Types 23 and 24, the -138 checksum, the
#              PRF and string-to-key. Encryption draws its own confounder.
#   impacket   impacket 0.13.1's krb5/crypto.py, from the wheel pip
#              fetches, checked against its SHA-256 and unpacked under
#              $OUT/impacket; it needs pycryptodomex and six on the
#              system's Python. Type 23, the checksum, the PRF and
#              string-to-key; it has no export type. Encryption takes the
#              confounder as an argument.
#   kerby      Apache Kerby's kerb-crypto (apache/directory-kerby,
#              db7a0a0), the classes KerbyRc4Witness.java reaches,
#              compiled from source by javac. Types 23 and 24, the
#              checksum, the PRF and string-to-key; encryption draws its
#              own confounder.
#
# The protocol is KerbyRc4Witness.java's, which mit-krb5 and the
# generator's impacket shim also speak (mit-krb5 has its own, wrapped
# by the generator). selftest.py then requires the three to agree.
#
# CFLAGS_EXTRA goes to the C compile - "-fsanitize=address,undefined -g"
# for a sanitizer run; MIT's own library is not instrumented by it.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/rc4hmacwitness}
KRB5=${KRB5:-/opt/krb5}
CFLAGS_EXTRA=${CFLAGS_EXTRA:-}
mkdir -p "$OUT/src"

gcc -O2 $CFLAGS_EXTRA "$HERE/../krb5witness/main.c" -I"$KRB5/include" -L"$KRB5/lib" \
    -Wl,--disable-new-dtags,-rpath,"$KRB5/lib" -lkrb5 -lk5crypto -lcom_err \
    -o "$OUT/mit-krb5"

WHEEL=impacket-0.13.1-py3-none-any.whl
WHEEL_SHA256=3e5349c1209cdd3b90bff6f8b61c0d89aea0f3dbba6ad02ad254b9d3ef2301d0
if [ ! -f "$OUT/src/$WHEEL" ]; then
    python3 -m pip download -q --no-deps -d "$OUT/src" impacket==0.13.1
fi
echo "$WHEEL_SHA256  $OUT/src/$WHEEL" | sha256sum -c -
rm -rf "$OUT/impacket"
mkdir -p "$OUT/impacket"
python3 -m zipfile -e "$OUT/src/$WHEEL" "$OUT/impacket"

KERBY_COMMIT=db7a0a092633c357970e73735dd222e7c284da7f
if [ ! -d "$OUT/src/directory-kerby" ]; then
    git init -q "$OUT/src/directory-kerby"
    git -C "$OUT/src/directory-kerby" fetch -q --depth 1 \
        https://github.com/apache/directory-kerby "$KERBY_COMMIT"
    git -C "$OUT/src/directory-kerby" checkout -q FETCH_HEAD
fi
[ "$(git -C "$OUT/src/directory-kerby" rev-parse HEAD)" = "$KERBY_COMMIT" ] \
    || { echo "directory-kerby is not at $KERBY_COMMIT"; exit 1; }
K="$OUT/src/directory-kerby"
SRC="$K/kerby-kerb/kerb-crypto/src/main/java:$K/kerby-kerb/kerb-core/src/main/java"
SRC="$SRC:$K/kerby-common/kerby-asn1/src/main/java:$K/kerby-common/kerby-util/src/main/java"
SRC="$SRC:$K/kerby-common/kerby-config/src/main/java"
rm -rf "$OUT/kerby-classes"
mkdir -p "$OUT/kerby-classes"
javac -nowarn -d "$OUT/kerby-classes" -sourcepath "$SRC" "$HERE/KerbyRc4Witness.java"
printf '#!/bin/sh\nexec java -cp "%s" KerbyRc4Witness\n' "$OUT/kerby-classes" > "$OUT/kerby"
chmod +x "$OUT/kerby"

python3 "$HERE/selftest.py" "$OUT"
echo "$OUT"
