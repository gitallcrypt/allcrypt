#!/bin/sh
# Builds /opt/lmswitness: other implementations of LMS and HSS (RFC 8554,
# RFC 9858), as witnesses for vectors/lms.vec.
#
#   hashsigs  Cisco's hash-sigs, by the RFC 8554 authors, its "192" branch
#             (cisco/hash-sigs d711fa7), which has RFC 9858's parameter
#             sets, built single-threaded with SECRET_METHOD 2 - RFC 8554
#             Appendix A's key derivation, its default - under
#             hashsigs_driver.c. It takes OpenSSL's SHA-256, as it does by
#             default. Signs trees and hierarchies, verifies.
#   bc        Bouncy Castle 1.77's LMS and HSS, from the jar the system
#             ships, under LmsWitness.java. Signs trees and hierarchies,
#             verifies.
#   pyhsslms  Russ Housley's pyhsslms 2.0.0, from PyPI with its hash
#             required, under lms_python.py. Signs trees, verifies.
#   hbs-lms   The hbs-lms 0.2.0-alpha.1 crate, under rust_lms/, pinned with
#             its checksum by rust_lms/Cargo.lock. Verifies, the SHA-256/256
#             parameter sets only.
#
# The hash-sigs files are fetched from raw.githubusercontent.com by commit
# and checked against hashsigs.sha256. selftest.py then requires RFC 8554's
# and RFC 9858's worked examples of every witness that can take them, and
# the witnesses to agree over keys of every parameter set.
#
# CFLAGS_EXTRA goes to the C compile - "-fsanitize=address,undefined -g"
# for a sanitizer run.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/lmswitness}
JAR=${2:-/usr/share/java/bcprov-1.77.jar}
CFLAGS_EXTRA=${CFLAGS_EXTRA:-}
mkdir -p "$OUT/src/hash-sigs"

HS=https://raw.githubusercontent.com/cisco/hash-sigs/d711fa7c8a7a00e234dc4d58af05abd71f7181a5
while read -r sum name; do
    f="$OUT/src/hash-sigs/$name"
    [ -f "$f" ] || curl -sSf -o "$f" "$HS/$name"
    echo "$sum  $f" | sha256sum -c --quiet -
done < "$HERE/hashsigs.sha256"
(cd "$OUT/src/hash-sigs" && cc -O2 $CFLAGS_EXTRA -Wno-deprecated-declarations -I. \
    -o "$OUT/hashsigs" "$HERE/hashsigs_driver.c" \
    $(grep '\.c$' "$HERE/hashsigs.sha256" | awk '{print $2}') -lcrypto)

mkdir -p "$OUT/bc"
javac -nowarn -Xlint:none -d "$OUT/bc" -cp "$JAR" "$HERE/LmsWitness.java"
printf '#!/bin/sh\nexec java -cp "%s/bc:%s" LmsWitness 2>/dev/null\n' "$OUT" "$JAR" > "$OUT/bc-lms"
chmod +x "$OUT/bc-lms"

python3 -m pip install -q --no-deps --require-hashes --target "$OUT/py" \
    -r "$HERE/requirements.txt"
cp "$HERE/lms_python.py" "$OUT/lms_python.py"
printf '#!/bin/sh\nexec python3 -I "%s/lms_python.py" "%s/py"\n' "$OUT" "$OUT" > "$OUT/pyhsslms"
chmod +x "$OUT/pyhsslms"

rm -rf "$OUT/rust_lms"
cp -r "$HERE/rust_lms" "$OUT/rust_lms"
(cd "$OUT/rust_lms" && cargo build -q --release --locked)
cp "$OUT/rust_lms/target/release/lms-witness" "$OUT/hbs-lms"

python3 "$HERE/selftest.py" "$OUT"
echo "$OUT"
