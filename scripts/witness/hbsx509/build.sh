#!/bin/sh
# Builds /opt/hbswitness: Bouncy Castle 1.85's HSS, XMSS and XMSS^MT in
# X.509 (RFC 9802) and CMS (RFC 9708), as a witness for
# vectors/hbs_x509.vec.
#
#   bc-hbs   bcgit/bc-java at tag r1rv85 (57fbd3c), its core, prov, pkix
#            and util sources fetched sparsely, and the classes
#            HbsX509Witness.java reaches compiled by javac - with the PQC
#            provider's LMS and XMSS registrations and the provider's
#            digests, which the JCA looks up by name and javac would not
#            find on its own. 1.77, the jar
#            the system ships, predates RFC 9802: it writes XMSS keys under
#            Bouncy Castle's own OIDs.
#
# selftest.py then requires it to verify RFC 9802's three appendix
# certificates and to write their keys back byte for byte, and to verify
# a CMS message of its own and refuse it over other content.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/hbswitness}
COMMIT=57fbd3c501f7a369f64eda311d6a709fc0bcae84
mkdir -p "$OUT/src"
B="$OUT/src/bc-java"
if [ ! -d "$B" ]; then
    git init -q "$B"
    git -C "$B" config core.sparseCheckout true
    printf 'core/src/main/java/\nprov/src/main/java/\npkix/src/main/java/\nutil/src/main/java/\nLICENSE.html\n' \
        > "$B/.git/info/sparse-checkout"
    git -C "$B" fetch -q --depth 1 --filter=blob:none https://github.com/bcgit/bc-java "$COMMIT"
    git -C "$B" checkout -q FETCH_HEAD
fi
[ "$(git -C "$B" rev-parse HEAD)" = "$COMMIT" ] || { echo "bc-java is not at $COMMIT"; exit 1; }
SRC="$B/core/src/main/java:$B/prov/src/main/java:$B/pkix/src/main/java:$B/util/src/main/java"
P="$B/prov/src/main/java/org/bouncycastle/pqc/jcajce/provider"
D="$B/prov/src/main/java/org/bouncycastle/jcajce/provider/digest"
rm -rf "$OUT/classes"
mkdir -p "$OUT/classes"
javac -nowarn -d "$OUT/classes" -sourcepath "$SRC" "$HERE/HbsX509Witness.java" \
    "$P/LMS.java" "$P/XMSS.java" "$P"/lms/*.java "$P"/xmss/*.java "$D"/*.java
printf '#!/bin/sh\nexec java -cp "%s" HbsX509Witness\n' "$OUT/classes" > "$OUT/bc-hbs"
chmod +x "$OUT/bc-hbs"

python3 "$HERE/selftest.py" "$OUT"
echo "$OUT"
