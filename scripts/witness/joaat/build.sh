#!/bin/sh
# Builds /opt/joaatwitness: Jenkins's one-at-a-time from three
# implementations, the two not on the system fetched once from GitHub at
# pinned commits and checked against joaat.sha256.
#
# - PHP's ext/hash, with driver.php: php-witness. joaat, from zero; PHP
#   takes no seed.
# - Perl 5.24's S_perl_hash_old_one_at_a_time (Perl/perl5, hv_func.h),
#   cut out of the header, with driver_perl.c: perl-witness. Seeded:
#   Perl starts the hash from its seed.
# - gVisor's pkg/tcpip/hash/jenkins (google/gvisor), compiled with the
#   system's go, offline, with go/driver.go: gvisor-witness. Seeded, its
#   state being an exported type to start from.
#
# Before reporting success the witnesses must agree on one input;
# scripts/make_joaat_vectors.py compares the rest.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/joaatwitness}
GH=https://raw.githubusercontent.com
GVISOR=$GH/google/gvisor/74790145a973ef73bb23198016bb20b60b187f53
PERL=$GH/Perl/perl5/be2c0c650b028f54e427f2469a59942edfdff8a9
mkdir -p "$OUT/go" "$OUT/src"
for f in $(cut -c67- "$HERE/joaat.sha256"); do
    case "$f" in
        gvisor/*) url=$GVISOR/${f#gvisor/} ;;
        perl5/*) url=$PERL/${f#perl5/} ;;
    esac
    mkdir -p "$OUT/src/$(dirname "$f")"
    [ -f "$OUT/src/$f" ] || curl -sSfL -o "$OUT/src/$f" "$url"
done
(cd "$OUT/src" && sha256sum -c --quiet "$HERE/joaat.sha256")

printf '#!/bin/sh\nexec php %s/driver.php\n' "$HERE" > "$OUT/php-witness"
# The function, from its name to its closing brace; its return type is on
# the line before, and the driver writes that.
sed -n '/^S_perl_hash_old_one_at_a_time(/,/^}/p' "$OUT/src/perl5/hv_func.h" > "$OUT/perl_oaat.h"
grep -q 'hash += \*str++;' "$OUT/perl_oaat.h"
cc -O1 -w -I"$OUT" -o "$OUT/perl-witness" "$HERE/driver_perl.c"

printf 'module gvisor.dev/gvisor\n\ngo 1.22\n' > "$OUT/src/gvisor/go.mod"
cp "$HERE/go/driver.go" "$OUT/go/"
cat > "$OUT/go/go.mod" <<GOMOD
module joaatwitness

go 1.22

require gvisor.dev/gvisor v0.0.0

replace gvisor.dev/gvisor => $OUT/src/gvisor
GOMOD
(cd "$OUT/go" && GOFLAGS=-mod=mod GOPROXY=off go build -o "$OUT/gvisor-witness" .)
chmod +x "$OUT/php-witness"

printf 'Bob Jenkins' > "$OUT/check"
for w in php perl gvisor; do
    echo "joaat seed:00000000 $OUT/check" | "$OUT/$w-witness"
done | sort -u | wc -l | grep -qx 1 || { echo "the witnesses disagree"; exit 1; }
echo "built $OUT"
