#!/bin/sh
# Build age 1.3.2 into PREFIX/bin - age, age-keygen, age-inspect, its
# plugins (age-plugin-batchpass, -pq, -tag, -tagpq) - and age-tag-witness
# (main.go here), which opens files to age's tagged recipients with
# age's own test identities.
#
#   sh scripts/witness/agetag/build.sh /opt/age132
#
# age's module wants a newer Go than may be here and fetches its
# dependencies from vanity hosts through the module proxy. Each is
# cloned instead from its GitHub mirror at the version age's go.mod
# names, `replace`d, and the go lines lowered to the local toolchain's.
# The witness sits inside age's tree, at tag/tagwitness, because the test
# identities are in an internal package there.
set -eu
PREFIX=${1:?usage: build.sh PREFIX}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
clone() { git -c advice.detachedHead=false clone -q --depth 1 --branch "$2" "https://github.com/$1" "$WORK/$3"; }
clone FiloSottile/age v1.3.2 age
clone FiloSottile/edwards25519 v1.2.0 edwards25519
clone FiloSottile/hpke v0.4.0 hpke
clone FiloSottile/nistec v0.0.4 nistec
clone golang/crypto v0.55.0 crypto
clone golang/sys v0.47.0 sys
clone golang/term v0.45.0 term
GOVERSION=$(go env GOVERSION | sed -E 's/^go([0-9]+\.[0-9]+).*/\1/')
for m in age edwards25519 hpke nistec crypto sys term; do
    sed -i -E "s/^go [0-9.]+$/go $GOVERSION/; /^toolchain/d" "$WORK/$m/go.mod"
done
# The test-only requirements would need the module proxy.
python3 - "$WORK/age/go.mod" <<'PY'
import re, sys
path = sys.argv[1]
text = open(path).read()
text = re.sub(r"// Test dependencies\.\nrequire \([^)]*\)\n", "", text)
text += """
replace (
	filippo.io/edwards25519 => ../edwards25519
	filippo.io/hpke => ../hpke
	filippo.io/nistec => ../nistec
	golang.org/x/crypto => ../crypto
	golang.org/x/sys => ../sys
	golang.org/x/term => ../term
)
"""
open(path, "w").write(text)
PY
mkdir -p "$WORK/age/tag/tagwitness" "$PREFIX/bin"
cp "$HERE/main.go" "$WORK/age/tag/tagwitness/"
cd "$WORK/age"
export GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=mod GOSUMDB=off
for p in ./cmd/age ./cmd/age-keygen ./cmd/age-inspect ./cmd/age-plugin-batchpass \
         ./extra/age-plugin-pq ./extra/age-plugin-tag ./extra/age-plugin-tagpq; do
    go build -ldflags "-X main.Version=v1.3.2" -o "$PREFIX/bin/" "$p"
done
go build -o "$PREFIX/bin/age-tag-witness" ./tag/tagwitness
echo "built $PREFIX/bin: $(ls "$PREFIX/bin" | tr '\n' ' ')"
