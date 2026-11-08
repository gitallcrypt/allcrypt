#!/bin/sh
# Build hpke-witness (filippo.io/hpke v0.4.0, the HPKE behind Go's
# crypto/hpke) into PREFIX, from its source and its one dependency
# (golang.org/x/crypto, from GitHub's mirror) at fixed tags, without the
# module proxy. The modules declare newer Go versions than their code
# needs; their go lines are lowered to the local toolchain's.
#
#   sh scripts/witness/hpke/build.sh /opt/hpkewitness
set -eu
PREFIX=${1:?usage: build.sh PREFIX}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
git -c advice.detachedHead=false clone -q --depth 1 --branch v0.4.0 https://github.com/FiloSottile/hpke "$WORK/hpke"
git -c advice.detachedHead=false clone -q --depth 1 --branch v0.41.0 https://github.com/golang/crypto "$WORK/crypto"
git -c advice.detachedHead=false clone -q --depth 1 --branch v0.35.0 https://github.com/golang/sys "$WORK/sys"
GOVERSION=$(go env GOVERSION | sed -E 's/^go([0-9]+\.[0-9]+).*/\1/')
for m in hpke crypto sys; do
    sed -i -E "s/^go [0-9.]+$/go $GOVERSION/; /^toolchain/d" "$WORK/$m/go.mod"
done
mkdir -p "$WORK/witness"
cp "$HERE/main.go" "$WORK/witness/"
cat > "$WORK/witness/go.mod" <<MOD
module hpkewitness

go $GOVERSION

require filippo.io/hpke v0.4.0

replace (
	filippo.io/hpke => ../hpke
	golang.org/x/crypto => ../crypto
	golang.org/x/sys => ../sys
)
MOD
mkdir -p "$PREFIX"
(cd "$WORK/witness" && GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=mod GOSUMDB=off \
    go build -o "$PREFIX/hpke-witness" .)
echo "built $PREFIX/hpke-witness"
