#!/bin/sh
# Builds /opt/li0ard: li0ard's TypeScript DSTU 4145-2002, with its GOST
# 34.311-95 and Kupyna for certificates (li0ard/dstu, commit 6c277c8),
# and what they import - three files of @noble/curves and @noble/hashes
# 2.4.0 (paulmillr's repositories, their TypeScript sources) and bn.js
# 5.2.3 (indutny/bn.js) - run by bun through driver.ts. The sources are fetched once and checked against
# li0ard.sha256 into src/, and copied to run/ to be run.
#
# One line of li0ard's src/dstu4145/index.ts is removed in run/: the
# re-export of its ECIES, which imports an ASN.1 package this build does
# not fetch and the driver does not use.
#
# Before reporting success, the driver must answer for a public key on
# every curve; scripts/make_dstu4145_onb_vectors.py checks what it says.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/li0ard}
LI0ARD=https://raw.githubusercontent.com/li0ard/dstu/6c277c8906588a11f0d21a844347e83574ca325a/src
CURVES=https://raw.githubusercontent.com/paulmillr/noble-curves/2.4.0/src
HASHES=https://raw.githubusercontent.com/paulmillr/noble-hashes/2.4.0/src
BN=https://raw.githubusercontent.com/indutny/bn.js/v5.2.3/lib
for f in $(cut -c67- "$HERE/li0ard.sha256"); do
    case "$f" in
        li0ard/src/*) url=$LI0ARD/${f#li0ard/src/} ;;
        li0ard/node_modules/@noble/curves/*) url=$CURVES/${f#li0ard/node_modules/@noble/curves/} ;;
        li0ard/node_modules/@noble/hashes/*) url=$HASHES/${f#li0ard/node_modules/@noble/hashes/} ;;
        li0ard/node_modules/bn.js/*) url=$BN/${f#li0ard/node_modules/bn.js/} ;;
    esac
    mkdir -p "$OUT/src/$(dirname "$f")"
    [ -f "$OUT/src/$f" ] || curl -sSfL -o "$OUT/src/$f" "$url"
done
(cd "$OUT/src" && sha256sum -c --quiet "$HERE/li0ard.sha256")

rm -rf "$OUT/run"
cp -r "$OUT/src/li0ard" "$OUT/run"
cd "$OUT/run"
sed -i '/^export \* from "\.\/ecies\.js";$/d' src/dstu4145/index.ts
for d in . node_modules/@noble/curves node_modules/@noble/hashes; do
    echo '{"type": "module"}' > "$d/package.json"
done
echo '{"name": "bn.js", "main": "bn.js"}' > node_modules/bn.js/package.json
cp "$HERE/driver.ts" driver.ts

python3 -I - "$OUT" <<'EOF'
import subprocess, sys
out = sys.argv[1]
bun = __import__("os").environ.get("BUN") or "bun"
lines = "".join(f"pub {n} 01\n" for n in range(15))
got = subprocess.run([bun, f"{out}/run/driver.ts"], input=lines, capture_output=True,
                     text=True, check=True).stdout.split("\n")[:15]
if any(g.startswith("error") or len(g.split()) != 2 for g in got):
    sys.exit(f"the driver failed: {got}")
print("li0ard answers on all 15 curves")
EOF
echo "$OUT"
