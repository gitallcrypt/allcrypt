#!/bin/sh
# Builds /opt/bcwitness: a driver over Bouncy Castle's block cipher
# engines (BlockWitness.java), compiled against the bcprov jar the system
# ships (1.77 on this machine; pass another as the second argument).
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/bcwitness}
JAR=${2:-/usr/share/java/bcprov-1.77.jar}
mkdir -p "$OUT"
cp "$JAR" "$OUT/bcprov.jar"
javac -cp "$OUT/bcprov.jar" -d "$OUT" "$HERE/BlockWitness.java"
echo "$OUT"
