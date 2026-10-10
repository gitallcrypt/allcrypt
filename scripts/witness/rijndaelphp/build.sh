#!/bin/sh
# Builds /opt/rijndaelphp: phpseclib 1.0.23's pure-PHP Rijndael, the two
# files it needs, fetched once and checked against their SHA-256. Its
# internal engine takes every Rijndael block and key size, independently
# of Bouncy Castle's. driver.php runs it.
set -e
OUT=${1:-/opt/rijndaelphp}
BASE=https://raw.githubusercontent.com/phpseclib/phpseclib/1.0.23/phpseclib/Crypt
mkdir -p "$OUT/Crypt"
curl -sSfL -o "$OUT/Crypt/Rijndael.php" "$BASE/Rijndael.php"
curl -sSfL -o "$OUT/Crypt/Base.php" "$BASE/Base.php"
cd "$OUT/Crypt"
echo "f7a800425cd26b105670c75a6c6783b1f53b1ae421fd852af073962a41bec1f4  Rijndael.php
e954051ac36ec62680bcbc49bdc29913f1ad2ee6f134666b3285487e880a3770  Base.php" | sha256sum -c
echo "$OUT"
