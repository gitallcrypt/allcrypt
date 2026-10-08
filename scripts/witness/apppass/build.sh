#!/bin/sh
# Builds /opt/apppass: witnesses for the database and forum password
# hashes. Two sources, each fetched at a pinned tag and checked by hash:
#
#   MariaDB 10.11.6  sql/password.c   - the pre-4.1 OLD_PASSWORD hash
#                                       (hash_password), extracted and
#                                       compiled, not transcribed.
#   WordPress 6.4    class-phpass.php - the portable "$P$"/"$H$" hash
#                                       (phpBB3 and WordPress), run as is.
#
# The newer MySQL PASSWORD, PostgreSQL md5 and vBulletin schemes are
# md5/sha1 constructions and are witnessed by PHP's own md5/sha1 in
# scripts/make_app_password_vectors.py; nothing is built for them here.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/opt/apppass}
mkdir -p "$OUT"
fetch() { curl -sSf -o "$OUT/$1" "$2"; echo "$3  $OUT/$1" | sha256sum -c --quiet; }

fetch password.c https://raw.githubusercontent.com/MariaDB/server/mariadb-10.11.6/sql/password.c \
    ee1a0156e3b68f613418d00eea0a4e434c782a63b90bee2ea953673cf0fcc580
fetch class-phpass.php https://raw.githubusercontent.com/WordPress/WordPress/6.4/wp-includes/class-phpass.php \
    aefd65a0d51ee89888f7477230b221b166ad9ef30723c586e0c36df8a11ae0bc

# Pull MariaDB's hash_password() out of the file verbatim and wrap it in a
# main that prints its two words the way my_make_scrambled_password_323
# does (sprintf "%08lx%08lx"). The algorithm's bytes come from the fetched
# file, not from this script.
{
    echo 'typedef unsigned long ulong; typedef unsigned char uchar; typedef unsigned int uint;'
    echo '#include <stdio.h>'
    echo '#include <string.h>'
    awk '/^void hash_password\(/{p=1} p{print} p&&/^}/{exit}' "$OUT/password.c"
    cat <<'MAIN'
int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        ulong r[2];
        hash_password(r, argv[i], (uint) strlen(argv[i]));
        printf("%08lx%08lx\n", r[0], r[1]);
    }
    return 0;
}
MAIN
} > "$OUT/ml323.c"
grep -q 'nr2+=(nr2 << 8) ^ nr;' "$OUT/ml323.c"   # the function really arrived
cc -O2 -w -o "$OUT/ml323" "$OUT/ml323.c"
echo "$OUT"
