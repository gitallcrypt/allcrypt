#!/usr/bin/env python3
"""Write vectors/app_passwords.vec: the database and forum password
hashes' known answers.

    scripts/witness/apppass/build.sh /opt/apppass
    python3 scripts/make_app_password_vectors.py

**A development tool, not a test.** It needs the witness built (which
fetches its two sources once) and a PHP interpreter;
`tests/test_app_passwords.rs` reads `vectors/app_passwords.vec` offline.
Where each answer comes from:

- `mysql_old`: MariaDB's own `hash_password`, extracted from
  `sql/password.c` and compiled (`/opt/apppass/ml323`). This is the
  pre-4.1 `OLD_PASSWORD()` / `mysql323` scheme.
- `mysql_password`, `postgres_md5`, `vbulletin`: PHP's `sha1`/`md5`,
  which are independent of this library's own, applied in each scheme's
  published construction by `scripts/witness/apppass/driver.php`.
- `phpass`: WordPress 6.4's `class-phpass.php` run as is - the portable
  `$P$` (WordPress) and `$H$` (phpBB3) hash.

Row formats, one hash per row:

    mysql_old password=<hex> hash=<16 lowercase hex>
    mysql_password password=<hex> hash=*<40 uppercase hex>
    postgres_md5 password=<hex> user=<hex> hash=md5<32 lowercase hex>
    vbulletin password=<hex> salt=<hex> hash=<32 lowercase hex>
    phpass password=<hex> setting=<ascii> hash=<ascii>
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "app_passwords.vec")
WITNESS = os.environ.get("APPPASS_WITNESS", "/opt/apppass")
DRIVER = os.path.join(HERE, "witness", "apppass", "driver.php")
PHPASS_CLASS = os.path.join(WITNESS, "class-phpass.php")
ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# A spread of passwords: empty, ASCII, spaces and tabs (which mysql_old
# skips), long, and non-ASCII bytes.
PASSWORDS = [
    b"", b"a", b"abc", b"password", b"hashcat", b"Sesame1234!",
    b"with spaces", b"tab\tinside", b"  leading", b"trailing  ",
    b"x" * 80, bytes(range(1, 40)), "paßwort".encode(),
    "éèê".encode(),
]


def php(mode, rows):
    """Run the PHP driver over tab-separated hex rows."""
    stdin = "".join("\t".join(fields) + "\n" for fields in rows)
    out = subprocess.run(["php", DRIVER, mode, PHPASS_CLASS], input=stdin,
                         check=True, capture_output=True, text=True).stdout.split("\n")
    return out[:len(rows)]


def mysql_old(passwords):
    # Pass the raw password bytes as argv (text=False), so no encoding
    # round-trip alters a non-ASCII byte. None of these has a NUL, which
    # argv cannot carry.
    out = subprocess.run([os.path.join(WITNESS, "ml323").encode()] + list(passwords),
                         check=True, capture_output=True).stdout.decode().split()
    # The witness takes its arguments as C strings, so a password with an
    # embedded NUL cannot be passed this way; none of ours has one.
    assert len(out) == len(passwords), out
    return out


def main():
    if not os.path.exists(os.path.join(WITNESS, "ml323")):
        sys.exit(f"no witness in {WITNESS}: run scripts/witness/apppass/build.sh")
    rows = []

    for pw, h in zip(PASSWORDS, mysql_old(PASSWORDS)):
        rows.append(f"mysql_old password={pw.hex() or '-'} hash={h}")

    for pw, h in zip(PASSWORDS, php("mysql_password", [[pw.hex()] for pw in PASSWORDS])):
        rows.append(f"mysql_password password={pw.hex() or '-'} hash={h}")

    users = [b"postgres", b"alice", b"", b"admin"]
    pg = [(pw, u) for pw in PASSWORDS[:8] for u in users]
    for (pw, u), h in zip(pg, php("postgres_md5", [[pw.hex(), u.hex()] for pw, u in pg])):
        rows.append(f"postgres_md5 password={pw.hex() or '-'} user={u.hex() or '-'} hash={h}")

    salts = [b"abc", b"Nx9", b"a longer salt here", b")(*&^%"]
    vb = [(pw, s) for pw in PASSWORDS[:8] for s in salts]
    for (pw, s), h in zip(vb, php("vbulletin", [[pw.hex(), s.hex()] for pw, s in vb])):
        rows.append(f"vbulletin password={pw.hex() or '-'} salt={s.hex()} hash={h}")

    # phpass settings: the id ($P$ WordPress, $H$ phpBB3), one round
    # character, and an eight-character salt. The round characters sweep
    # the low end of the cost range.
    settings = []
    for ident in ("$P$", "$H$"):
        for rc in "BCDE":  # itoa64 indices 11..14: 2^11 .. 2^14 iterations
            settings.append(f"{ident}{rc}" + "ab/0CdeF")
    php_rows = [[pw.hex(), s] for pw in PASSWORDS[:8] for s in settings]
    results = php("phpass", php_rows)
    for (pwhex, s), h in zip(php_rows, results):
        if h.startswith("*"):
            sys.exit(f"phpass witness rejected setting {s!r}")
        pw = bytes.fromhex(pwhex)
        rows.append(f"phpass password={pw.hex() or '-'} setting={s} hash={h}")

    header = ("# Database and forum password hashes. Written by\n"
              "# scripts/make_app_password_vectors.py; do not edit. mysql_old is\n"
              "# MariaDB's own hash_password; phpass is WordPress 6.4's\n"
              "# class-phpass.php; the md5/sha1 schemes are witnessed by PHP's\n"
              "# md5/sha1. See the script for the row formats.\n")
    with open(OUTPUT, "w") as f:
        f.write(header)
        for r in rows:
            f.write(r + "\n")
    print(f"{len(rows)} rows")


if __name__ == "__main__":
    main()
