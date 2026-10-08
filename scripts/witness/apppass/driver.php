<?php
// driver.php MODE PHPASS_CLASS   < tab-separated hex args, one row per line.
// Prints one hash per input line. Passwords, salts and usernames arrive as
// hex so binary and newlines survive; settings and hashes are ASCII.
require $argv[2];
$mode = $argv[1];
$ph = new PasswordHash(8, true);
while (($line = fgets(STDIN)) !== false) {
    $f = explode("\t", rtrim($line, "\n"));
    switch ($mode) {
        case 'phpass':
            echo $ph->crypt_private(hex2bin($f[0]), $f[1]);
            break;
        case 'mysql_password':               // MySQL 4.1+ PASSWORD()
            echo '*' . strtoupper(sha1(sha1(hex2bin($f[0]), true)));
            break;
        case 'postgres_md5':                  // "md5" + md5(password + user)
            echo 'md5' . md5(hex2bin($f[0]) . hex2bin($f[1]));
            break;
        case 'vbulletin':                     // md5(md5(password) + salt)
            echo md5(md5(hex2bin($f[0])) . hex2bin($f[1]));
            break;
    }
    echo "\n";
}
