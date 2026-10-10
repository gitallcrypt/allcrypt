<?php
// php driver.php WITNESS_DIR
//
// Reads "BLOCK_BITS KEY PLAINTEXT" lines of hex on stdin and writes the
// ECB ciphertext of each under phpseclib's internal Rijndael engine, one
// hex line per input line. A fresh cipher object per line.
set_include_path($argv[1] . PATH_SEPARATOR . get_include_path());
require_once 'Crypt/Rijndael.php';
while (($line = fgets(STDIN)) !== false) {
    $parts = explode(' ', trim($line));
    if (count($parts) != 3) continue;
    $c = new Crypt_Rijndael(CRYPT_MODE_ECB);
    $c->setPreferredEngine(CRYPT_ENGINE_INTERNAL);
    $c->disablePadding();
    $c->setBlockLength((int)$parts[0]);
    $key = hex2bin($parts[1]);
    $c->setKeyLength(strlen($key) * 8);
    $c->setKey($key);
    echo bin2hex($c->encrypt(hex2bin($parts[2]))), "\n";
}
