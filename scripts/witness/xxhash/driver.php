<?php
// PHP's ext/hash, for xxHash: xxh32, xxh64, xxh3 and xxh128, which it
// takes from the reference implementation it bundles.
// One request per line on stdin, "NAME KEY PATH", KEY "seed:" and sixteen
// hex digits or "secret:" and a path; answered with the hash of the
// file's bytes as lowercase big endian hex, or "error". The data goes in
// in pieces of 1, 2, 3 ... bytes.
while (($line = fgets(STDIN)) !== false) {
    $parts = preg_split('/\s+/', trim($line));
    $data = count($parts) == 3 ? @file_get_contents($parts[2]) : false;
    $name = $parts[0];
    if ($data === false || !in_array($name, ['xxh32', 'xxh64', 'xxh3', 'xxh128'], true)) {
        echo "error\n";
        continue;
    }
    if (str_starts_with($parts[1], 'seed:') && strlen($parts[1]) == 21) {
        // A signed 64 bit integer from the sixteen digits, which is what
        // PHP's int holds; XXH32's seed is the low 32 bits.
        $seed = unpack('J', hex2bin(substr($parts[1], 5)))[1];
        if ($name == 'xxh32' && ($seed < 0 || $seed > 0xffffffff)) {
            echo "error\n";
            continue;
        }
        $options = ['seed' => $seed];
    } elseif (str_starts_with($parts[1], 'secret:') && ($name == 'xxh3' || $name == 'xxh128')) {
        $secret = file_get_contents(substr($parts[1], 7));
        // PHP keeps the first 256 bytes of a longer secret, with a
        // warning, and hashes long inputs under those: not XXH3 with the
        // secret given, so refused here.
        if (strlen($secret) > 256) {
            echo "error\n";
            continue;
        }
        $options = ['secret' => $secret];
    } else {
        echo "error\n";
        continue;
    }
    try {
        $ctx = hash_init($name, 0, '', $options);
    } catch (Error $e) {
        echo "error\n";
        continue;
    }
    for ($at = 0, $step = 1; $at < strlen($data); $at += $step, $step++) {
        hash_update($ctx, substr($data, $at, $step));
    }
    echo hash_final($ctx), "\n";
}
