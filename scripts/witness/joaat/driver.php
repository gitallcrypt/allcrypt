<?php
// PHP's ext/hash, for Jenkins's one-at-a-time: joaat, from zero only.
// One request per line on stdin, "NAME KEY PATH", NAME joaat and KEY
// "seed:" and eight hex digits, all zeros; answered with the hash of the
// file's bytes as lowercase big endian hex, or "error". The data goes in
// in pieces of 1, 2, 3 ... bytes.
while (($line = fgets(STDIN)) !== false) {
    $parts = preg_split('/\s+/', trim($line));
    $data = count($parts) == 3 ? @file_get_contents($parts[2]) : false;
    if ($data === false || $parts[0] !== 'joaat' || $parts[1] !== 'seed:00000000') {
        echo "error\n";
        continue;
    }
    $ctx = hash_init('joaat');
    for ($at = 0, $step = 1; $at < strlen($data); $at += $step, $step++) {
        hash_update($ctx, substr($data, $at, $step));
    }
    echo hash_final($ctx), "\n";
}
