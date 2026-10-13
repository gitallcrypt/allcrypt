<?php
// PHP's ext/hash: Tiger at 128, 160 and 192 bits after three or four
// passes, HAVAL at every length and pass count, and Snefru-256. One request
// per line on stdin, "NAME PATH", answered with the lowercase hex digest
// of the file's bytes under NAME or "error"; NAME is tigerBITS_PASSES,
// havalBITS_PASSES or snefru256. The data goes in in pieces of 1, 2,
// 3 ... bytes.
while (($line = fgets(STDIN)) !== false) {
    $parts = preg_split('/\s+/', trim($line));
    $data = count($parts) == 2 ? @file_get_contents($parts[1]) : false;
    $algo = preg_replace('/^(tiger|haval)(\d+)_(\d)$/', '$1$2,$3', $parts[0]);
    if ($data === false || !in_array($algo, hash_algos(), true) || !preg_match('/^(tiger|haval|snefru)/', $algo)) {
        echo "error\n";
        continue;
    }
    $ctx = hash_init($algo);
    for ($at = 0, $step = 1; $at < strlen($data); $at += $step, $step++) {
        hash_update($ctx, substr($data, $at, $step));
    }
    echo hash_final($ctx), "\n";
}
