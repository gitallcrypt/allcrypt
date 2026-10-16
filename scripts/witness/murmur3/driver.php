<?php
// PHP's ext/hash, for MurmurHash3: murmur3a (x86_32), murmur3c (x86_128)
// and murmur3f (x64_128), from PMurHash, an incremental implementation.
// One request per line on stdin, "NAME KEY PATH", NAME murmur3_32,
// murmur3_x86_128 or murmur3_x64_128 and KEY "seed:" and eight hex
// digits; answered with the hash of the file's bytes as PHP prints it,
// each word big endian, or "error". The data goes in in pieces of 1, 2,
// 3 ... bytes.
$names = ['murmur3_32' => 'murmur3a', 'murmur3_x86_128' => 'murmur3c',
          'murmur3_x64_128' => 'murmur3f'];
while (($line = fgets(STDIN)) !== false) {
    $parts = preg_split('/\s+/', trim($line));
    $data = count($parts) == 3 ? @file_get_contents($parts[2]) : false;
    if ($data === false || !isset($names[$parts[0]])
            || !preg_match('/^seed:[0-9a-f]{8}$/', $parts[1])) {
        echo "error\n";
        continue;
    }
    $ctx = hash_init($names[$parts[0]], 0, '', ['seed' => hexdec(substr($parts[1], 5))]);
    for ($at = 0, $step = 1; $at < strlen($data); $at += $step, $step++) {
        hash_update($ctx, substr($data, $at, $step));
    }
    echo hash_final($ctx), "\n";
}
