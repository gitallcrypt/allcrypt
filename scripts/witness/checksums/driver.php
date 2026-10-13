<?php
// PHP's ext/hash, for the checksums: crc32 (PHP's crc32b), crc32c,
// adler32, and FNV-1 and FNV-1a at 32 and 64 bits as fnvVARIANT_BITS.
// One request per line on stdin, "NAME PATH", answered with the
// checksum of the file's bytes as lowercase big endian hex, or "error".
// The data goes in in pieces of 1, 2, 3 ... bytes.
$names = ['crc32' => 'crc32b', 'crc32c' => 'crc32c', 'adler32' => 'adler32',
          'fnv1_32' => 'fnv132', 'fnv1a_32' => 'fnv1a32', 'fnv1_64' => 'fnv164',
          'fnv1a_64' => 'fnv1a64'];
while (($line = fgets(STDIN)) !== false) {
    $parts = preg_split('/\s+/', trim($line));
    $data = count($parts) == 2 ? @file_get_contents($parts[1]) : false;
    if ($data === false || !isset($names[$parts[0]])) {
        echo "error\n";
        continue;
    }
    $ctx = hash_init($names[$parts[0]]);
    for ($at = 0, $step = 1; $at < strlen($data); $at += $step, $step++) {
        hash_update($ctx, substr($data, $at, $step));
    }
    echo hash_final($ctx), "\n";
}
