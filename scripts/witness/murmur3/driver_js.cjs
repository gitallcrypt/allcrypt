// murmurhash3js 3.0.1 (pid/murmurHash3js), JavaScript: x86_32, x86_128
// and x64_128, over strings whose characters are the bytes. One request
// per line on stdin, "NAME KEY PATH", KEY "seed:" and eight hex digits;
// answered with the hash of the file's bytes, each word big endian,
// first word first, or "error". The library hashes a whole string.
const fs = require("fs");
const readline = require("readline");
const murmur = require(process.argv[2]);

function answer(name, key, path) {
    const match = /^seed:([0-9a-f]{8})$/.exec(key);
    if (!match) return "error";
    const seed = parseInt(match[1], 16);
    let data;
    try {
        data = fs.readFileSync(path).toString("latin1");
    } catch (e) {
        return "error";
    }
    switch (name) {
        case "murmur3_32":
            return (murmur.x86.hash32(data, seed) >>> 0).toString(16).padStart(8, "0");
        case "murmur3_x86_128":
            return murmur.x86.hash128(data, seed);
        case "murmur3_x64_128":
            return murmur.x64.hash128(data, seed);
    }
    return "error";
}

const lines = readline.createInterface({ input: process.stdin });
lines.on("line", (line) => {
    const parts = line.trim().split(/\s+/);
    process.stdout.write((parts.length === 3 ? answer(...parts) : "error") + "\n");
});
