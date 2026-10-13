// tjwebb's fnv-plus: FNV-1 and FNV-1a at 32, 64, 128, 256, 512 and 1024
// bits, as fnvVARIANT_BITS. Its index.js is the first argument. One
// request per line on stdin, "NAME PATH", answered with the hash of the
// file's bytes as lowercase big endian hex, or "error". One-shot: it
// takes a string, here the bytes as Latin-1, with its UTF-8 mode off.
const fs = require("node:fs");
const readline = require("node:readline");
const fnv = require(process.argv[2]);
fnv.useUTF8(false);

readline.createInterface({ input: process.stdin }).on("line", (line) => {
    const [name, path] = line.trim().split(/\s+/);
    const match = /^fnv(1|1a)_(32|64|128|256|512|1024)$/.exec(name ?? "");
    let answer = "error";
    try {
        if (match) {
            fnv.version(match[1]);
            answer = fnv.hash(fs.readFileSync(path).toString("latin1"), Number(match[2])).hex();
        }
    } catch {
        answer = "error";
    }
    console.log(answer);
});
