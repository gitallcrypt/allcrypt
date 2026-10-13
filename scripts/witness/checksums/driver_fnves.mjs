// hugoalh's fnv-es: FNV-0, FNV-1 and FNV-1a at every size, as
// fnvVARIANT_BITS. Its module, base.ts, is the first argument; run with
// node's --experimental-strip-types. One request per line on stdin,
// "NAME PATH", answered with the hash of the file's bytes as lowercase
// big endian hex, or "error". The data goes in in pieces of 1, 2, 3 ...
// bytes.
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";

// The module reaches for a polyfill over the network when this is
// missing, as it is in node 22; this is the whole of what it needs.
Uint8Array.fromHex ??= (hex) => Uint8Array.from(hex.match(/../g) ?? [], (b) => parseInt(b, 16));
const { FNV } = await import(process.argv[2]);

for await (const line of createInterface({ input: process.stdin })) {
    const [name, path] = line.trim().split(/\s+/);
    const match = /^fnv(0|1|1a)_(\d+)$/.exec(name ?? "");
    let answer = "error";
    try {
        const data = readFileSync(path);
        const h = new FNV({ variant: match[1], size: Number(match[2]) });
        for (let at = 0, step = 1; at < data.length; at += step, step++) {
            h.update(data.subarray(at, at + step));
        }
        answer = h.hashHex().toLowerCase();
    } catch {
        answer = "error";
    }
    console.log(answer);
}
