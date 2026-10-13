// DSTU 9041:2020 through li0ard's @li0ard/dstu, run by bun.
//
// One request per line on stdin, one answer per line back, hex fields:
//
//     pub <bits> <e>                  the public key e*P, x || y
//     enc <bits> <Q> <epsilon> <M>    the ciphertext r || t
//     dec <bits> <e> <C>              the message, or "error <reason>"
//
// <bits> is 256 or 512, the curve's field size. Scalars are big endian.
import { dstu9041_256, dstu9041_512 } from "./src/dstu9041/index.ts";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const unhex = (s: string) => new Uint8Array(Buffer.from(s === "-" ? "" : s, "hex"));

function answer(line: string): string {
  const [op, bits, ...rest] = line.trim().split(/\s+/);
  const scheme = bits === "256" ? dstu9041_256 : bits === "512" ? dstu9041_512 : null;
  if (!scheme) return "error bits";
  try {
    if (op === "pub") return hex(scheme.getPublicKey(unhex(rest[0])));
    if (op === "enc") return hex(scheme.encrypt(unhex(rest[2]), unhex(rest[0]), unhex(rest[1])));
    if (op === "dec") return hex(scheme.decrypt(unhex(rest[1]), unhex(rest[0]))) || "-";
    return "error op";
  } catch (e) {
    return "error " + String((e as Error).message).replace(/\s+/g, "_");
  }
}

const input = await Bun.stdin.text();
const out: string[] = [];
for (const line of input.split("\n")) if (line.trim()) out.push(answer(line));
process.stdout.write(out.map((l) => l + "\n").join(""));
