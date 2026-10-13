// DSTU 4145-2002 through li0ard's TypeScript (li0ard/dstu), run by bun.
//
// One request per line on stdin, hex fields, big endian. CURVE is the
// curve's number as allcrypt numbers them: 0 to 9 in a polynomial basis,
// 10 to 14 the five in an optimal normal basis (m = 173, 179, 191, 233,
// 431). Field elements are written in the curve's own basis.
//
//     pub CURVE D                  QX QY, Q = -dG
//     compress CURVE QX QY         the standard's compression
//     decompress CURVE BYTES       QX QY
//     sign CURVE D HASH E          S R, the hash read little endian
//     verify CURVE QX QY HASH R S  01 or 00
//     dh CURVE D QX QY COFACTOR    ZX, of d*Q, or of (h*d mod n)*Q with
//                                  COFACTOR 1
//     x509 M KS A B N BP DKE HASH TBS SIG KEY
//                                  01 or 00: a certificate's signature under
//                                  a dstu4145le key, as li0ard's own
//                                  x509.spec.ts checks one
//
// x509 takes the issuer's ECBinary as the certificate carries it - M, the
// polynomial's exponents in their DER order joined by commas, A, B and BP
// as stored (little endian), N big endian - then its DKE (- for none),
// the hash the signature OID names (gost34311, kupyna256, kupyna384 or
// kupyna512), the TBSCertificate, the signature's OCTET STRING contents
// and the issuer's key's, the last two as stored. It builds the signer
// and the hash exactly as createSignerFromParameters and
// proceedCertificate in li0ard's src/dstu4145/x509.spec.ts do.
//
// "error <reason>" when li0ard refuses. li0ard's signer reads the hash
// big endian, so the hash is reversed for it here.
import {
  DSTU_163, DSTU_167, DSTU_173, DSTU_179, DSTU_191, DSTU_233, DSTU_257, DSTU_307, DSTU_367,
  DSTU_431, DSTU_173_ONB, DSTU_179_ONB, DSTU_191_ONB, DSTU_233_ONB, DSTU_431_ONB, dstu4145,
} from "./src/dstu4145/index.ts";
import { binaryWeierstrass } from "./src/dstu4145/ec/index.ts";
import { dstu4145_le, expandPoint } from "./src/dstu4145/index.ts";
import { _Gost3431195, DKE_1 } from "./src/dstu9311/index.ts";
import { kupyna256, kupyna384, kupyna512 } from "./src/kupyna/index.ts";

const PARAMS = [DSTU_163, DSTU_167, DSTU_173, DSTU_179, DSTU_191, DSTU_233, DSTU_257, DSTU_307,
  DSTU_367, DSTU_431, DSTU_173_ONB, DSTU_179_ONB, DSTU_191_ONB, DSTU_233_ONB, DSTU_431_ONB];
const signers: Record<number, ReturnType<typeof dstu4145>> = {};
const curves: Record<number, ReturnType<typeof binaryWeierstrass>> = {};
const signer = (n: string) => (signers[+n] ??= dstu4145(PARAMS[+n]));
const curve = (n: string) => (curves[+n] ??= binaryWeierstrass(PARAMS[+n]));

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const unhex = (s: string) => new Uint8Array(Buffer.from(s === "-" ? "" : s, "hex"));
const reversed = (b: Uint8Array) => b.slice().reverse();
const halves = (b: Uint8Array) => `${hex(b.subarray(0, b.length / 2))} ${hex(b.subarray(b.length / 2))}`;
const joined = (x: string, y: string) => new Uint8Array([...unhex(x), ...unhex(y)]);

function padded(b: Uint8Array, n: number): Uint8Array {
  const out = new Uint8Array(Math.max(n, b.length));
  out.set(b, out.length - b.length);
  return out;
}

function x509(m: number, f: string[]): boolean {
  const [ks, a, b, order, bp, dke, hashName, tbs, sig, key] = f;
  const exponents = ks.split(",").map(Number);
  const curveA = +a as 0 | 1;
  const curveB = hex(reversed(unhex(b)));
  const G = expandPoint(reversed(unhex(bp)), { m, ks: exponents, a: curveA, b: curveB });
  const signer = dstu4145_le({
    m, ks: exponents, a: curveA, b: curveB, order,
    cofactor: 4 >> curveA as 2 | 4,
    Gx: hex(G.x), Gy: hex(G.y),
  });
  const hash = {
    gost34311: () => new _Gost3431195(dke === "-" ? DKE_1 : unhex(dke)),
    kupyna256: () => kupyna256.create(),
    kupyna384: () => kupyna384.create(),
    kupyna512: () => kupyna512.create(),
  }[hashName]!();
  const digest = hash.update(unhex(tbs)).digest();
  return signer.verify(unhex(key), digest, unhex(sig));
}

function answer(line: string): string {
  const [op, n, ...f] = line.trim().split(/\s+/);
  try {
    switch (op) {
      case "pub":
        return halves(signer(n).getPublicKey(unhex(f[0]), false));
      case "compress":
        return hex(curve(n).Point.fromBytes(joined(f[0], f[1])).toBytes(true));
      case "decompress":
        return halves(curve(n).Point.fromBytes(unhex(f[0])).toBytes(false));
      case "sign":
        return halves(signer(n).sign(unhex(f[0]), reversed(unhex(f[1])), unhex(f[2])));
      case "verify": {
        const width = signer(n).lengths.scalarByteLength;
        const signature = new Uint8Array([...padded(unhex(f[4]), width),
                                          ...padded(unhex(f[3]), width)]);
        return signer(n).verify(joined(f[0], f[1]), reversed(unhex(f[2])), signature)
          ? "01" : "00";
      }
      case "x509":
        return x509(+n, f) ? "01" : "00";
      case "dh":
        return hex(signer(n).getSharedSecret(unhex(f[0]), joined(f[1], f[2]), f[3] === "1"));
    }
    return "error op";
  } catch (e) {
    return "error " + String((e as Error).message).replace(/\s+/g, "_");
  }
}

const input = await Bun.stdin.text();
const out: string[] = [];
for (const line of input.split("\n")) if (line.trim()) out.push(answer(line));
process.stdout.write(out.map((l) => l + "\n").join(""));
