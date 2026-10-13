// ctph-witness: ctph.js 0.0.5, the CTPH CyberChef runs, under node.
//
// One request per line on stdin:
//
//   hash PATH             ctph.digest of the file's bytes
//   similarity D1 D2      ctph.similarity of two digests, as JSON (NaN is
//                         "NaN"), or "error" where ctph.js throws
//
// One line out per request.
const fs = require("fs");
const ctph = require(process.argv[2]);

const out = [];
for (const line of fs.readFileSync(0, "utf8").split("\n")) {
  if (!line) continue;
  const [op, a, b] = line.split(" ");
  try {
    if (op === "hash") {
      out.push(ctph.digest(Array.from(fs.readFileSync(a))));
    } else if (op === "similarity") {
      const s = ctph.similarity(a, b);
      out.push(Number.isNaN(s) ? "NaN" : JSON.stringify(s));
    } else {
      out.push("error");
    }
  } catch (e) {
    out.push("error");
  }
}
process.stdout.write(out.map((l) => l + "\n").join(""));
