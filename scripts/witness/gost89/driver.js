// node driver.js WITNESS_DIR OPERATION
//
// gost89's GOST 28147-89, GOST 34.311-95 and DSTU key wrap, over the
// request format of scripts/witness/bcwitness/UaWitness.java: one line
// of space-separated hex fields per request on stdin, one hex line out,
// "-" for an empty field. The S-box is given as a 64-byte DKE and
// unpacked with gost89's own unpackSbox.
//
//   gost-ecb   DKE KEY DATA
//   gost-cfb   DKE KEY IV DATA
//   gost-mac   DKE KEY DATA          4 bytes
//   gost3411   DKE DATA              DATA is passed in one update call
//   wrap       KEK IV CEK            the default DKE only
//   unwrap     KEK WRAPPED
'use strict';
const dir = process.argv[2];
const op = process.argv[3];
const Gost = require(dir + '/lib/gost89.js');
const Dstu = require(dir + '/lib/dstu.js');
const Hash = require(dir + '/lib/hash.js');
const keywrap = require(dir + '/lib/keywrap.js');

const hex = (s) => s === '-' ? Buffer.alloc(0) : Buffer.from(s, 'hex');

function run(f) {
    if (op === 'wrap') {
        return keywrap.wrap(hex(f[2]), hex(f[0]), hex(f[1]));
    }
    if (op === 'unwrap') {
        return keywrap.unwrap(hex(f[1]), hex(f[0]));
    }
    const sbox = Dstu.unpackSbox(hex(f[0]));
    if (op === 'gost3411') {
        const h = new Hash();
        h.gost = Gost.init(sbox);
        const data = hex(f[1]);
        // One call: gost89's update keeps a stale remainder when a later
        // call completes a block exactly.
        if (data.length) h.update(data);
        const out = Buffer.alloc(32);
        h.finish(out);
        return out;
    }
    const g = Gost.init(sbox);
    g.key(hex(f[1]));
    if (op === 'gost-ecb') return g.crypt(hex(f[2]));
    if (op === 'gost-cfb') return g.crypt_cfb(hex(f[2]), hex(f[3]));
    if (op === 'gost-mac') return g.mac(32, hex(f[2]));
    throw new Error('unknown operation ' + op);
}

const lines = require('fs').readFileSync(0, 'utf8').split('\n').filter((l) => l.trim());
const out = [];
for (const line of lines) {
    try {
        out.push(Buffer.from(run(line.trim().split(' '))).toString('hex'));
    } catch (e) {
        out.push('error: ' + String(e.message).replace(/\n/g, ' '));
    }
}
process.stdout.write(out.join('\n') + '\n');
