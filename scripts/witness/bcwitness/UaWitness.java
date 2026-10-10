// java -cp bcprov.jar:OUT UaWitness OPERATION
//
// Bouncy Castle's Ukrainian algorithms, and GOST 28147-89 under an S-box
// given as a 64-byte DSTU 4145 DKE. Reads one request per line of
// space-separated hex fields on stdin and writes one hex line per
// request, or "error: <message>". Objects are built fresh per line.
//
//   gost-ecb   DKE KEY DATA        GOST 28147-89, simple replacement
//   gost-cfb   DKE KEY IV DATA     gamma with feedback (64-bit CFB)
//   gost-cnt   DKE KEY IV DATA     gamma (GOST counter mode)
//   gost-mac   DKE KEY DATA        imitovstavka, 4 bytes
//   gost3411   DKE DATA            GOST 34.311-95 / R 34.11-94 under DKE
//   kalyna-BITS KEY DATA           DSTU 7624, BITS-bit block, ECB
//   kupyna-BITS DATA               DSTU 7564, BITS-bit digest
//   kalyna-sboxes                  DSTU7624Engine's S0..S3, one per line
//   kalyna-ctr-BITS KEY IV DATA     DSTU 7624 counter mode (KCTR)
//   kalyna-cbc-BITS KEY IV DATA     and -cfb-, -ofb-: the generic modes,
//                                   whole-block feedback
//   kalyna-mac-BITS KEY QBYTES DATA DSTU 7624 MAC, whole blocks only
//   kalyna-kw-BITS KEY DATA         DSTU 7624 key wrap, whole blocks only
//   kalyna-unkw-BITS KEY WRAPPED    its unwrap
//
// An empty DATA field is written "-".
import java.io.BufferedReader;
import java.io.InputStreamReader;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.DSTU7564Digest;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.macs.GOST28147Mac;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.GOFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithSBox;
import org.bouncycastle.util.encoders.Hex;

public class UaWitness {
    static byte[] hex(String s) {
        return s.equals("-") ? new byte[0] : Hex.decode(s);
    }

    // The DKE's nibbles in order, high first: the expansion Bouncy
    // Castle's own DSTU 4145 signature code applies to a DKE.
    static byte[] expand(byte[] dke) {
        byte[] sbox = new byte[128];
        for (int i = 0; i < dke.length; i++) {
            sbox[2 * i] = (byte) ((dke[i] >> 4) & 0xf);
            sbox[2 * i + 1] = (byte) (dke[i] & 0xf);
        }
        return sbox;
    }

    static byte[] stream(BlockCipher mode, CipherParameters params, byte[] data) {
        mode.init(true, params);
        int bs = mode.getBlockSize();
        byte[] padded = new byte[(data.length + bs - 1) / bs * bs];
        System.arraycopy(data, 0, padded, 0, data.length);
        byte[] out = new byte[padded.length];
        for (int off = 0; off < padded.length; off += bs) {
            mode.processBlock(padded, off, out, off);
        }
        byte[] trimmed = new byte[data.length];
        System.arraycopy(out, 0, trimmed, 0, data.length);
        return trimmed;
    }

    static byte[] run(String op, String[] f) throws Exception {
        if (op.startsWith("gost")) {
            byte[] sbox = expand(hex(f[0]));
            if (op.equals("gost3411")) {
                GOST3411Digest d = new GOST3411Digest(sbox);
                byte[] m = hex(f[1]);
                d.update(m, 0, m.length);
                byte[] out = new byte[32];
                d.doFinal(out, 0);
                return out;
            }
            CipherParameters keyed = new ParametersWithSBox(new KeyParameter(hex(f[1])), sbox);
            switch (op) {
                case "gost-ecb": {
                    GOST28147Engine e = new GOST28147Engine();
                    return stream(e, keyed, hex(f[2]));
                }
                case "gost-cfb":
                    return stream(new CFBBlockCipher(new GOST28147Engine(), 64),
                                  new ParametersWithIV(keyed, hex(f[2])), hex(f[3]));
                case "gost-cnt":
                    return stream(new GOFBBlockCipher(new GOST28147Engine()),
                                  new ParametersWithIV(keyed, hex(f[2])), hex(f[3]));
                case "gost-mac": {
                    GOST28147Mac mac = new GOST28147Mac();
                    mac.init(keyed);
                    byte[] m = hex(f[2]);
                    mac.update(m, 0, m.length);
                    byte[] out = new byte[mac.getMacSize()];
                    mac.doFinal(out, 0);
                    return out;
                }
            }
        }
        if (op.startsWith("kalyna-ctr-")) {
            int bits = Integer.parseInt(op.substring("kalyna-ctr-".length()));
            return stream(new org.bouncycastle.crypto.modes.KCTRBlockCipher(new DSTU7624Engine(bits)),
                          new ParametersWithIV(new KeyParameter(hex(f[0])), hex(f[1])), hex(f[2]));
        }
        if (op.startsWith("kalyna-cbc-") || op.startsWith("kalyna-cfb-")
                || op.startsWith("kalyna-ofb-")) {
            int bits = Integer.parseInt(op.substring(op.lastIndexOf('-') + 1));
            DSTU7624Engine e = new DSTU7624Engine(bits);
            BlockCipher mode = op.startsWith("kalyna-cbc-")
                ? new org.bouncycastle.crypto.modes.CBCBlockCipher(e)
                : op.startsWith("kalyna-cfb-") ? new CFBBlockCipher(e, bits)
                : new org.bouncycastle.crypto.modes.OFBBlockCipher(e, bits);
            return stream(mode, new ParametersWithIV(new KeyParameter(hex(f[0])), hex(f[1])),
                          hex(f[2]));
        }
        if (op.startsWith("kalyna-mac-")) {
            int bits = Integer.parseInt(op.substring("kalyna-mac-".length()));
            org.bouncycastle.crypto.macs.DSTU7624Mac mac =
                new org.bouncycastle.crypto.macs.DSTU7624Mac(bits, 8 * Integer.parseInt(f[1]));
            mac.init(new KeyParameter(hex(f[0])));
            byte[] m = hex(f.length > 2 ? f[2] : "-");
            mac.update(m, 0, m.length);
            byte[] out = new byte[mac.getMacSize()];
            mac.doFinal(out, 0);
            return out;
        }
        if (op.startsWith("kalyna-kw-") || op.startsWith("kalyna-unkw-")) {
            boolean wrapping = op.startsWith("kalyna-kw-");
            int bits = Integer.parseInt(op.substring(op.lastIndexOf('-') + 1));
            org.bouncycastle.crypto.engines.DSTU7624WrapEngine w =
                new org.bouncycastle.crypto.engines.DSTU7624WrapEngine(bits);
            w.init(wrapping, new KeyParameter(hex(f[0])));
            byte[] d = hex(f[1]);
            return wrapping ? w.wrap(d, 0, d.length) : w.unwrap(d, 0, d.length);
        }
        if (op.startsWith("kalyna-")) {
            int bits = Integer.parseInt(op.substring("kalyna-".length()));
            return stream(new DSTU7624Engine(bits), new KeyParameter(hex(f[0])), hex(f[1]));
        }
        if (op.startsWith("kupyna-")) {
            int bits = Integer.parseInt(op.substring("kupyna-".length()));
            DSTU7564Digest d = new DSTU7564Digest(bits);
            byte[] m = hex(f[0]);
            d.update(m, 0, m.length);
            byte[] out = new byte[d.getDigestSize()];
            d.doFinal(out, 0);
            return out;
        }
        throw new IllegalArgumentException("unknown operation " + op);
    }

    public static void main(String[] args) throws Exception {
        if (args[0].equals("kalyna-sboxes")) {
            for (String name : new String[]{"S0", "S1", "S2", "S3"}) {
                java.lang.reflect.Field f = DSTU7624Engine.class.getDeclaredField(name);
                f.setAccessible(true);
                System.out.println(Hex.toHexString((byte[]) f.get(null)));
            }
            return;
        }
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        StringBuilder out = new StringBuilder();
        String line;
        while ((line = in.readLine()) != null) {
            try {
                out.append(Hex.toHexString(run(args[0], line.trim().split(" "))));
            } catch (Exception e) {
                out.append("error: ").append(e.getClass().getSimpleName()).append(' ')
                   .append(String.valueOf(e.getMessage()).replace('\n', ' '));
            }
            out.append('\n');
        }
        System.out.print(out);
    }
}
