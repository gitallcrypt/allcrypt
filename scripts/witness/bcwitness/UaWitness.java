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
//   kupyna-mac-BITS KEY DATA       DSTU 7564's MAC (DSTU7564Mac)
//   kalyna-sboxes                  DSTU7624Engine's S0..S3, one per line
//   kalyna-ctr-BITS KEY IV DATA     DSTU 7624 counter mode (KCTR)
//   kalyna-cbc-BITS KEY IV DATA     and -cfb-, -ofb-: the generic modes,
//                                   whole-block feedback
//   kalyna-mac-BITS KEY QBYTES DATA DSTU 7624 MAC, whole blocks only
//   kalyna-kw-BITS KEY DATA         DSTU 7624 key wrap, whole blocks only
//   kalyna-unkw-BITS KEY WRAPPED    its unwrap
//   kalyna-gcm-BITS KEY IV QBYTES AAD DATA       DSTU 7624 GCM (KGCM):
//                                   ciphertext || tag
//   kalyna-ungcm-BITS KEY IV QBYTES AAD SEALED   its opening
//   kalyna-gmac-BITS KEY QBYTES DATA             GMAC (KGMac), zero IV
//   kalyna-ccm-BITS KEY IV QBYTES NB AAD DATA    DSTU 7624 CCM (KCCM)
//   kalyna-unccm-BITS KEY IV QBYTES NB AAD SEALED
//   kalyna-xts-BITS KEY IV DATA                  DSTU 7624 XTS (KXTS)
//   kalyna-unxts-BITS KEY IV DATA
//
// DSTU 4145-2002 (DSTU4145Signer, DSTU4145PointEncoder). CURVE is a
// named curve's number, 0 to 9 (DSTU4145NamedCurves), or
// "M:K3,K2,K1:A:B:N:GX:GY" for a curve given whole (one K for a
// trinomial). Integers and field elements are big-endian hex, answers
// space-separated. HASH is the byte string the signer is handed.
//
//   dstu4145-pub CURVE D                 QX QY, Q = -dG
//   dstu4145-sign CURVE D E HASH         R S, with e the random integer
//                                        the signer draws
//   dstu4145-verify CURVE QX QY HASH R S "01" or "00"
//   dstu4145-compress CURVE QX QY        the standard's compression
//   dstu4145-decompress CURVE BYTES      QX QY
//   dstu4145-dh CURVE D QX QY COFACTOR   x of d.Q, or of (h.d mod n).Q
//                                        when COFACTOR is 1 (ECDHBasic-
//                                        and ECDHCBasicAgreement)
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
        if (op.startsWith("kalyna-gcm-") || op.startsWith("kalyna-ungcm-")
                || op.startsWith("kalyna-ccm-") || op.startsWith("kalyna-unccm-")) {
            boolean sealing = op.startsWith("kalyna-gcm-") || op.startsWith("kalyna-ccm-");
            boolean ccm = op.contains("ccm-");
            int bits = Integer.parseInt(op.substring(op.lastIndexOf('-') + 1));
            org.bouncycastle.crypto.modes.AEADBlockCipher mode = ccm
                ? new org.bouncycastle.crypto.modes.KCCMBlockCipher(
                      new DSTU7624Engine(bits), Integer.parseInt(f[3]))
                : new org.bouncycastle.crypto.modes.KGCMBlockCipher(new DSTU7624Engine(bits));
            int at = ccm ? 4 : 3;
            mode.init(sealing, new org.bouncycastle.crypto.params.AEADParameters(
                new KeyParameter(hex(f[0])), 8 * Integer.parseInt(f[2]), hex(f[1])));
            byte[] aad = hex(f[at]);
            mode.processAADBytes(aad, 0, aad.length);
            byte[] d = hex(f[at + 1]);
            byte[] out = new byte[mode.getOutputSize(d.length)];
            int n = mode.processBytes(d, 0, d.length, out, 0);
            n += mode.doFinal(out, n);
            byte[] trimmed = new byte[n];
            System.arraycopy(out, 0, trimmed, 0, n);
            return trimmed;
        }
        if (op.startsWith("kalyna-gmac-")) {
            int bits = Integer.parseInt(op.substring("kalyna-gmac-".length()));
            org.bouncycastle.crypto.macs.KGMac mac = new org.bouncycastle.crypto.macs.KGMac(
                new org.bouncycastle.crypto.modes.KGCMBlockCipher(new DSTU7624Engine(bits)),
                8 * Integer.parseInt(f[1]));
            mac.init(new ParametersWithIV(new KeyParameter(hex(f[0])), new byte[bits / 8]));
            byte[] m = hex(f.length > 2 ? f[2] : "-");
            mac.update(m, 0, m.length);
            byte[] out = new byte[mac.getMacSize()];
            mac.doFinal(out, 0);
            return out;
        }
        if (op.startsWith("kalyna-xts-") || op.startsWith("kalyna-unxts-")) {
            int bits = Integer.parseInt(op.substring(op.lastIndexOf('-') + 1));
            org.bouncycastle.crypto.modes.KXTSBlockCipher x =
                new org.bouncycastle.crypto.modes.KXTSBlockCipher(new DSTU7624Engine(bits));
            x.init(op.startsWith("kalyna-xts-"),
                   new ParametersWithIV(new KeyParameter(hex(f[0])), hex(f[1])));
            byte[] d = hex(f[2]);
            byte[] out = new byte[d.length];
            x.processBytes(d, 0, d.length, out, 0);
            x.doFinal(out, d.length);
            return out;
        }
        if (op.startsWith("kalyna-")) {
            int bits = Integer.parseInt(op.substring("kalyna-".length()));
            return stream(new DSTU7624Engine(bits), new KeyParameter(hex(f[0])), hex(f[1]));
        }
        if (op.startsWith("kupyna-mac-")) {
            int bits = Integer.parseInt(op.substring("kupyna-mac-".length()));
            org.bouncycastle.crypto.macs.DSTU7564Mac mac =
                new org.bouncycastle.crypto.macs.DSTU7564Mac(bits);
            mac.init(new KeyParameter(hex(f[0])));
            byte[] m = hex(f.length > 1 ? f[1] : "-");
            mac.update(m, 0, m.length);
            byte[] out = new byte[mac.getMacSize()];
            mac.doFinal(out, 0);
            return out;
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

    // The bytes of e, as BigIntegers.createRandomBigInteger reads them:
    // (bits + 7) / 8 of them, big endian, the spare top bits masked.
    static class FixedRandom extends java.security.SecureRandom {
        final byte[] data;
        FixedRandom(byte[] data) { this.data = data; }
        public void nextBytes(byte[] out) {
            if (out.length != data.length) {
                throw new IllegalStateException("asked for " + out.length + " bytes");
            }
            System.arraycopy(data, 0, out, 0, out.length);
        }
    }

    static java.math.BigInteger big(String s) {
        return new java.math.BigInteger(s, 16);
    }

    static org.bouncycastle.crypto.params.ECDomainParameters domain(String spec) {
        if (!spec.contains(":")) {
            return org.bouncycastle.asn1.ua.DSTU4145NamedCurves.getByOID(
                new org.bouncycastle.asn1.ASN1ObjectIdentifier(
                    org.bouncycastle.asn1.ua.UAObjectIdentifiers.dstu4145le.getId() + ".2." + spec));
        }
        String[] p = spec.split(":");
        int m = Integer.parseInt(p[0]);
        String[] k = p[1].split(",");
        java.math.BigInteger a = big(p[2]), b = big(p[3]), n = big(p[4]);
        java.math.BigInteger h = java.math.BigInteger.ONE.shiftLeft(m).add(n.shiftRight(1)).divide(n);
        org.bouncycastle.math.ec.ECCurve curve = k.length == 1
            ? new org.bouncycastle.math.ec.ECCurve.F2m(m, Integer.parseInt(k[0]), a, b, n, h)
            : new org.bouncycastle.math.ec.ECCurve.F2m(m, Integer.parseInt(k[2]),
                  Integer.parseInt(k[1]), Integer.parseInt(k[0]), a, b, n, h);
        return new org.bouncycastle.crypto.params.ECDomainParameters(
            curve, curve.createPoint(big(p[5]), big(p[6])), n, h);
    }

    static String fe(org.bouncycastle.crypto.params.ECDomainParameters d, java.math.BigInteger x) {
        int len = (d.getCurve().getFieldSize() + 7) / 8;
        return Hex.toHexString(org.bouncycastle.util.BigIntegers.asUnsignedByteArray(len, x));
    }

    static String point(org.bouncycastle.crypto.params.ECDomainParameters d,
                        org.bouncycastle.math.ec.ECPoint p) {
        p = p.normalize();
        return fe(d, p.getAffineXCoord().toBigInteger()) + " "
            + fe(d, p.getAffineYCoord().toBigInteger());
    }

    static String dstu4145(String op, String[] f) throws Exception {
        org.bouncycastle.crypto.params.ECDomainParameters d = domain(f[0]);
        org.bouncycastle.crypto.signers.DSTU4145Signer signer =
            new org.bouncycastle.crypto.signers.DSTU4145Signer();
        switch (op) {
            case "dstu4145-pub":
                return point(d, d.getG().multiply(big(f[1])).negate());
            case "dstu4145-sign": {
                int bits = d.getN().bitLength() - 1;
                byte[] e = org.bouncycastle.util.BigIntegers.asUnsignedByteArray(
                    (bits + 7) / 8, big(f[2]));
                signer.init(true, new org.bouncycastle.crypto.params.ParametersWithRandom(
                    new org.bouncycastle.crypto.params.ECPrivateKeyParameters(big(f[1]), d),
                    new FixedRandom(e)));
                java.math.BigInteger[] rs = signer.generateSignature(hex(f[3]));
                return rs[0].toString(16) + " " + rs[1].toString(16);
            }
            case "dstu4145-verify": {
                signer.init(false, new org.bouncycastle.crypto.params.ECPublicKeyParameters(
                    d.getCurve().createPoint(big(f[1]), big(f[2])), d));
                return signer.verifySignature(hex(f[3]), big(f[4]), big(f[5])) ? "01" : "00";
            }
            case "dstu4145-compress":
                return Hex.toHexString(org.bouncycastle.asn1.ua.DSTU4145PointEncoder.encodePoint(
                    d.getCurve().createPoint(big(f[1]), big(f[2]))));
            case "dstu4145-decompress":
                return point(d, org.bouncycastle.asn1.ua.DSTU4145PointEncoder.decodePoint(
                    d.getCurve(), hex(f[1])));
            case "dstu4145-dh": {
                org.bouncycastle.crypto.BasicAgreement agreement = f[4].equals("1")
                    ? new org.bouncycastle.crypto.agreement.ECDHCBasicAgreement()
                    : new org.bouncycastle.crypto.agreement.ECDHBasicAgreement();
                agreement.init(new org.bouncycastle.crypto.params.ECPrivateKeyParameters(big(f[1]), d));
                return fe(d, agreement.calculateAgreement(
                    new org.bouncycastle.crypto.params.ECPublicKeyParameters(
                        d.getCurve().createPoint(big(f[2]), big(f[3])), d)));
            }
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
                String[] f = line.trim().split(" ");
                out.append(args[0].startsWith("dstu4145") ? dstu4145(args[0], f)
                           : Hex.toHexString(run(args[0], f)));
            } catch (Exception e) {
                out.append("error: ").append(e.getClass().getSimpleName()).append(' ')
                   .append(String.valueOf(e.getMessage()).replace('\n', ' '));
            }
            out.append('\n');
        }
        System.out.print(out);
    }
}
