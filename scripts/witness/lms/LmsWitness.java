// Bouncy Castle 1.77's LMS and HSS as a witness, under the request lines
// selftest.py describes. A tree is an LMSPrivateKeyParameters from SEED
// and I at the leaf asked for, signing through LMSSigner. A hierarchy is
// HSSPrivateKeyParameters over the top tree and placeholders below it,
// which resetKeyToIndex - package-private, reached by reflection, as is
// LMSSignature - replaces with the trees the index calls for, derived from
// their parents as the library derives them; HSSSigner signs and
// verifies.
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.pqc.crypto.lms.HSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.HSSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.HSSSigner;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSSigner;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.util.encoders.Hex;

public class LmsWitness {
    static byte[] unhex(String s) {
        return s.equals("-") ? new byte[0] : Hex.decode(s);
    }

    // The parameter sets by type code, from the classes' public fields:
    // the lookup by type is package-private.
    static Object byType(Class<?> c, int type) throws Exception {
        for (java.lang.reflect.Field field : c.getFields()) {
            if (field.getType() == c) {
                Object p = field.get(null);
                if ((int) c.getMethod("getType").invoke(p) == type) {
                    return p;
                }
            }
        }
        return null;
    }

    static LMSPrivateKeyParameters tree(LMSigParameters lm, LMOtsParameters ots, int q,
                                        byte[] id, byte[] seed) {
        return new LMSPrivateKeyParameters(lm, ots, q, id, 1 << lm.getH(), seed);
    }

    static byte[] lmsSign(LMSPrivateKeyParameters key, byte[] message) {
        LMSSigner signer = new LMSSigner();
        signer.init(true, key);
        return signer.generateSignature(message);
    }

    static String hss(String[] f) throws Exception {
        int levels = Integer.parseInt(f[1]);
        if (levels < 1 || levels > 8 || f.length != 2 + 2 * levels + 3) {
            return "error request";
        }
        LMSigParameters[] lm = new LMSigParameters[levels];
        LMOtsParameters[] ots = new LMOtsParameters[levels];
        for (int i = 0; i < levels; i++) {
            lm[i] = (LMSigParameters) byType(LMSigParameters.class, Integer.parseInt(f[2 + 2 * i]));
            ots[i] = (LMOtsParameters) byType(LMOtsParameters.class,
                                              Integer.parseInt(f[3 + 2 * i]));
            if (lm[i] == null || ots[i] == null) {
                return "error unsupported";
            }
        }
        byte[] seedI = unhex(f[2 + 2 * levels]);
        long count = Long.parseLong(f[3 + 2 * levels]);
        byte[] message = unhex(f[4 + 2 * levels]);
        int m = lm[0].getM();
        byte[] seed = java.util.Arrays.copyOfRange(seedI, 0, m);
        byte[] id = java.util.Arrays.copyOfRange(seedI, m, m + 16);
        if (seedI.length != m + 16) {
            return "error request";
        }
        long limit = 1;
        for (int i = 0; i < levels; i++) {
            limit <<= lm[i].getH();
        }
        Method parse = Class.forName("org.bouncycastle.pqc.crypto.lms.LMSSignature")
            .getMethod("getInstance", Object.class);
        parse.setAccessible(true);
        List<LMSPrivateKeyParameters> keys = new ArrayList<>();
        List sigs = new ArrayList();
        keys.add(tree(lm[0], ots[0], 0, id, seed));
        for (int i = 1; i < levels; i++) {
            LMSPrivateKeyParameters placeholder = tree(lm[i], ots[i], 0, new byte[16],
                                                       new byte[lm[i].getM()]);
            keys.add(placeholder);
            sigs.add(parse.invoke(null, (Object) lmsSign(tree(lm[i - 1], ots[i - 1], 0, id, seed),
                placeholder.getPublicKey().getEncoded())));
        }
        HSSPrivateKeyParameters key = new HSSPrivateKeyParameters(levels, keys, sigs, count, limit);
        Method reset = HSSPrivateKeyParameters.class.getDeclaredMethod("resetKeyToIndex");
        reset.setAccessible(true);
        reset.invoke(key);
        HSSSigner signer = new HSSSigner();
        signer.init(true, key);
        byte[] signature = signer.generateSignature(message);
        return Hex.toHexString(key.getPublicKey().getEncoded()) + " "
            + Hex.toHexString(signature);
    }

    static String lms(String[] f) throws Exception {
        // lms <lms> <ots> <seed||I> <q> <message>
        if (f.length != 6) {
            return "error request";
        }
        LMSigParameters lm = (LMSigParameters) byType(LMSigParameters.class,
                                                      Integer.parseInt(f[1]));
        LMOtsParameters ots = (LMOtsParameters) byType(LMOtsParameters.class,
                                                       Integer.parseInt(f[2]));
        if (lm == null || ots == null) {
            return "error unsupported";
        }
        byte[] seedI = unhex(f[3]);
        int m = lm.getM();
        if (seedI.length != m + 16) {
            return "error request";
        }
        LMSPrivateKeyParameters key = tree(lm, ots, Integer.parseInt(f[4]),
            java.util.Arrays.copyOfRange(seedI, m, m + 16),
            java.util.Arrays.copyOfRange(seedI, 0, m));
        byte[] signature = lmsSign(key, unhex(f[5]));
        return Hex.toHexString(key.getPublicKey().getEncoded()) + " "
            + Hex.toHexString(signature);
    }

    static String verify(String[] f) {
        if (f.length != 4) {
            return "error request";
        }
        try {
            HSSSigner signer = new HSSSigner();
            signer.init(false, HSSPublicKeyParameters.getInstance(unhex(f[1])));
            return signer.verifySignature(unhex(f[2]), unhex(f[3])) ? "ok" : "bad";
        } catch (Exception e) {
            return "bad";
        }
    }

    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = in.readLine()) != null) {
            String[] f = line.trim().split(" ");
            String out;
            try {
                switch (f[0]) {
                    case "hss": out = hss(f); break;
                    case "lms": out = lms(f); break;
                    case "verify": out = verify(f); break;
                    default: out = "error request";
                }
            } catch (Exception e) {
                out = "error " + e.getClass().getSimpleName();
            }
            System.out.println(out);
            System.out.flush();
        }
    }
}
