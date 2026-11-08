// Bouncy Castle 1.77's XMSS and XMSS^MT as a witness, under the request
// lines selftest.py describes. Its WOTS+ keys are derived as RFC 8391
// suggests - a PRF of SK_SEED and the leaf's address, expanded per chain -
// not as SP 800-208 requires, so from the same seeds it makes other keys:
// it answers `sign-rfc8391`, from its own key generation fed SK_SEED,
// SK_PRF and SEED in the order it draws them, signing and discarding
// signatures until it reaches the index asked for, and it verifies
// RFC 8391's parameter sets; SP 800-208's are unknown to it.
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSSigner;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.encoders.Hex;

public class XmssWitness {
    static class Given extends SecureRandom {
        private final byte[] bytes;
        private int at;
        Given(byte[] bytes) { this.bytes = bytes; }
        @Override
        public void nextBytes(byte[] out) {
            System.arraycopy(bytes, at, out, 0, out.length);
            at += out.length;
        }
    }

    static byte[] unhex(String s) {
        return s.equals("-") ? new byte[0] : Hex.decode(s);
    }

    static String signRfc8391(String[] f) throws java.io.IOException {
        if (f.length != 6) {
            return "error request";
        }
        int oid = Integer.parseInt(f[2]);
        byte[] seeds = unhex(f[3]);
        long idx = Long.parseLong(f[4]);
        byte[] message = unhex(f[5]);
        AsymmetricCipherKeyPair pair;
        MessageSigner signer;
        int n;
        if (f[1].equals("xmss")) {
            XMSSParameters p = XMSSParameters.lookupByOID(oid);
            if (p == null) {
                return "error unsupported";
            }
            n = p.getTreeDigestSize();
            XMSSKeyPairGenerator g = new XMSSKeyPairGenerator();
            g.init(new XMSSKeyGenerationParameters(p, new Given(seeds)));
            pair = g.generateKeyPair();
            signer = new XMSSSigner();
        } else {
            XMSSMTParameters p = XMSSMTParameters.lookupByOID(oid);
            if (p == null) {
                return "error unsupported";
            }
            n = p.getTreeDigestSize();
            XMSSMTKeyPairGenerator g = new XMSSMTKeyPairGenerator();
            g.init(new XMSSMTKeyGenerationParameters(p, new Given(seeds)));
            pair = g.generateKeyPair();
            signer = new XMSSMTSigner();
        }
        if (seeds.length != 3 * n) {
            return "error request";
        }
        signer.init(true, pair.getPrivate());
        for (long i = 0; i < idx; i++) {
            signer.generateSignature(new byte[0]);
        }
        byte[] signature = signer.generateSignature(message);
        byte[] pub = f[1].equals("xmss")
            ? ((XMSSPublicKeyParameters) pair.getPublic()).getEncoded()
            : ((XMSSMTPublicKeyParameters) pair.getPublic()).getEncoded();
        return Hex.toHexString(pub) + " " + Hex.toHexString(signature);
    }

    static String verify(String[] f) {
        if (f.length != 5) {
            return "error request";
        }
        try {
            byte[] pk = unhex(f[2]);
            int oid = ((pk[0] & 0xff) << 24) | ((pk[1] & 0xff) << 16) | ((pk[2] & 0xff) << 8)
                | (pk[3] & 0xff);
            MessageSigner signer;
            if (f[1].equals("xmss")) {
                XMSSParameters p = XMSSParameters.lookupByOID(oid);
                if (p == null) {
                    return "error unsupported";
                }
                int n = p.getTreeDigestSize();
                if (pk.length != 4 + 2 * n) {
                    return "bad";
                }
                signer = new XMSSSigner();
                signer.init(false, new XMSSPublicKeyParameters.Builder(p)
                    .withRoot(Arrays.copyOfRange(pk, 4, 4 + n))
                    .withPublicSeed(Arrays.copyOfRange(pk, 4 + n, 4 + 2 * n)).build());
            } else {
                XMSSMTParameters p = XMSSMTParameters.lookupByOID(oid);
                if (p == null) {
                    return "error unsupported";
                }
                int n = p.getTreeDigestSize();
                if (pk.length != 4 + 2 * n) {
                    return "bad";
                }
                signer = new XMSSMTSigner();
                signer.init(false, new XMSSMTPublicKeyParameters.Builder(p)
                    .withRoot(Arrays.copyOfRange(pk, 4, 4 + n))
                    .withPublicSeed(Arrays.copyOfRange(pk, 4 + n, 4 + 2 * n)).build());
            }
            return signer.verifySignature(unhex(f[3]), unhex(f[4])) ? "ok" : "bad";
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
                    case "sign-rfc8391": out = signRfc8391(f); break;
                    case "sign": out = "error unsupported"; break;
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
