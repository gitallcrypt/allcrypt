// Bouncy Castle 1.77's ZUC as a witness, under the request lines driver.h
// describes: Zuc128Engine and Zuc256Engine for the keystream, Zuc128Mac and
// Zuc256Mac for the MAC with a raw IV. Bouncy Castle's MACs take whole
// bytes, so a bit length that is not a multiple of eight is refused, and its
// engines stop after 2047 (ZUC-128) and 625 (ZUC-256) keystream words. The
// keystream is taken in pieces of 1, 2, 3 .. bytes.
import java.io.BufferedReader;
import java.io.InputStreamReader;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.Zuc128Engine;
import org.bouncycastle.crypto.engines.Zuc256Engine;
import org.bouncycastle.crypto.macs.Zuc128Mac;
import org.bouncycastle.crypto.macs.Zuc256Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

public class ZucWitness {
    static byte[] unhex(String s) {
        return s.equals("-") ? new byte[0] : Hex.decode(s);
    }

    static String stream(String[] f) {
        StreamCipher c;
        if (f[1].equals("zuc128")) c = new Zuc128Engine();
        else if (f[1].equals("zuc256")) c = new Zuc256Engine();
        else return "error unsupported";
        c.init(true, new ParametersWithIV(new KeyParameter(unhex(f[2])), unhex(f[3])));
        int n = Integer.parseInt(f[4]);
        byte[] out = new byte[n];
        byte[] zero = new byte[n];
        for (int at = 0, piece = 1; at < n; piece++) {
            int take = Math.min(piece, n - at);
            c.processBytes(zero, at, take, out, at);
            at += take;
        }
        return Hex.toHexString(out);
    }

    static String zucmac(String[] f) {
        int tagBits = Integer.parseInt(f[1]);
        byte[] key = unhex(f[2]);
        int bits = Integer.parseInt(f[4]);
        if (bits % 8 != 0) return "error whole bytes only";
        Mac m;
        if (key.length == 16) {
            if (tagBits != 32) return "error tag size";
            m = new Zuc128Mac();
        } else {
            m = new Zuc256Mac(tagBits);
        }
        m.init(new ParametersWithIV(new KeyParameter(key), unhex(f[3])));
        byte[] data = unhex(f[5]);
        m.update(data, 0, data.length);
        byte[] tag = new byte[m.getMacSize()];
        m.doFinal(tag, 0);
        return Hex.toHexString(tag);
    }

    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        for (String line; (line = in.readLine()) != null;) {
            String[] f = line.trim().split("\\s+");
            String answer;
            try {
                if (f.length == 5 && f[0].equals("stream")) answer = stream(f);
                else if (f.length == 6 && f[0].equals("zucmac")) answer = zucmac(f);
                else if (f.length == 8 && (f[0].equals("f8") || f[0].equals("f9")))
                    answer = "error unsupported";
                else answer = "error request";
            } catch (RuntimeException e) {
                answer = "error " + e.getMessage();
            }
            System.out.println(answer);
            System.out.flush();
        }
    }
}
