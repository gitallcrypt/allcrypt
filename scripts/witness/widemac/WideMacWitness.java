// Bouncy Castle's CMAC and EAX over the wide-block ciphers, as a witness.
// The same request format as cryptopp_driver.cpp.
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.engines.Shacal2Engine;
import org.bouncycastle.crypto.engines.ThreefishEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class WideMacWitness {
    static BlockCipher engine(String name) {
        switch (name) {
            case "threefish256": return new ThreefishEngine(256);
            case "threefish512": return new ThreefishEngine(512);
            case "threefish1024": return new ThreefishEngine(1024);
            case "shacal2": return new Shacal2Engine();
            case "kalyna-256": return new DSTU7624Engine(256);
            case "kalyna-512": return new DSTU7624Engine(512);
            case "rijndael-160": return new RijndaelEngine(160);
            case "rijndael-192": return new RijndaelEngine(192);
            case "rijndael-224": return new RijndaelEngine(224);
            case "rijndael-256": return new RijndaelEngine(256);
            default: return null;
        }
    }

    static byte[] unhex(String text) {
        return text.equals("-") ? new byte[0] : Hex.decode(text);
    }

    static String hex(byte[] bytes) {
        return bytes.length == 0 ? "-" : Hex.toHexString(bytes);
    }

    static String answer(String line) {
        String[] f = line.trim().split("\\s+");
        if (f.length < 2) return "error op";
        BlockCipher cipher = engine(f[1]);
        if (cipher == null) return "error unsupported";
        try {
            if (f[0].equals("cmac") && f.length == 4) {
                CMac mac = new CMac(cipher);
                mac.init(new KeyParameter(unhex(f[2])));
                byte[] msg = unhex(f[3]);
                mac.update(msg, 0, msg.length);
                byte[] tag = new byte[mac.getMacSize()];
                mac.doFinal(tag, 0);
                return hex(tag);
            }
            if (f[0].equals("eax") && f.length == 6) {
                EAXBlockCipher eax = new EAXBlockCipher(cipher);
                int tagBits = cipher.getBlockSize() * 8;
                eax.init(true, new AEADParameters(new KeyParameter(unhex(f[2])), tagBits,
                                                   unhex(f[3]), unhex(f[4])));
                byte[] pt = unhex(f[5]);
                byte[] out = new byte[eax.getOutputSize(pt.length)];
                int n = eax.processBytes(pt, 0, pt.length, out, 0);
                n += eax.doFinal(out, n);
                int tagLen = cipher.getBlockSize();
                byte[] ct = new byte[n - tagLen], tag = new byte[tagLen];
                System.arraycopy(out, 0, ct, 0, ct.length);
                System.arraycopy(out, ct.length, tag, 0, tagLen);
                return hex(ct) + " " + hex(tag);
            }
            return "error op";
        } catch (Exception e) {
            return "error " + String.valueOf(e.getMessage()).replace('\n', ' ');
        }
    }

    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        for (String line; (line = in.readLine()) != null;) {
            System.out.println(answer(line));
            System.out.flush();
        }
    }
}
