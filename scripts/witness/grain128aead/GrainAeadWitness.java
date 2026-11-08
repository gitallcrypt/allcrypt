// Bouncy Castle 1.77's Grain128AEADEngine as a witness, under the request
// lines rweather_grain.c describes. The associated data and the plaintext
// go in pieces of 1, 2, 3 .. bytes; the answer is the ciphertext followed
// by the tag, after a decryption of it gives the plaintext back.
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import org.bouncycastle.crypto.engines.Grain128AEADEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

public class GrainAeadWitness {
    static byte[] unhex(String s) {
        return s.equals("-") ? new byte[0] : Hex.decode(s);
    }

    static byte[] run(boolean encrypt, byte[] key, byte[] nonce, byte[] ad, byte[] in)
            throws Exception {
        Grain128AEADEngine e = new Grain128AEADEngine();
        e.init(encrypt, new ParametersWithIV(new KeyParameter(key), nonce));
        for (int at = 0, piece = 1; at < ad.length; piece++) {
            int take = Math.min(piece, ad.length - at);
            e.processAADBytes(ad, at, take);
            at += take;
        }
        byte[] out = new byte[e.getOutputSize(in.length)];
        int got = 0;
        for (int at = 0, piece = 1; at < in.length; piece++) {
            int take = Math.min(piece, in.length - at);
            got += e.processBytes(in, at, take, out, got);
            at += take;
        }
        got += e.doFinal(out, got);
        return Arrays.copyOf(out, got);
    }

    static String answer(String line) {
        String[] f = line.trim().split(" ");
        if (f.length != 5 || !f[0].equals("seal")) return "error request";
        try {
            byte[] key = unhex(f[1]), nonce = unhex(f[2]), ad = unhex(f[3]), pt = unhex(f[4]);
            byte[] sealed = run(true, key, nonce, ad, pt);
            // Bouncy Castle's engine has no decryption of its own: the
            // keystream XOR is the same both ways and its tag is over the
            // input, so a decryption is the plaintext's tag recomputed.
            byte[] ct = Arrays.copyOf(sealed, pt.length);
            byte[] keystream = run(true, key, nonce, ad, new byte[pt.length]);
            byte[] back = new byte[pt.length];
            for (int i = 0; i < back.length; i++) back[i] = (byte)(ct[i] ^ keystream[i]);
            if (!Arrays.equals(back, pt)) return "error decrypt";
            return Hex.toHexString(sealed);
        } catch (Exception e) {
            return "error " + e.getClass().getSimpleName();
        }
    }

    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        for (String line; (line = in.readLine()) != null; ) {
            System.out.println(answer(line));
            System.out.flush();
        }
    }
}
