// Bouncy Castle 1.77's ISAACEngine as a witness, under the request lines
// driver.h describes; 32 bit requests only.
//
// ISAACEngine reads the key into the seed array as little-endian words,
// as driver.h does, and runs randinit and one isaac() call in init. It
// then calls isaac() again before its first byte, so block 0 is never
// output: its keystream is blocks 1, 2, .. with each block's words in
// index order and each word big endian. Requests with <first> 0 are
// refused, and each word is turned back to little endian here. The
// keystream is taken in pieces of 1, 2, 3 .. bytes. A key ISAACEngine
// cannot take answers "error" and the exception.
import java.io.BufferedReader;
import java.io.InputStreamReader;
import org.bouncycastle.crypto.engines.ISAACEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class IsaacWitness {
    static String answer(String line) {
        String[] f = line.trim().split(" ");
        if (f.length != 5 || !f[0].equals("isaac")) return "error request";
        if (!f[1].equals("32")) return "error unsupported";
        byte[] key = f[2].equals("-") ? new byte[0] : Hex.decode(f[2]);
        int first = Integer.parseInt(f[3]), count = Integer.parseInt(f[4]);
        if (count < 1 || count > 64 || first > 1024) return "error request";
        if (first == 0) return "error unsupported";
        if (key.length > 1024) return "error key";
        ISAACEngine c = new ISAACEngine();
        int n = (first - 1 + count) * 1024;
        byte[] out = new byte[n];
        try {
            c.init(true, new KeyParameter(key));
            byte[] zero = new byte[n];
            for (int at = 0, piece = 1; at < n; piece++) {
                int take = Math.min(piece, n - at);
                c.processBytes(zero, at, take, out, at);
                at += take;
            }
        } catch (RuntimeException e) {
            return "error " + e.getClass().getSimpleName();
        }
        byte[] blocks = new byte[count * 1024];
        int from = (first - 1) * 1024;
        for (int i = 0; i < blocks.length; i += 4) {
            for (int j = 0; j < 4; j++) blocks[i + j] = out[from + i + 3 - j];
        }
        return Hex.toHexString(blocks);
    }

    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        for (String line; (line = in.readLine()) != null; ) {
            System.out.println(answer(line));
            System.out.flush();
        }
    }
}
