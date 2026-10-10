// java -cp bcprov.jar:OUT BlockWitness ENGINE
//
// Reads "KEY PLAINTEXT" lines of hex on stdin and writes the ciphertext
// of each block under Bouncy Castle's engine, one hex line per input
// line, or "error: <message>" where the engine refuses the key. The
// engine is constructed fresh for every line, so no state carries over.
import java.io.BufferedReader;
import java.io.InputStreamReader;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class BlockWitness {
    static BlockCipher engine(String name) {
        switch (name) {
            case "rc6": return new org.bouncycastle.crypto.engines.RC6Engine();
            case "cast256": return new org.bouncycastle.crypto.engines.CAST6Engine();
            // "rijndael160" and so on: the block size in bits follows the name.
            case "rijndael128": case "rijndael160": case "rijndael192":
            case "rijndael224": case "rijndael256":
                return new org.bouncycastle.crypto.engines.RijndaelEngine(
                    Integer.parseInt(name.substring("rijndael".length())));
            default: throw new IllegalArgumentException("unknown engine " + name);
        }
    }

    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        StringBuilder out = new StringBuilder();
        String line;
        while ((line = in.readLine()) != null) {
            String[] parts = line.trim().split(" ");
            byte[] key = parts[0].equals("-") ? new byte[0] : Hex.decode(parts[0]);
            byte[] pt = Hex.decode(parts[1]);
            try {
                BlockCipher c = engine(args[0]);
                c.init(true, new KeyParameter(key));
                byte[] ct = new byte[pt.length];
                for (int off = 0; off < pt.length; off += c.getBlockSize()) {
                    c.processBlock(pt, off, ct, off);
                }
                out.append(Hex.toHexString(ct));
            } catch (Exception e) {
                out.append("error: ").append(e.getClass().getSimpleName()).append(' ')
                   .append(String.valueOf(e.getMessage()).replace('\n', ' '));
            }
            out.append('\n');
        }
        System.out.print(out);
    }
}
