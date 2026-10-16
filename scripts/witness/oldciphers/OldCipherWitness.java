// java -cp bcprov.jar:OUT OldCipherWitness CIPHER
//
// Bouncy Castle's engine for CIPHER as a witness, speaking
// ../nessie/driver.h's request format on stdin and stdout:
//
//   enc <key hex> <block hex>, dec ..., enc-n ... <n>, dec-n ... <n>
//
// answered with hex, or "error lengths" where the engine refuses the key
// or the block is not one block. CIPHER is
//
//   skipjack   SkipjackEngine
//   threefish256, threefish512, threefish1024
//              ThreefishEngine, with the key alone, given as a
//              KeyParameter, or the key followed by the 16 byte tweak,
//              given as TweakableBlockCipherParameters
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.SkipjackEngine;
import org.bouncycastle.crypto.engines.ThreefishEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.TweakableBlockCipherParameters;
import org.bouncycastle.util.encoders.Hex;

public class OldCipherWitness {
    static BlockCipher engine(String cipher, boolean encrypting, byte[] key) {
        BlockCipher c;
        CipherParameters params = new KeyParameter(key);
        switch (cipher) {
            case "skipjack":
                // The engine reads the first ten bytes of a longer key
                // and pads nothing; ten bytes is the only Skipjack key.
                if (key.length != 10) throw new IllegalArgumentException("length");
                c = new SkipjackEngine();
                break;
            case "threefish256":
            case "threefish512":
            case "threefish1024": {
                // A fresh engine each time: the engine keeps an earlier
                // tweak when given a key alone. It checks the key's length.
                int bytes = Integer.parseInt(cipher.substring("threefish".length())) / 8;
                c = new ThreefishEngine(8 * bytes);
                if (key.length == bytes + 16)
                    params = new TweakableBlockCipherParameters(
                        new KeyParameter(Arrays.copyOf(key, bytes)),
                        Arrays.copyOfRange(key, bytes, bytes + 16));
                break;
            }
            default: throw new IllegalStateException("unknown cipher " + cipher);
        }
        c.init(encrypting, params);
        return c;
    }

    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = in.readLine()) != null) {
            String[] p = line.trim().split("\\s+");
            String answer;
            try {
                boolean iterated = p[0].equals("enc-n") || p[0].equals("dec-n");
                boolean encrypting = p[0].startsWith("enc");
                if (!iterated && !p[0].equals("enc") && !p[0].equals("dec"))
                    throw new IllegalArgumentException("op");
                long n = iterated ? Long.parseLong(p[3]) : 1;
                BlockCipher c = engine(args[0], encrypting, Hex.decode(p[1]));
                byte[] block = Hex.decode(p[2]);
                if (block.length != c.getBlockSize() || n < 1)
                    throw new IllegalArgumentException("lengths");
                byte[] out = new byte[block.length];
                for (long i = 0; i < n; i++) {
                    c.processBlock(block, 0, out, 0);
                    System.arraycopy(out, 0, block, 0, block.length);
                }
                answer = Hex.toHexString(block);
            } catch (IllegalStateException e) {
                throw e;
            } catch (RuntimeException e) {
                answer = "error lengths";
            }
            System.out.println(answer);
            System.out.flush();
        }
    }
}
