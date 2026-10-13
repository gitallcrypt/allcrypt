// java -cp bcprov.jar:OUT NessieWitness CIPHER
//
// Bouncy Castle's engine for CIPHER as a NESSIE witness, speaking
// driver.h's request format on stdin and stdout:
//
//   enc <key hex> <block hex>, dec ..., enc-n ... <n>, dec-n ... <n>
//
// answered with hex, or "error lengths" where the engine refuses the key
// or the block is not one block. CIPHER is
//
//   noekeon            NoekeonEngine, which is Noekeon's direct-key mode
//   noekeon-indirect   the indirect-key mode by its definition: the key
//                      encrypted by NoekeonEngine under the all-zero key,
//                      then used as a direct key
//   shacal2            Shacal2Engine, given the key zero-padded to 64
//                      bytes - SHACAL-2's definition of a shorter key -
//                      since the engine takes multiples of 8 bytes only
import java.io.BufferedReader;
import java.io.InputStreamReader;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.NoekeonEngine;
import org.bouncycastle.crypto.engines.Shacal2Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class NessieWitness {
    static BlockCipher engine(String cipher, boolean encrypting, byte[] key) {
        switch (cipher) {
            case "noekeon": {
                BlockCipher c = new NoekeonEngine();
                c.init(encrypting, new KeyParameter(key));
                return c;
            }
            case "noekeon-indirect": {
                if (key.length != 16) throw new IllegalArgumentException("length");
                BlockCipher zero = new NoekeonEngine();
                zero.init(true, new KeyParameter(new byte[16]));
                byte[] working = new byte[16];
                zero.processBlock(key, 0, working, 0);
                BlockCipher c = new NoekeonEngine();
                c.init(encrypting, new KeyParameter(working));
                return c;
            }
            case "shacal2": {
                if (key.length < 16 || key.length > 64) throw new IllegalArgumentException("length");
                BlockCipher c = new Shacal2Engine();
                c.init(encrypting, new KeyParameter(java.util.Arrays.copyOf(key, 64)));
                return c;
            }
            default: throw new IllegalStateException("unknown cipher " + cipher);
        }
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
