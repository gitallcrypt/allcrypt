// zilijonas/FEAL-NX's fealnx.encryption and fealnx.decryption as a
// witness, speaking ../nessie/driver.h's request format on stdin and
// stdout. The round count N is the environment's ROUNDS, 32 when it is
// not set; a key is FEAL-NX's 16 bytes, or FEAL-N's 8, which the
// FEAL-NX specification defines as the same with the right key half
// zero.
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;

public class FealWitness {
    static byte[] unhex(String s) {
        if (s.length() % 2 != 0) throw new IllegalArgumentException("hex");
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        String text = System.getenv("ROUNDS");
        int rounds = text == null || text.isEmpty() ? 32 : Integer.parseInt(text);
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
                byte[] key = unhex(p[1]);
                if (key.length == 8) key = Arrays.copyOf(key, 16);
                byte[] block = unhex(p[2]);
                if (key.length != 16 || block.length != 8 || n < 1)
                    throw new IllegalArgumentException("lengths");
                for (long i = 0; i < n; i++)
                    block = encrypting ? fealnx.encryption(block, key, rounds)
                                       : fealnx.decryption(block, key, rounds);
                answer = hex(block);
            } catch (RuntimeException e) {
                answer = "error lengths";
            }
            System.out.println(answer);
            System.out.flush();
        }
    }
}
