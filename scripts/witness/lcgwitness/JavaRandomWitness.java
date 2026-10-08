// java JavaRandomWitness SEED METHOD ARG COUNT
//
// java.util.Random seeded with the long SEED, METHOD called COUNT times
// and each result printed on its own line. ARG is nextInt's bound and
// nextBytes's length, and ignored otherwise. Doubles and floats print
// with Double.toString / Float.toString, which round-trip exactly; bytes
// print as hex.
import java.util.Random;

public class JavaRandomWitness {
    public static void main(String[] args) {
        Random r = new Random(Long.parseLong(args[0]));
        String method = args[1];
        int arg = Integer.parseInt(args[2]);
        int count = Integer.parseInt(args[3]);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < count; i++) {
            switch (method) {
                case "nextInt": out.append(r.nextInt()); break;
                case "nextIntBounded": out.append(r.nextInt(arg)); break;
                case "nextLong": out.append(r.nextLong()); break;
                case "nextBoolean": out.append(r.nextBoolean()); break;
                case "nextFloat": out.append(r.nextFloat()); break;
                case "nextDouble": out.append(r.nextDouble()); break;
                case "nextBytes": {
                    byte[] b = new byte[arg];
                    r.nextBytes(b);
                    for (byte x : b) out.append(String.format("%02x", x & 0xff));
                    break;
                }
                default: throw new IllegalArgumentException(method);
            }
            out.append('\n');
        }
        System.out.print(out);
    }
}
