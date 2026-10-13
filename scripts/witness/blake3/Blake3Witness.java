// Bouncy Castle's Blake3Digest. Requests as driver_c.c's: MODE/LENGTH/SEEK
// PATH, one per line on stdin, answered with the lowercase hex output or
// "error". The data goes in in pieces of 1, 2, 3 ... bytes.
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.bouncycastle.crypto.digests.Blake3Digest;
import org.bouncycastle.crypto.params.Blake3Parameters;
import org.bouncycastle.util.encoders.Hex;

public class Blake3Witness {
    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = in.readLine()) != null) {
            try {
                String[] fields = line.trim().split(" ");
                String[] parts = fields[0].split("/");
                int length = Integer.parseInt(parts[1]);
                int seek = Integer.parseInt(parts[2]);
                // At its default size: initialising with a context
                // derives the context key through doFinal at the digest's
                // size, into a 32 byte buffer, which fails for a larger
                // size in 1.77. The output comes from doOutput, the XOF.
                Blake3Digest digest = new Blake3Digest();
                if (parts[0].startsWith("keyed=")) {
                    digest.init(Blake3Parameters.key(Hex.decode(parts[0].substring(6))));
                } else if (parts[0].startsWith("derive=")) {
                    digest.init(Blake3Parameters.context(Hex.decode(parts[0].substring(7))));
                } else if (!parts[0].equals("hash")) {
                    throw new IllegalArgumentException(parts[0]);
                }
                byte[] data = Files.readAllBytes(Paths.get(fields[1]));
                for (int at = 0, step = 1; at < data.length; at += step, step++) {
                    digest.update(data, at, Math.min(step, data.length - at));
                }
                byte[] skipped = new byte[seek + 1];
                if (seek > 0) {
                    digest.doOutput(skipped, 0, seek);
                }
                byte[] out = new byte[length];
                digest.doOutput(out, 0, length);
                System.out.println(Hex.toHexString(out));
            } catch (Exception e) {
                System.out.println("error");
            }
            System.out.flush();
        }
    }
}
