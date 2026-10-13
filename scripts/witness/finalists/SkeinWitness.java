// Bouncy Castle's SkeinDigest at any state size and whole number of
// bytes out. One request per line on stdin, "skeinSTATE_BITS PATH",
// answered with the lowercase hex digest of the file's bytes, or
// "error". The data goes in in pieces of 1, 2, 3 ... bytes.
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.bouncycastle.crypto.digests.SkeinDigest;

public class SkeinWitness {
    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = in.readLine()) != null) {
            String[] fields = line.trim().split("\\s+");
            try {
                if (fields.length != 2 || !fields[0].matches("skein\\d+_\\d+")) {
                    throw new IllegalArgumentException(line);
                }
                String[] sizes = fields[0].substring(5).split("_");
                SkeinDigest digest = new SkeinDigest(Integer.parseInt(sizes[0]),
                                                     Integer.parseInt(sizes[1]));
                byte[] data = Files.readAllBytes(Paths.get(fields[1]));
                for (int at = 0, step = 1; at < data.length; at += step, step++) {
                    digest.update(data, at, Math.min(step, data.length - at));
                }
                byte[] out = new byte[digest.getDigestSize()];
                digest.doFinal(out, 0);
                StringBuilder hex = new StringBuilder();
                for (byte b : out) {
                    hex.append(String.format("%02x", b & 0xff));
                }
                System.out.println(hex);
            } catch (Exception e) {
                System.out.println("error");
            }
            System.out.flush();
        }
    }
}
