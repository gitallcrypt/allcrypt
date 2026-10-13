// Bouncy Castle's SipHash and SipHash128 MACs, at any round counts.
// Requests as driver_ref.c's, siphash only, one per line on stdin with a
// file of message, answered with the lowercase hex tag or "error". The
// data goes in in pieces of 1, 2, 3 ... bytes.
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.macs.SipHash;
import org.bouncycastle.crypto.macs.SipHash128;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class SipHashWitness {
    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = in.readLine()) != null) {
            try {
                String[] fields = line.trim().split(" ");
                String[] nameKey = fields[0].split(":");
                String[] parts = nameKey[0].split("-");
                if (!parts[0].equals("siphash")) {
                    throw new IllegalArgumentException(parts[0]);
                }
                int c = Integer.parseInt(parts[1]), d = Integer.parseInt(parts[2]);
                int bytes = Integer.parseInt(parts[3]);
                Mac mac = bytes == 8 ? new SipHash(c, d) : bytes == 16 ? new SipHash128(c, d) : null;
                mac.init(new KeyParameter(Hex.decode(nameKey[1])));
                byte[] data = Files.readAllBytes(Paths.get(fields[1]));
                for (int at = 0, step = 1; at < data.length; at += step, step++) {
                    mac.update(data, at, Math.min(step, data.length - at));
                }
                byte[] out = new byte[mac.getMacSize()];
                mac.doFinal(out, 0);
                System.out.println(Hex.toHexString(out));
            } catch (Exception e) {
                System.out.println("error");
            }
            System.out.flush();
        }
    }
}
