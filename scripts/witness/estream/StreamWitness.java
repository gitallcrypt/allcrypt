// Bouncy Castle's HC-128 and HC-256 as a witness: `stream <cipher> <key
// hex> <iv hex> <length>` per line; the first <length> bytes of keystream
// in hex, or "error ...". The keystream is taken in pieces of 1, 2, 3 ..
// bytes.
import java.io.BufferedReader;
import java.io.InputStreamReader;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.HC128Engine;
import org.bouncycastle.crypto.engines.HC256Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

public class StreamWitness {
    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        for (String line; (line = in.readLine()) != null;) {
            String[] f = line.trim().split("\\s+");
            String answer;
            if (f.length != 5 || !f[0].equals("stream")) {
                answer = "error request";
            } else {
                StreamCipher c;
                if (f[1].equals("hc128")) c = new HC128Engine();
                else if (f[1].equals("hc256")) c = new HC256Engine();
                else c = null;
                if (c == null) {
                    answer = "error unsupported";
                } else {
                    try {
                        byte[] key = Hex.decode(f[2]);
                        byte[] iv = f[3].equals("-") ? new byte[0] : Hex.decode(f[3]);
                        c.init(true, new ParametersWithIV(new KeyParameter(key), iv));
                        int n = Integer.parseInt(f[4]);
                        byte[] out = new byte[n];
                        byte[] zero = new byte[n];
                        for (int at = 0, piece = 1; at < n; piece++) {
                            int take = Math.min(piece, n - at);
                            c.processBytes(zero, at, take, out, at);
                            at += take;
                        }
                        answer = Hex.toHexString(out);
                    } catch (IllegalArgumentException e) {
                        answer = "error " + e.getMessage();
                    }
                }
            }
            System.out.println(answer);
            System.out.flush();
        }
    }
}
