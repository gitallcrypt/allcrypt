/* Kerberos RC4-HMAC (RFC 4757) as a witness: Apache Kerby's kerb-crypto
 * (apache/directory-kerby, db7a0a0), Rc4HmacEnc, Rc4HmacExpEnc and
 * HmacMd5Rc4CheckSum, compiled from source with the classes they reach.
 * One request per line, hex, "-" for empty:
 *
 *   encrypt <enctype 23|24> <key> <usage> <plaintext>  -> ciphertext (random confounder)
 *   decrypt <enctype 23|24> <key> <usage> <ciphertext> -> plaintext
 *   checksum <key> <usage> <data>                       -> hmac-md5-arcfour
 *   prf <key> <input>                                   -> output
 *   s2k <password as UTF-8>                             -> key
 *
 * A refusal is "error ..." and the next line is still read. */
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import org.apache.kerby.kerberos.kerb.crypto.cksum.HmacMd5Rc4CheckSum;
import org.apache.kerby.kerberos.kerb.crypto.enc.Rc4HmacEnc;
import org.apache.kerby.kerberos.kerb.crypto.enc.Rc4HmacExpEnc;

public class KerbyRc4Witness {
    static byte[] unhex(String s) {
        if (s.equals("-")) return new byte[0];
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    static String hex(byte[] b) {
        if (b.length == 0) return "-";
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    static Rc4HmacEnc enc(String etype) {
        switch (etype) {
            case "23": return new Rc4HmacEnc();
            case "24": return new Rc4HmacExpEnc();
            default: throw new IllegalArgumentException("enctype " + etype);
        }
    }

    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line;
        while ((line = in.readLine()) != null) {
            String[] w = line.trim().split(" ");
            String answer;
            try {
                switch (w[0]) {
                    case "encrypt":
                        answer = hex(enc(w[1]).encrypt(unhex(w[4]), unhex(w[2]), Integer.parseUnsignedInt(w[3])));
                        break;
                    case "decrypt":
                        answer = hex(enc(w[1]).decrypt(unhex(w[4]), unhex(w[2]), Integer.parseUnsignedInt(w[3])));
                        break;
                    case "checksum":
                        answer = hex(new HmacMd5Rc4CheckSum().checksumWithKey(unhex(w[3]), unhex(w[1]),
                                                                            Integer.parseUnsignedInt(w[2])));
                        break;
                    case "prf":
                        answer = hex(new Rc4HmacEnc().prf(unhex(w[1]), unhex(w[2])));
                        break;
                    case "s2k":
                        String password = new String(unhex(w[1]), StandardCharsets.UTF_8);
                        answer = hex(new Rc4HmacEnc().str2key(password, "", null));
                        break;
                    default:
                        answer = "error request";
                }
            } catch (Exception e) {
                answer = "error " + e.getClass().getSimpleName();
            }
            System.out.println(answer);
            System.out.flush();
        }
    }
}
