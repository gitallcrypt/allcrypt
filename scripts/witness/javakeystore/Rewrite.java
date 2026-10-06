// Re-writes a key store through Java's KeyStore API, for
// scripts/check_keystore.py: the one way to have Java write a store
// keytool will not, such as one under the empty password.
//
//     java Rewrite.java IN IN-TYPE IN-PASSWORD OUT OUT-TYPE OUT-PASSWORD
//
// Every entry is copied with its key under the output password. The
// algorithms are Java's defaults unless the keystore.pkcs12.* system
// properties say otherwise.

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.util.Collections;

public class Rewrite {
    public static void main(String[] args) throws Exception {
        char[] inPassword = args[2].toCharArray();
        char[] outPassword = args[5].toCharArray();
        KeyStore in = KeyStore.getInstance(args[1]);
        try (FileInputStream f = new FileInputStream(args[0])) {
            in.load(f, inPassword);
        }
        KeyStore out = KeyStore.getInstance(args[4]);
        out.load(null, null);
        for (String alias : Collections.list(in.aliases())) {
            if (in.isCertificateEntry(alias)) {
                out.setCertificateEntry(alias, in.getCertificate(alias));
            } else {
                out.setKeyEntry(alias, in.getKey(alias, inPassword), outPassword,
                                in.getCertificateChain(alias));
            }
        }
        try (FileOutputStream f = new FileOutputStream(args[3])) {
            out.store(f, outPassword);
        }
    }
}
