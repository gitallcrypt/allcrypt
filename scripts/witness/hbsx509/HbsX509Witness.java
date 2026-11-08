/* HSS, XMSS and XMSS^MT in X.509 (RFC 9802) as a witness: Bouncy Castle
 * 1.85 (bcgit/bc-java, tag r1rv85), its provider, PQC provider and
 * certificate builder, compiled from source with the classes this file
 * reaches. One request per line, hex, "-" for empty:
 *
 *   selfsigned hss <lms type>/<lmots type>,...  -> certificate (BC's own key)
 *   selfsigned xmss <height>/<digest>           -> certificate
 *   selfsigned xmssmt <height>/<layers>/<digest> -> certificate
 *   verify <certificate> <issuer certificate>   -> "good" or "bad"
 *   spki <certificate>                          -> the subject key as BC writes it again
 *   cmssign <scheme> <params> <content> <attrs|noattrs> <attached|detached> [digest]
 *       -> a SignedData ContentInfo, signed by a key BC generates, with
 *          its self-signed certificate in it. The digest algorithm is
 *          BC's own choice unless one is named (a JCA name: SHA256,
 *          SHA512, SHAKE128, SHAKE256).
 *   cmsverify <signed data> <content|attached>  -> "good", or "bad" and why:
 *          every signer, against the certificate the message carries
 *   cmsdigest <signed data>                     -> each signer's digest
 *          algorithm and signature algorithm, DER, as BC reads them
 *
 * CMS is RFC 9708 for HSS; for XMSS and XMSS^MT nothing specifies it,
 * and these are what BC writes under RFC 9802's identifiers.
 *
 * Types are RFC 8554's codes in decimal; digests are XMSSParameterSpec's
 * names (SHA256, SHA512, SHAKE128, SHAKE256, SHA256/192, SHAKE256/256,
 * SHAKE256/192). A refusal is "error ..." and the next line is still
 * read. */
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collection;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.cms.CMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.LMSHSSKeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.LMSKeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.XMSSMTParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;

public class HbsX509Witness {
    static byte[] unhex(String s) {
        if (s.equals("-")) return new byte[0];
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return b.length == 0 ? "-" : sb.toString();
    }

    static KeyPair generate(String alg, String param) throws Exception {
        switch (alg) {
            case "hss": {
                String[] levels = param.split(",");
                LMSKeyGenParameterSpec[] specs = new LMSKeyGenParameterSpec[levels.length];
                for (int i = 0; i < levels.length; i++) {
                    String[] t = levels[i].split("/");
                    specs[i] = new LMSKeyGenParameterSpec(
                        LMSigParameters.getParametersForType(Integer.parseInt(t[0])),
                        LMOtsParameters.getParametersForType(Integer.parseInt(t[1])));
                }
                KeyPairGenerator g = KeyPairGenerator.getInstance("LMS", "BCPQC");
                g.initialize(new LMSHSSKeyGenParameterSpec(specs));
                return g.generateKeyPair();
            }
            case "xmss": {
                String[] t = param.split("/", 2);
                KeyPairGenerator g = KeyPairGenerator.getInstance("XMSS", "BCPQC");
                g.initialize(new XMSSParameterSpec(Integer.parseInt(t[0]), t[1]));
                return g.generateKeyPair();
            }
            case "xmssmt": {
                String[] t = param.split("/", 3);
                KeyPairGenerator g = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");
                g.initialize(new XMSSMTParameterSpec(Integer.parseInt(t[0]), Integer.parseInt(t[1]), t[2]));
                return g.generateKeyPair();
            }
            default:
                throw new IllegalArgumentException(alg);
        }
    }

    static String signatureName(String alg) {
        switch (alg) {
            case "hss": return "LMS";
            case "xmss": return "XMSS";
            default: return "XMSSMT";
        }
    }

    static X509CertificateHolder selfSigned(String alg, KeyPair kp) throws Exception {
        X500Name name = new X500Name("CN=Bouncy Castle " + alg);
        Date from = new Date(1735689600000L), to = new Date(2051222400000L);
        ContentSigner signer = new JcaContentSignerBuilder(signatureName(alg))
            .setProvider("BCPQC").build(kp.getPrivate());
        return new JcaX509v3CertificateBuilder(
            name, BigInteger.valueOf(9802), from, to, name, kp.getPublic()).build(signer);
    }

    static String cmsSign(String[] w) throws Exception {
        KeyPair kp = generate(w[1], w[2]);
        X509CertificateHolder cert = selfSigned(w[1], kp);
        byte[] content = unhex(w[3]);
        // The public key lets BC work out an HSS key's digest (the tree's
        // hash); for XMSS it has no rule, and one has to be named.
        JcaContentSignerBuilder sb = w.length > 6
            ? new JcaContentSignerBuilder(signatureName(w[1]),
                  new DefaultDigestAlgorithmIdentifierFinder().find(w[6]))
            : new JcaContentSignerBuilder(signatureName(w[1]), kp.getPublic());
        ContentSigner signer = sb.setProvider("BCPQC").build(kp.getPrivate());
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
            .setDirectSignature(w[4].equals("noattrs"))
            .build(signer, cert));
        gen.addCertificate(cert);
        CMSSignedData sd = gen.generate(new CMSProcessableByteArray(content), w[5].equals("attached"));
        return hex(sd.getEncoded("DER"));
    }

    // BC 1.85's CMS name table has LMS under id-alg-hss-lms-hashsig but
    // nothing under RFC 9802's XMSS and XMSS^MT identifiers, so it cannot
    // verify the XMSS messages its own generator writes ("Unknown
    // signature type requested: SHA256with1.3.6.1.5.5.7.6.34"). Those two
    // names are supplied here, the same names its content signer takes;
    // everything else is BC's own table.
    static final CMSSignatureAlgorithmNameGenerator NAMES = new CMSSignatureAlgorithmNameGenerator() {
        final DefaultCMSSignatureAlgorithmNameGenerator bc = new DefaultCMSSignatureAlgorithmNameGenerator();
        public String getSignatureName(AlgorithmIdentifier digest, AlgorithmIdentifier signature) {
            if (signature.getAlgorithm().equals(IANAObjectIdentifiers.id_alg_xmss_hashsig)) return "XMSS";
            if (signature.getAlgorithm().equals(IANAObjectIdentifiers.id_alg_xmssmt_hashsig)) return "XMSSMT";
            return bc.getSignatureName(digest, signature);
        }
    };

    static String cmsVerify(String[] w) throws Exception {
        CMSSignedData sd = w[2].equals("attached")
            ? new CMSSignedData(unhex(w[1]))
            : new CMSSignedData(new CMSProcessableByteArray(unhex(w[2])), unhex(w[1]));
        Store<X509CertificateHolder> certs = sd.getCertificates();
        Collection<SignerInformation> signers = sd.getSignerInfos().getSigners();
        if (signers.isEmpty()) return "bad no signers";
        for (SignerInformation si : signers) {
            Collection<X509CertificateHolder> matches = certs.getMatches(si.getSID());
            if (matches.isEmpty()) return "bad no certificate for a signer";
            SubjectPublicKeyInfo spki = matches.iterator().next().getSubjectPublicKeyInfo();
            PublicKey key = KeyFactory.getInstance(spki.getAlgorithm().getAlgorithm().getId(), "BCPQC")
                .generatePublic(new X509EncodedKeySpec(spki.getEncoded()));
            SignerInformationVerifier verifier = new SignerInformationVerifier(
                NAMES, new DefaultSignatureAlgorithmIdentifierFinder(),
                new JcaContentVerifierProviderBuilder().setProvider("BCPQC").build(key),
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());
            try {
                if (!si.verify(verifier))
                    return "bad signature";
            } catch (Exception e) {
                return "bad " + e.getClass().getSimpleName() + " " + e.getMessage();
            }
        }
        return "good";
    }

    static String cmsDigest(String[] w) throws Exception {
        CMSSignedData sd = new CMSSignedData(unhex(w[1]));
        StringBuilder sb = new StringBuilder();
        for (SignerInformation si : sd.getSignerInfos().getSigners()) {
            if (sb.length() > 0) sb.append(' ');
            sb.append(hex(si.getDigestAlgorithmID().getEncoded("DER"))).append(',')
              .append(hex(new AlgorithmIdentifier(si.getEncryptionAlgOID() == null ? null
                  : new org.bouncycastle.asn1.ASN1ObjectIdentifier(si.getEncryptionAlgOID()))
                  .getEncoded("DER")));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = in.readLine()) != null) {
            String[] w = line.trim().split(" ");
            String answer;
            try {
                switch (w[0]) {
                    case "selfsigned":
                        answer = hex(selfSigned(w[1], generate(w[1], w[2])).getEncoded());
                        break;
                    case "cmssign":
                        answer = cmsSign(w);
                        break;
                    case "cmsverify":
                        answer = cmsVerify(w);
                        break;
                    case "cmsdigest":
                        answer = cmsDigest(w);
                        break;
                    case "verify": {
                        X509CertificateHolder cert = new X509CertificateHolder(unhex(w[1]));
                        X509CertificateHolder issuer = new X509CertificateHolder(unhex(w[2]));
                        PublicKey key = KeyFactory.getInstance(
                            issuer.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId(), "BCPQC")
                            .generatePublic(new X509EncodedKeySpec(
                                issuer.getSubjectPublicKeyInfo().getEncoded()));
                        boolean ok = cert.isSignatureValid(
                            new JcaContentVerifierProviderBuilder().setProvider("BCPQC").build(key));
                        answer = ok ? "good" : "bad";
                        break;
                    }
                    case "spki": {
                        X509CertificateHolder cert = new X509CertificateHolder(unhex(w[1]));
                        SubjectPublicKeyInfo spki = cert.getSubjectPublicKeyInfo();
                        PublicKey key = KeyFactory.getInstance(
                            spki.getAlgorithm().getAlgorithm().getId(), "BCPQC")
                            .generatePublic(new X509EncodedKeySpec(spki.getEncoded()));
                        answer = hex(key.getEncoded());
                        break;
                    }
                    default:
                        answer = "error request";
                }
            } catch (Exception e) {
                answer = "error " + e.getClass().getSimpleName() + " " + e.getMessage();
            }
            System.out.println(answer.replace('\n', ' '));
            System.out.flush();
        }
    }
}
