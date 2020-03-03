package uk.gov.ida.cloudhsmtool;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import picocli.CommandLine;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public  class HSMCli {

    public static final BigInteger RSA_PUBLIC_EXPONENT = BigInteger.valueOf(65537);
    public static final String SIGNING_ALGO_SHA256_RSA = "SHA256WITHRSAANDMGF1";
    public static final String LABEL_PUBLIC_SUFFIX = ":public";
    public static final int DEFAULT_KEY_SIZE = 2048;
    public static final String PROVIDER_NAME_CAVIUM = "Cavium";

    @CommandLine.Parameters(arity = "1", description = "keystore alias")
    protected String hsmKeyLabel;

    protected KeyStore getKeystore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore ks = KeyStore.getInstance("Cavium");
        ks.load(null, null);
        return ks;
    }

    public String getHsmKeyLabel() {
        return hsmKeyLabel;
    }

    public String toPEMFormat(String header, byte[] encoded) throws IOException, CertificateEncodingException {
        StringWriter buf = new StringWriter();
        PemWriter pemWriter = new PemWriter(buf);
        pemWriter.writeObject(new PemObject(header, encoded));
        pemWriter.close();
        return buf.toString();
    }
}
