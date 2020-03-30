package uk.gov.ida.cloudhsmtool;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.Before;
import org.mockito.Mock;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.Field;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static uk.gov.ida.cloudhsmtool.CloudHSMWrapper.SIGNING_ALGO_SHA384_WITH_ECDSA;

public class HSMTestUtils {

    @Mock
    protected CloudHSMWrapper cloudHSMWrapper;

    protected PrivateKey privateKey;

    protected PublicKey publicKey;

    @Before
    public void setUp() throws Exception {
        KeyPair keyPair = createKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
    }

    protected KeyPair createKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        return gen.generateKeyPair();
    }

    protected void setField(CloudHSMWrapper cloudHSMWrapper, Object callable) throws Exception {
        Field field = GenKeyPair.class.getSuperclass().getDeclaredField("cloudHSMWrapper");
        field.set(callable, cloudHSMWrapper);
    }

    protected ByteArrayOutputStream captureSystemOut() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new java.io.PrintStream(out));
        return out;
    }

    protected X509Certificate readSystemOutToCertificate(ByteArrayOutputStream out) throws IOException, CertificateException {
        final StringReader stringReader = new StringReader(out.toString());
        final PemReader pemReader = new PemReader(stringReader);
        final byte[] x509Data = pemReader.readPemObject().getContent();
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        Certificate certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(x509Data));
        return (X509Certificate) certificate;
    }

    protected ContentSigner buildContentSigner(PrivateKey privateKey) throws IOException, OperatorCreationException {
        AlgorithmIdentifier signatureAlgorithm = new DefaultSignatureAlgorithmIdentifierFinder().find(
                SIGNING_ALGO_SHA384_WITH_ECDSA);
        AlgorithmIdentifier digestAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find(signatureAlgorithm);
        AsymmetricKeyParameter privateKeyParam = PrivateKeyFactory.createKey(privateKey.getEncoded());
        ContentSigner contentSigner = new BcECContentSignerBuilder(signatureAlgorithm, digestAlgorithm).build(privateKeyParam);
        return contentSigner;
    }

    protected CreateSelfSignedCertificate createSelfSignedCertificate(CloudHSMWrapper cloudHSMWrapper) throws Exception {
        CreateSelfSignedCertificate createSelfSignedCertificate = new CreateSelfSignedCertificate();
        setField(cloudHSMWrapper, createSelfSignedCertificate);
        return createSelfSignedCertificate;
    }

}
