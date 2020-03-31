package uk.gov.ida.cloudhsmtool;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import picocli.CommandLine;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Period;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.concurrent.Callable;

@CommandLine.Command(
        name = "create-chained-cert",
        description = "Creates a chained certificate for a CloudHSM label"
)
public class CreateChainedCertificate extends CreateSelfSignedCertificate implements Callable<Void> {

    @CommandLine.Option(names = {"-parent-cert-base64"}, required = true)
    protected String parentCertBase64;

    @CommandLine.Option(names = {"-ca-cert"}, defaultValue = "false")
    protected boolean certAuthority;

    @CommandLine.Option(names = {"-parent-key-label"}, required = true)
    protected String parentKeyLabel;

    @Override
    X509Certificate generateCertificate(KeyPair keyPair) throws Exception {

        X509Certificate parentCert = getParentCertificate(parentCertBase64);

        ZonedDateTime now = ZonedDateTime.now();
        ZonedDateTime expiry = now.plus(Period.ofMonths(expiryMonths));

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                parentCert, // parent cert is the issuer authority
                new BigInteger(64, new SecureRandom()),
                Date.from(now.toInstant()),
                Date.from(expiry.toInstant()),
                buildSubject(),
                keyPair.getPublic());

        Key parentKey = cloudHSMWrapper.getPrivateKey(this.parentKeyLabel);

        if (certAuthority) {
            certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        } else {
            certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        }

        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic()));
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(parentCert.getPublicKey()));

        return buildX509Certificate(certBuilder, (PrivateKey) parentKey);
    }

    private X509Certificate getParentCertificate(String pemString) throws CertificateException, IOException {
        StringReader stringReader = new StringReader(pemString);
        PemReader pemReader = new PemReader(stringReader);
        PemObject pemObject = pemReader.readPemObject();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(pemObject.getContent());
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(inputStream);
        return cert;
    }

}
