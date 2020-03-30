package uk.gov.ida.cloudhsmtool;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import picocli.CommandLine;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
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
        name = "create-self-signed-cert",
        description = "Creates a self-signed certificate for given HSM keystore alias"
)
public class CreateSelfSignedCertificate extends HSMCli implements Callable<Void> {

    @CommandLine.Option(names = {"-C"}, description = "country code", defaultValue = "UK")
    protected String country;

    @CommandLine.Option(names = {"-L"}, description = "location", defaultValue = "London")
    protected String location;

    @CommandLine.Option(names = {"-O"}, description = "organization", defaultValue = "Cabinet Office")
    protected String organization;

    @CommandLine.Option(names = {"-OU"}, description = "organizational unit", defaultValue = "GDS")
    protected String organizationalUnit;

    @CommandLine.Option(names = {"-CN"}, required = true, description = "common name")
    protected String commonName;

    @CommandLine.Option(names = {"-expiry"}, description = "expiry in months", defaultValue = "12")
    protected Integer expiryMonths;

    @Override
    public Void call() throws Exception {

        final String hsmKeyLabel = getHsmKeyLabel();
        if (!cloudHSMWrapper.containsAlias(hsmKeyLabel)) {
            throw new IllegalStateException("Could not find keystore entry for alias " + hsmKeyLabel);
        }

        KeyPair kp = cloudHSMWrapper.getKeyPair(hsmKeyLabel);
        X509Certificate cert = generateCertificate(kp);
        System.out.println(toPEMFormat("CERTIFICATE", cert.getEncoded()));

        return null;
    }

    X509Certificate generateCertificate(KeyPair keyPair) throws Exception {

        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        ZonedDateTime now = ZonedDateTime.now();
        ZonedDateTime expiry = now.plus(Period.ofMonths(expiryMonths));
        BigInteger serialNum = new BigInteger(64, new SecureRandom());

        X500Name issuerAndSubject = buildSubject();

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                issuerAndSubject,
                serialNum,
                Date.from(now.toInstant()),
                Date.from(expiry.toInstant()),
                issuerAndSubject,
                keyInfo
        );

        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        return buildX509Certificate(certBuilder, keyPair.getPrivate());
    }

    X509Certificate buildX509Certificate(X509v3CertificateBuilder certBuilder, PrivateKey privateKey) throws IOException, CertificateException {
        ContentSigner signer = cloudHSMWrapper.getContentSigner(privateKey);
        byte[] cert = certBuilder.build(signer).getEncoded();
        ByteArrayInputStream certStream = new ByteArrayInputStream(cert);
        return (X509Certificate) CertificateFactory
                .getInstance("X.509")
                .generateCertificate(certStream);
    }

    X500Name buildSubject() {
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        nameBuilder.addRDN(BCStyle.C, country);
        nameBuilder.addRDN(BCStyle.L, location);
        nameBuilder.addRDN(BCStyle.O, organization);
        nameBuilder.addRDN(BCStyle.OU, organizationalUnit);
        nameBuilder.addRDN(BCStyle.CN, commonName);
        return nameBuilder.build();
    }

}
