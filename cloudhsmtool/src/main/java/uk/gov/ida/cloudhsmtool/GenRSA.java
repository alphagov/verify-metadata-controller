package uk.gov.ida.cloudhsmtool;

import picocli.CommandLine;
import com.cavium.key.parameter.CaviumRSAKeyGenParameterSpec;
import com.cavium.key.parameter.CaviumECGenParameterSpec;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.params.DSAKeyParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.util.io.pem.PemObject;

import java.util.concurrent.Callable;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyPair;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateEncodingException;
import java.security.SecureRandom;
import java.time.ZonedDateTime;
import java.math.BigInteger;
import java.util.Date;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.lang.Exception;

@CommandLine.Command(
	name        = "genrsa",
	description = "Generate non extractable private key in HSM"
)
public class GenRSA implements Callable<Void> {

	private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
	private static final int DEFAULT_CERT_VALIDITY = 365 * 5; // 5years in days
	private static final int DEFAULT_KEY_SIZE = 2048;

	@CommandLine.Parameters(arity = "1", description = "Label")
	private String hsmKeyLabel;

	@Override
	public Void call() throws Exception {
		KeyStore ks = KeyStore.getInstance("Cavium");
		ks.load(null, null);
		if (!ks.containsAlias(hsmKeyLabel)) {
			generateRSAKeyPair(DEFAULT_KEY_SIZE, hsmKeyLabel);
		}
		ks.load(null, null);
		Key privateKey = ks.getKey(hsmKeyLabel, null);
		if (!(privateKey instanceof PrivateKey)) {
			throw new Exception("failed to fetch PrivateKey for "+hsmKeyLabel);
		}
		Key publicKey = ks.getKey(hsmKeyLabel+":public", null);
		if (!(publicKey instanceof PublicKey)) {
			throw new Exception("failed to fetch PublicKey for "+hsmKeyLabel+"public");
		}
		KeyPair kp = new KeyPair((PublicKey) publicKey, (PrivateKey) privateKey);
		X509Certificate cert = generateSelfSignedCert(kp, DEFAULT_CERT_VALIDITY);
		System.out.println(toPEM(cert));
		return null;
	}

	public String toPEM(X509Certificate cert) throws IOException, CertificateEncodingException {
		StringWriter buf = new StringWriter();
		PemWriter pemWriter = new PemWriter(buf);
		pemWriter.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
		pemWriter.close();
		return buf.toString();
	}


	// Generate an RSA key pair.
	// The label passed will be appended with ":public" for the public key.
	public KeyPair generateRSAKeyPair(int keySizeInBits, String label) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
			boolean isExtractable = false;
			boolean isPersistent = true;
			return generateRSAKeyPairWithParams(keySizeInBits, label, isExtractable, isPersistent);
	}

	public KeyPair generateRSAKeyPairWithParams(int keySizeInBits, String label, boolean isExtractable, boolean isPersistent) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("rsa", "Cavium");;
			CaviumRSAKeyGenParameterSpec spec = new CaviumRSAKeyGenParameterSpec(keySizeInBits, new BigInteger("65537"), label + ":public", label, isExtractable, isPersistent);
			keyPairGen.initialize(spec);
			return keyPairGen.generateKeyPair();
	}

	public static X509Certificate generateSelfSignedCert(KeyPair keyPair, int days) throws Exception {
		SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

		Date startDate = new Date();
		Date expiryDate = new Date((new Date()).getTime() + days * 86400000l);
		BigInteger serialNum = new BigInteger(64, new SecureRandom());

		X500NameBuilder subjectGen = new X500NameBuilder(BCStyle.INSTANCE);
		subjectGen.addRDN(BCStyle.CN, "signing");
		X500Name subject = subjectGen.build();

		X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
			subject,
			serialNum,
			startDate,
			expiryDate,
			subject,
			keyInfo
		);
		JcaX509ExtensionUtils instance = new JcaX509ExtensionUtils();
		certGen.addExtension(X509Extension.subjectKeyIdentifier, false, instance.createSubjectKeyIdentifier(keyInfo));

		ContentSigner signer = new CaviumRSAContentSigner(keyPair.getPrivate(), "SHA256withRSA");

		byte[] cert = certGen.build(signer).getEncoded();
		ByteArrayInputStream certStream = new ByteArrayInputStream(cert);
		return (X509Certificate) CertificateFactory
			.getInstance("X.509")
			.generateCertificate(certStream)
		;
	}
}
