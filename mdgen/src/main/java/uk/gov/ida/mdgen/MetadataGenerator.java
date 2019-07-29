package uk.gov.ida.mdgen;

import com.github.mustachejava.DefaultMustacheFactory;
import com.github.mustachejava.Mustache;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SSODescriptor;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Support;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;
import picocli.CommandLine;
import picocli.CommandLine.ArgGroup;
import se.litsec.opensaml.utils.ObjectUtils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;

public class MetadataGenerator implements Callable<Void> {
    private final Logger LOG = LoggerFactory.getLogger(MetadataGenerator.class);
    private final Yaml yaml = new Yaml();
    private BasicX509Credential samlSigningCredential;
    private BasicX509Credential metadataSigningCredential;
    private X509KeyInfoGeneratorFactory keyInfoGeneratorFactory;

    enum NodeType { connector, proxy }
    enum SigningAlgoType {
        rsa(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256),
        rsapss(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1),
        ecdsa(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256);

        private final String uri;

        SigningAlgoType(String uri) {
            this.uri = uri;
        }
    }

    @CommandLine.Parameters(index = "0", description = "Type of node")
    private NodeType nodeType;

    @CommandLine.Parameters(index = "1", description = "YAML definition file")
    private File yamlFile;

    @CommandLine.Parameters(index = "2", description = "Public X509 cert for metadata signing")
    private File metadataSigningCertFile;

    @CommandLine.Option(names = "--hsm-metadata-signing-label", description = "HSM Metadata key label", required = true)
    private String hsmMetadataKeyLabel;

    @CommandLine.Option(names = "--output", description = "Output metadata file")
    private File outputFile;

    @CommandLine.Option(names = "--algorithm", description = "Signing algorithm")
    private SigningAlgoType signingAlgo = SigningAlgoType.rsa;

    @CommandLine.Option(names = "--hsm-saml-signing-label", description = "HSM Signing key label (required for self-signed SAML Signing cert from HSM)")
    private String hsmSigningKeyLabel;

    @ArgGroup(exclusive = true, multiplicity = "1")
    SamlSigningCert samlSigningCert;

    static class SamlSigningCert {
        @CommandLine.Option(names = "--hsm-saml-signing-cert-file", description = "Public X509 cert for saml signing certificate generated by metadata-controller")
        private static File metadataControllerSuppliedSamlSigningCert;

        @CommandLine.Option(names = "--supplied-saml-signing-cert-file", description = "Public X509 cert for saml signing certificate supplied manually")
        private static File manuallySuppliedSamlSigningCert;
    }

    @CommandLine.Option(names = "--supplied-saml-encryption-cert-file", description = "Public X509 cert for saml encryption certificate supplied manually")
    private File manuallySuppliedSamlEncryptionsCert;

    public static void main(String[] args) throws InitializationException {
        InitializationService.initialize();
        CommandLine.call(new MetadataGenerator(), args);
    }

    @Override
    public Void call() throws Exception {
        setSecurityProvider();
        setupMetadataSigningCredential();
        setupSigningAlgo();
        setupKeyInfoGeneratorFactory();
        EntityDescriptor entityDescriptor = buildEntityDescriptor();
        XMLObjectSupport.marshallToOutputStream(entityDescriptor, getOutputStream());
        return null;
    }

    private OutputStream getOutputStream() throws FileNotFoundException {
        OutputStream outputStream;

        if (outputFile == null) {
            outputStream = System.out;
        } else {
            outputStream = new FileOutputStream(outputFile);
        }
        return outputStream;
    }

    private void setupMetadataSigningCredential() throws Exception {
        if (!metadataSigningCertFile.exists()) {
            System.err.println("MetadataSigningCertFile not found at: " + metadataSigningCertFile.getPath());
            Path currentRelativePath = Paths.get("");
            String s = currentRelativePath.toAbsolutePath().toString();
            System.err.println("Current relative path is: " + s);
            System.exit(1);
        }
        X509Certificate metadataSigningCert = decodeCertificate(metadataSigningCertFile);
        metadataSigningCredential = getSigningCredentialFromCloudHSM(metadataSigningCert, hsmMetadataKeyLabel);
    }

    private void setupSigningAlgo() {
        if (signingAlgo == SigningAlgoType.rsapss) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (metadataSigningCredential.getPublicKey() instanceof ECPublicKey) {
            LOG.warn("Credential public key is of EC type, using ECDSA signing algorithm");
            signingAlgo = SigningAlgoType.ecdsa;
        }
    }

    private void setupKeyInfoGeneratorFactory() {
        keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        keyInfoGeneratorFactory.setEmitEntityCertificate(true);
    }

    private BasicX509Credential getSigningCredentialFromCloudHSM(X509Certificate cert, String label) throws Exception {
        KeyStore cloudHsmStore = KeyStore.getInstance("Cavium");
        cloudHsmStore.load(null, null);
        PrivateKey key = (PrivateKey)cloudHsmStore.getKey(label, null);
        return new BasicX509Credential(cert, key);
    }

    private void setSecurityProvider() throws InstantiationException, IllegalAccessException, java.lang.reflect.InvocationTargetException, NoSuchMethodException, ClassNotFoundException {
        Provider caviumProvider = (Provider) ClassLoader.getSystemClassLoader()
            .loadClass("com.cavium.provider.CaviumProvider")
            .getConstructor()
            .newInstance();
        Security.addProvider(caviumProvider);
        JCEMapper.setProviderId("Cavium");
    }

    private String renderTemplate(String template, Map values) {
        Mustache mustache = new DefaultMustacheFactory().compile(template);
        StringWriter stringWriter = new StringWriter();
        mustache.execute(stringWriter, values);
        stringWriter.flush();
        return stringWriter.toString();
    }

    private EntityDescriptor buildEntityDescriptor() throws Exception {
        Map yamlMap = yaml.load(new FileInputStream(yamlFile));
        String xml = renderTemplate(nodeType.toString() + "_template.xml.mustache", yamlMap);
        EntityDescriptor entityDescriptor = ObjectUtils.unmarshall(new ByteArrayInputStream(xml.getBytes()), EntityDescriptor.class);
        entityDescriptor.setID(UUID.randomUUID().toString());
        entityDescriptor.setValidUntil(DateTime.now().plusDays(365));
        updateSsoDescriptors(entityDescriptor);
        sign(entityDescriptor);
        return entityDescriptor;
    }

    private void sign(EntityDescriptor entityDescriptor) throws SecurityException, MarshallingException, SignatureException {
        LOG.info("Attempting to sign metadata");
        LOG.info("\n  Algorithm: {}\n  Credential: {}\n",
            signingAlgo.uri,
            metadataSigningCredential.getEntityCertificate().getSubjectDN().getName());

        SignatureSigningParameters signingParams = new SignatureSigningParameters();
        signingParams.setSignatureAlgorithm(signingAlgo.uri);
        signingParams.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signingParams.setSigningCredential(metadataSigningCredential);
        signingParams.setKeyInfoGenerator(keyInfoGeneratorFactory.newInstance());

        SignatureSupport.signObject(entityDescriptor, signingParams);

        SAMLSignatureProfileValidator signatureProfileValidator = new SAMLSignatureProfileValidator();
        signatureProfileValidator.validate(entityDescriptor.getSignature());
        SignatureValidator.validate(entityDescriptor.getSignature(), metadataSigningCredential);
    }

    private void updateSsoDescriptors(EntityDescriptor entityDescriptor) throws Exception {
        addSamlSigningKeyDescriptor(getSsoDescriptor(entityDescriptor));
        addSamlEncryptionDescriptor(getSsoDescriptor(entityDescriptor));
    }

    private SSODescriptor getSsoDescriptor(EntityDescriptor entityDescriptor) {
        SSODescriptor spSso = null;
        switch (nodeType) {
            case connector:
                spSso = entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
                break;
            case proxy:
                spSso = entityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
                break;
        }
        return spSso;
    }

    private void addSamlSigningKeyDescriptor(SSODescriptor spSso) throws Exception {
        if ( SamlSigningCert.metadataControllerSuppliedSamlSigningCert != null ) {
            samlSigningCredential = getSigningCredentialFromCloudHSM(decodeCertificate(SamlSigningCert.metadataControllerSuppliedSamlSigningCert), hsmSigningKeyLabel);
        } else {
            samlSigningCredential = new BasicX509Credential(decodeCertificate(SamlSigningCert.manuallySuppliedSamlSigningCert));
        }
        spSso.getKeyDescriptors().add(buildKeyDescriptor(UsageType.SIGNING, samlSigningCredential));
    }

    private void addSamlEncryptionDescriptor(SSODescriptor spSso) throws Exception {
        BasicX509Credential samlEncCredential;
        if (manuallySuppliedSamlEncryptionsCert != null) {
            samlEncCredential = new BasicX509Credential(decodeCertificate(manuallySuppliedSamlEncryptionsCert));
        } else {
            samlEncCredential = samlSigningCredential;
        }
        spSso.getKeyDescriptors().add(buildKeyDescriptor(UsageType.ENCRYPTION, samlEncCredential));
    }

    private X509Certificate decodeCertificate(File certFile) throws CertificateException {
        return X509Support.decodeCertificate(certFile);
    }

    private KeyDescriptor buildKeyDescriptor(UsageType usageType, BasicX509Credential credential) throws SecurityException {
        KeyDescriptor keyDescriptor = (KeyDescriptor) XMLObjectSupport.buildXMLObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
        keyDescriptor.setUse(usageType);
        keyDescriptor.setKeyInfo(buildKeyInfo(credential));
        return keyDescriptor;
    }

    private KeyInfo buildKeyInfo(Credential credential) throws SecurityException {
        KeyInfo keyInfo = keyInfoGeneratorFactory.newInstance().generate(credential);
        return keyInfo;
    }
}
