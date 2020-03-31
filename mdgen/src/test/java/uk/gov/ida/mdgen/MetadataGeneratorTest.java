package uk.gov.ida.mdgen;

import org.apache.xml.security.signature.XMLSignature;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import picocli.CommandLine;
import uk.gov.ida.cloudhsmtool.CloudHSMWrapper;
import uk.gov.ida.saml.core.test.OpenSAMLMockitoRunner;

import java.security.PrivateKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.ida.mdgen.MetadataGenerator.RFC1123Z_FORMAT_PATTERN;

@RunWith(OpenSAMLMockitoRunner.class)
public class MetadataGeneratorTest extends MdgenTestUtils {

    @Test
    public void shouldGenerateMetadataWithRSAKeysAndSigningAlgos() throws Exception {
        CloudHSMWrapper cloudHSMWrapper = mock(CloudHSMWrapper.class);
        MetadataGenerator metadataGenerator = createMetadataGenerator(cloudHSMWrapper);
        PrivateKey privateKey = readPrivateKey("./test/key.rsa.pk8", "RSA");
        when(cloudHSMWrapper.getPrivateKey(PRIVATE_KEY_ALIAS)).thenReturn(privateKey);
        String metadata = createTempFile("metadata");
        String expiryString = DateTime.now()
                .plus(Duration.standardDays(1))
                .toString(RFC1123Z_FORMAT_PATTERN);

        CommandLine.call(metadataGenerator,
                "proxy",
                "./test/proxy.yml",
                "./test/cert.rsa.pem",
                "--output", metadata,
                "--hsm-saml-signing-cert-file", "./test/test-metadata-signing-cert.pem",
                "--hsm-metadata-signing-key-label", PRIVATE_KEY_ALIAS,
                "--hsm-saml-signing-key-label", PRIVATE_KEY_ALIAS,
                "--validityTimestamp", expiryString
        );

        EntityDescriptor entityDescriptor = (EntityDescriptor) XMLObjectSupport.unmarshallFromInputStream(getParserPool(), getFileFromPath(metadata));
        assertThat(entityDescriptor.getSignature().getSignatureAlgorithm()).isEqualTo(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1);
    }

    @Test
    public void shouldGenerateMetadataWithECKeysAndSigningAlgos() throws Exception {
        CloudHSMWrapper cloudHSMWrapper = mock(CloudHSMWrapper.class);
        MetadataGenerator metadataGenerator = createMetadataGenerator(cloudHSMWrapper);
        PrivateKey privateKey = readPrivateKey("./test/key.ecdsa.pk8", "EC");
        when(cloudHSMWrapper.getPrivateKey(PRIVATE_KEY_ALIAS)).thenReturn(privateKey);
        String metadata = createTempFile("metadata");
        String expiryString = DateTime.now()
                .plus(Duration.standardDays(1))
                .toString(RFC1123Z_FORMAT_PATTERN);

        CommandLine.call(metadataGenerator,
                "proxy",
                "./test/proxy.yml",
                "./test/cert.ecdsa.pem",
                "--output", metadata,
                "--hsm-saml-signing-cert-file", "./test/cert.ecdsa.pem",
                "--hsm-metadata-signing-key-label", PRIVATE_KEY_ALIAS,
                "--hsm-saml-signing-key-label", PRIVATE_KEY_ALIAS,
                "--validityTimestamp", expiryString
        );

        EntityDescriptor entityDescriptor = (EntityDescriptor) XMLObjectSupport.unmarshallFromInputStream(getParserPool(), getFileFromPath(metadata));
        assertThat(entityDescriptor.getSignature().getSignatureAlgorithm()).isEqualTo(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA384);
    }


}