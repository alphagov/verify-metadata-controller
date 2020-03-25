package uk.gov.ida.cloudhsmtool;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static uk.gov.ida.cloudhsmtool.CloudHSMWrapper.SIGNING_ALGO_SHA384_WITH_ECDSA;
import static uk.gov.ida.cloudhsmtool.GenKeyPairTest.CA_HSM_KEY_ALIAS;
import static uk.gov.ida.cloudhsmtool.GenKeyPairTest.HSM_KEY_ALIAS;

@RunWith(MockitoJUnitRunner.class)
public class CreateChainedCertificateTest extends HSMTestUtils {

    @Test
    public void shouldCreateACertificateSignedByIssuer() throws Exception {

        KeyPair caKeyPair = createKeyPair();
        PrivateKey caPrivateKey = caKeyPair.getPrivate();

        when(cloudHSMWrapper.containsAlias(CA_HSM_KEY_ALIAS)).thenReturn(true);
        when(cloudHSMWrapper.getKeyPair(CA_HSM_KEY_ALIAS)).thenReturn(caKeyPair);
        when(cloudHSMWrapper.getPrivateKey(CA_HSM_KEY_ALIAS)).thenReturn(caPrivateKey);
        when(cloudHSMWrapper.getContentSigner(caPrivateKey)).thenReturn(buildContentSigner(caPrivateKey));

        when(cloudHSMWrapper.containsAlias(HSM_KEY_ALIAS)).thenReturn(true);
        when(cloudHSMWrapper.getKeyPair(HSM_KEY_ALIAS)).thenReturn(new KeyPair(publicKey, privateKey));

        // generate issuer cert
        ByteArrayOutputStream out = captureSystemOut();
        CreateSelfSignedCertificate selfSigned = createSelfSignedCertificate(cloudHSMWrapper);
        CommandLine.call(selfSigned, CA_HSM_KEY_ALIAS,
                "-CN", "ca");
        String caCertPem = out.toString();

        // generate cart signed by issuer
        out = captureSystemOut(); // recapture system out
        CreateChainedCertificate chainedCertificate = createChainedCertificate(cloudHSMWrapper);
        CommandLine.call(chainedCertificate, HSM_KEY_ALIAS,
                "-CN", "leaf",
                "-parent-key-label", CA_HSM_KEY_ALIAS,
                "-parent-cert-base64", caCertPem);

        X509Certificate certificate = readSystemOutToCertificate(out);
        assertThat(certificate.getSubjectDN().getName()).contains("CN=leaf");
        assertThat(certificate.getIssuerDN().getName()).contains("CN=ca");
        assertThat(certificate.getSigAlgName()).isEqualTo(SIGNING_ALGO_SHA384_WITH_ECDSA);
    }

    private CreateChainedCertificate createChainedCertificate(CloudHSMWrapper cloudHSMWrapper) throws Exception {
        CreateChainedCertificate createChainedCertificate = new CreateChainedCertificate();
        setField(cloudHSMWrapper, createChainedCertificate);
        return createChainedCertificate;
    }

}