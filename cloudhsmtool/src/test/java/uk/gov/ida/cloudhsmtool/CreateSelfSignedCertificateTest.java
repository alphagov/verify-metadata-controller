package uk.gov.ida.cloudhsmtool;

import org.junit.Test;
import org.junit.jupiter.api.Assertions;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.ida.cloudhsmtool.CloudHSMWrapper.SIGNING_ALGO_SHA384_WITH_ECDSA;
import static uk.gov.ida.cloudhsmtool.GenKeyPairTest.HSM_KEY_ALIAS;

@RunWith(MockitoJUnitRunner.class)
public class CreateSelfSignedCertificateTest extends HSMTestUtils {

    @Test
    public void shouldCreateASelfSignedCertificateWithKeysInHSM() throws Exception {
        ByteArrayOutputStream out = captureSystemOut();
        when(cloudHSMWrapper.containsAlias(HSM_KEY_ALIAS)).thenReturn(true);
        when(cloudHSMWrapper.getKeyPair(HSM_KEY_ALIAS)).thenReturn(new KeyPair(publicKey, privateKey));
        when(cloudHSMWrapper.getContentSigner(privateKey)).thenReturn(buildContentSigner(privateKey));
        CreateSelfSignedCertificate selfSigned = createSelfSignedCertificate(cloudHSMWrapper);
        CommandLine.call(selfSigned, HSM_KEY_ALIAS, "-CN", "common-name");
        X509Certificate certificate = readSystemOutToCertificate(out);
        assertThat(certificate.getSubjectDN().getName()).contains("CN=common-name");
        assertThat(certificate.getIssuerDN().getName()).contains("CN=common-name");
        assertThat(certificate.getSigAlgName()).isEqualTo(SIGNING_ALGO_SHA384_WITH_ECDSA);
    }

    @Test
    public void shouldThrowExceptionCreatingSignedCertificateWithoutKeysInHSM() throws Exception {
        when(cloudHSMWrapper.containsAlias(HSM_KEY_ALIAS)).thenReturn(false);
        CreateSelfSignedCertificate selfSigned = createSelfSignedCertificate(cloudHSMWrapper);
        Assertions.assertThrows(CommandLine.ExecutionException.class, () -> CommandLine.call(selfSigned, HSM_KEY_ALIAS, "-CN", "foo"));
        verify(cloudHSMWrapper).containsAlias(HSM_KEY_ALIAS);
        verifyNoMoreInteractions(cloudHSMWrapper);
    }

}