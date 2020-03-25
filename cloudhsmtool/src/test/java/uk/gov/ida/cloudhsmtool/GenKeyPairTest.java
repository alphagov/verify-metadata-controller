package uk.gov.ida.cloudhsmtool;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import picocli.CommandLine;

import java.security.KeyPairGenerator;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class GenKeyPairTest extends HSMTestUtils {

    public static final String HSM_KEY_ALIAS = "label";
    public static final String CA_HSM_KEY_ALIAS = "ca_label";

    @Mock
    KeyPairGenerator keyPairGenerator;

    @Test
    public void shouldCreateKeyPairWhenKeystoreDoesNotContainPrivateKey() throws Exception {
        when(cloudHSMWrapper.containsAlias(HSM_KEY_ALIAS)).thenReturn(false);
        when(cloudHSMWrapper.getPrivateKey(HSM_KEY_ALIAS)).thenReturn(privateKey);
        when(cloudHSMWrapper.getPublicKey(HSM_KEY_ALIAS)).thenReturn(publicKey);
        when(cloudHSMWrapper.getKeyPairGenerator()).thenReturn(keyPairGenerator);
        GenKeyPair genKeyPair = createGenKeyPair(cloudHSMWrapper);
        CommandLine.call(genKeyPair, HSM_KEY_ALIAS);
        verify(keyPairGenerator).generateKeyPair();
    }

    @Test
    public void shouldNotCreateKeyPairWhenKeystoreContainsPrivateKey() throws Exception {
        when(cloudHSMWrapper.containsAlias(HSM_KEY_ALIAS)).thenReturn(true);
        when(cloudHSMWrapper.getPrivateKey(HSM_KEY_ALIAS)).thenReturn(privateKey);
        when(cloudHSMWrapper.getPublicKey(HSM_KEY_ALIAS)).thenReturn(publicKey);
        GenKeyPair genKeyPair = createGenKeyPair(cloudHSMWrapper);
        CommandLine.call(genKeyPair, HSM_KEY_ALIAS);
        verify(cloudHSMWrapper, never()).getKeyPairGenerator();
    }

    private GenKeyPair createGenKeyPair(CloudHSMWrapper cloudHSMWrapper) throws Exception {
        GenKeyPair genKeyPair = new GenKeyPair();
        setField(cloudHSMWrapper, genKeyPair);
        return genKeyPair;
    }

}