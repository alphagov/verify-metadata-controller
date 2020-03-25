package uk.gov.ida.cloudhsmtool;

import com.cavium.key.parameter.CaviumECGenParameterSpec;
import picocli.CommandLine;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.concurrent.Callable;

import static uk.gov.ida.cloudhsmtool.CloudHSMWrapper.PUBLIC_KEY_SUFFIX;

@CommandLine.Command(
        name = "genkeypair",
        description = "Generate non extractable key pair in CloudHSM"
)
public class GenKeyPair extends HSMCli implements Callable<Void> {

    @Override
    public Void call() throws Exception {

        final String hsmKeyLabel = getHsmKeyLabel();
        if (!cloudHSMWrapper.containsAlias(hsmKeyLabel)) {
            generateECKeyPairWithParams(hsmKeyLabel);
        }

        // gets key from keystore and checks its private
        cloudHSMWrapper.getPrivateKey(hsmKeyLabel);
        PublicKey publicKey = cloudHSMWrapper.getPublicKey(hsmKeyLabel);
        System.out.println(toPEMFormat("PUBLIC KEY", publicKey.getEncoded()));

        return null;
    }

    private void generateECKeyPairWithParams(String label)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {

        boolean isExtractable = false;
        boolean isPersistent = true;

        KeyPairGenerator keyPairGenerator = cloudHSMWrapper.getKeyPairGenerator();
        CaviumECGenParameterSpec params = new CaviumECGenParameterSpec(
                CaviumECGenParameterSpec.PRIME384,
                String.format("%s%s", label, PUBLIC_KEY_SUFFIX),
                label,
                isExtractable,
                isPersistent);
        keyPairGenerator.initialize(params);
        keyPairGenerator.generateKeyPair();
    }

}
