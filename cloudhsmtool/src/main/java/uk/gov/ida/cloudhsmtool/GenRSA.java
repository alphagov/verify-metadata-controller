package uk.gov.ida.cloudhsmtool;

import com.cavium.key.parameter.CaviumRSAKeyGenParameterSpec;
import picocli.CommandLine;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.concurrent.Callable;

@CommandLine.Command(
        name = "genrsa",
        description = "Generate non extractable private key in HSM"
)
public class GenRSA extends HSMCli implements Callable<Void> {

    @Override
    public Void call() throws Exception {

        KeyStore ks = getKeystore();
        String hsmKeyLabel = getHsmKeyLabel();
        KeyPair keyPair = null;
        if (!ks.containsAlias(hsmKeyLabel)) {
            keyPair = generateRSAKeyPair(DEFAULT_KEY_SIZE, hsmKeyLabel);
            ks.load(null, null);
        }

        PublicKey publicKey = keyPair.getPublic();
        if (!(publicKey instanceof PublicKey)) {
            throw new Exception("failed to fetch public key for " + hsmKeyLabel);
        }

        System.out.println(toPEMFormat("PUBLIC KEY", publicKey.getEncoded()));
        return null;
    }

    // Generate an RSA key pair.
    // The label passed will be appended with ":public" for the public key.
    private KeyPair generateRSAKeyPair(int keySizeInBits, String label) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        boolean isExtractable = false;
        boolean isPersistent = true;
        return generateRSAKeyPairWithParams(keySizeInBits, label, isExtractable, isPersistent);
    }

    private KeyPair generateRSAKeyPairWithParams(int keySizeInBits, String label, boolean isExtractable, boolean isPersistent) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("rsa", PROVIDER_NAME_CAVIUM);
        CaviumRSAKeyGenParameterSpec spec = new CaviumRSAKeyGenParameterSpec(keySizeInBits, RSA_PUBLIC_EXPONENT, label + LABEL_PUBLIC_SUFFIX, label, isExtractable, isPersistent);
        keyPairGen.initialize(spec);
        return keyPairGen.generateKeyPair();
    }

}
