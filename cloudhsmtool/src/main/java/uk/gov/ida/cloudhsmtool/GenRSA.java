package uk.gov.ida.cloudhsmtool;

import com.cavium.key.parameter.CaviumRSAKeyGenParameterSpec;
import picocli.CommandLine;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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
        System.out.println(toPEMFormat("PUBLIC KEY", publicKey.getEncoded()));
        return null;
    }

    // Generate an RSA key pair.
    // The label passed will be appended with ":public" for the public key.
    private void generateRSAKeyPair(int keySizeInBits, String label) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        boolean isExtractable = false;
        boolean isPersistent = true;
        generateRSAKeyPairWithParams(keySizeInBits, label, isExtractable, isPersistent);
    }

    private void generateRSAKeyPairWithParams(int keySizeInBits, String label, boolean isExtractable, boolean isPersistent) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("rsa", PROVIDER_NAME_CAVIUM);
        CaviumRSAKeyGenParameterSpec spec = new CaviumRSAKeyGenParameterSpec(keySizeInBits, RSA_PUBLIC_EXPONENT, label + LABEL_PUBLIC_SUFFIX, label, isExtractable, isPersistent);
        keyPairGen.initialize(spec);
        keyPairGen.generateKeyPair();
    }

}
