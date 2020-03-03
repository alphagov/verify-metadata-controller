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
import java.security.PublicKey;
import java.util.Iterator;
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
            System.out.println("Alias not found in keyStore, generating new RSA KeyPair");
            generateRSAKeyPair(DEFAULT_KEY_SIZE, hsmKeyLabel);
        }

        ks.load(null, null);

        System.out.println("Cavium keystore aliases:");

        Iterator<String> stringIterator = ks.aliases().asIterator();
        while (stringIterator.hasNext()) {
            String alias = stringIterator.next();
            System.out.println(alias);
            System.out.println("KeyStore contains alias: " + ks.containsAlias(alias));
            System.out.println("\\n");
        }

        try {
            com.cavium.key.CaviumKey publicCaviumKey = com.cavium.cfm2.Util.findFirstCaviumKey(hsmKeyLabel + LABEL_PUBLIC_SUFFIX);
            System.out.println("publicCaviumKey found! " + publicCaviumKey.getLabel());

        } catch (Exception e) {
            System.out.println("Public Cavium Key not found: " + e.getMessage());
        }


        System.out.println("Public label we're using: " + hsmKeyLabel + LABEL_PUBLIC_SUFFIX);

        try {
            boolean certificateEntry = ks.isCertificateEntry(hsmKeyLabel + LABEL_PUBLIC_SUFFIX);
            System.out.println("isCertificateEntry: " + certificateEntry);
        } catch (Exception e) {
            System.out.println("isCertificateEntry threw an error: " + e.getMessage());
        }

        try {
            boolean b = ks.containsAlias(hsmKeyLabel + LABEL_PUBLIC_SUFFIX);
            System.out.println("containsAlias: " + b);
        } catch (Exception e) {
            System.out.println("containsAlias threw an error: " + e.getMessage());
        }

        try {
            KeyStore.Entry entry = ks.getEntry(hsmKeyLabel + LABEL_PUBLIC_SUFFIX, null);
            System.out.println("entry: " + entry);
        } catch (Exception e) {
            System.out.println("entry threw an error: " + e.getMessage());
        }

        try {
            boolean keyEntry = ks.isKeyEntry(hsmKeyLabel + LABEL_PUBLIC_SUFFIX);
            System.out.println("isKeyEntry: " + keyEntry);
        } catch (Exception e) {
            System.out.println("isKeyEntry threw an error: " + e.getMessage());
        }


        Key privateKey = ks.getKey(hsmKeyLabel, null);
        if (!(privateKey instanceof PrivateKey)) {
            throw new Exception("failed to fetch PrivateKey for "+hsmKeyLabel);
        }

//        Key publicKey = ks.getKey(hsmKeyLabel + LABEL_PUBLIC_SUFFIX, null);
//        if (!(publicKey instanceof PublicKey)) {
//            System.out.println("String repr of public key: " + publicKey.toString());
//            System.out.println("Public key type: " + publicKey.getClass());
//            throw new Exception("failed to fetch PublicKey for "+hsmKeyLabel+"public");
//        }

        com.cavium.key.CaviumKey publicKey = com.cavium.cfm2.Util.findFirstCaviumKey(hsmKeyLabel + LABEL_PUBLIC_SUFFIX);



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
