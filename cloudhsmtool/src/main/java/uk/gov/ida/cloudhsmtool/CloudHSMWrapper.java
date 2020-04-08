package uk.gov.ida.cloudhsmtool;

import com.cavium.cfm2.CFM2Exception;
import com.cavium.key.CaviumRSAPrivateKey;
import org.apache.xml.security.algorithms.JCEMapper;
import org.bouncycastle.operator.ContentSigner;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;

public class CloudHSMWrapper {

    static final String PUBLIC_KEY_SUFFIX = ":public";
    static final String PROVIDER_NAME_CAVIUM = "Cavium";
    static final String KEY_GEN_ALGORITHM = "EC";
    static final String SIGNING_ALGO_SHA256_RSA = "SHA256withRSA";
    static final String SIGNING_ALGO_SHA384_WITH_ECDSA = "SHA384withECDSA";

    public boolean containsAlias(String label) throws GeneralSecurityException, IOException {
        return getKeystore().containsAlias(label);
    }

    public PrivateKey getPrivateKey(String label) throws GeneralSecurityException, IOException {
        Key privateKey = getKeystore().getKey(label, null);
        if (!(privateKey instanceof PrivateKey)) {
            throw new IllegalStateException(String.format("failed to fetch PrivateKey for %s", label));
        }
        return (PrivateKey) privateKey;
    }

    public PublicKey getPublicKey(String label) throws CFM2Exception {
        String publicKeyLabel = String.format("%s%s", label, PUBLIC_KEY_SUFFIX);
        com.cavium.key.CaviumKey publicKey = com.cavium.cfm2.Util.findFirstCaviumKey(publicKeyLabel);
        if (!(publicKey instanceof PublicKey)) {
            throw new IllegalStateException(String.format("failed to fetch PublicKey for %s", publicKeyLabel));
        }
        return (PublicKey) publicKey;
    }

    public KeyPair getKeyPair(String label) throws GeneralSecurityException, IOException, CFM2Exception {
        PublicKey publicKey = getPublicKey(label);
        PrivateKey privateKey = getPrivateKey(label);
        return new KeyPair(publicKey, privateKey);
    }

    public KeyPairGenerator getKeyPairGenerator() throws NoSuchProviderException, NoSuchAlgorithmException {
        return KeyPairGenerator.getInstance(KEY_GEN_ALGORITHM, PROVIDER_NAME_CAVIUM);
    }

    public ContentSigner getContentSigner(PrivateKey privateKey) {
        String sigAlgo = SIGNING_ALGO_SHA384_WITH_ECDSA;
        // there may be some RSA keys in HSM
        if (privateKey instanceof CaviumRSAPrivateKey) {
            sigAlgo = SIGNING_ALGO_SHA256_RSA;
        }
        return new CaviumContentSigner(privateKey, sigAlgo);
    }

    public void setSecurityProvider() throws InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException {
        Provider caviumProvider = (Provider) ClassLoader.getSystemClassLoader()
                .loadClass("com.cavium.provider.CaviumProvider")
                .getConstructor()
                .newInstance();
        Security.addProvider(caviumProvider);
        JCEMapper.setProviderId("Cavium");
    }

    private KeyStore getKeystore() throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(PROVIDER_NAME_CAVIUM);
        keyStore.load(null, null);
        return keyStore;
    }
}
