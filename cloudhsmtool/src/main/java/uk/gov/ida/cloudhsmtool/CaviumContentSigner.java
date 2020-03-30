package uk.gov.ida.cloudhsmtool;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;

import static uk.gov.ida.cloudhsmtool.CloudHSMWrapper.PROVIDER_NAME_CAVIUM;

public class CaviumContentSigner implements ContentSigner {

    private AlgorithmIdentifier algorithmIdentifier;
    private Signature sig;
    private ByteArrayOutputStream outputStream;

    CaviumContentSigner(PrivateKey privateKey, String sigAlgo) {
        this.algorithmIdentifier = new DefaultSignatureAlgorithmIdentifierFinder().find(sigAlgo);

        try {
            this.outputStream = new ByteArrayOutputStream();
            this.sig = Signature.getInstance(sigAlgo, PROVIDER_NAME_CAVIUM);
            this.sig.initSign(privateKey);
        } catch (GeneralSecurityException gse) {
            throw new IllegalArgumentException(gse.getMessage());
        }
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return this.algorithmIdentifier;
    }

    @Override
    public OutputStream getOutputStream() {
        return this.outputStream;
    }

    @Override
    public byte[] getSignature() {
        try {
            this.sig.update(outputStream.toByteArray());
            return this.sig.sign();
        } catch (GeneralSecurityException gse) {
            gse.printStackTrace();
            return null;
        }
    }
}
