package uk.gov.ida.cloudhsmtool;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import picocli.CommandLine;

import java.io.IOException;
import java.io.StringWriter;

abstract class HSMCli {

    @CommandLine.Parameters(arity = "1", description = "private key alias")
    protected String hsmKeyLabel;

    protected CloudHSMWrapper cloudHSMWrapper = new CloudHSMWrapper();

    String getHsmKeyLabel() {
        return hsmKeyLabel;
    }

    String toPEMFormat(String header, byte[] encoded) throws IOException {
        StringWriter buf = new StringWriter();
        PemWriter pemWriter = new PemWriter(buf);
        pemWriter.writeObject(new PemObject(header, encoded));
        pemWriter.close();
        return buf.toString();
    }
}
