package uk.gov.ida.cloudhsmtool;

import com.cavium.provider.CaviumProvider;
import picocli.CommandLine;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;

@CommandLine.Command(subcommands = {
	GenRSA.class,
	CreateSelfSignedCertificate.class,
	CreateChainedCertificate.class,
})
public class CloudHSMTool implements Callable<Void> {

	public static void main(String[] args) throws Exception {
		Provider caviumProvider = new CaviumProvider();
		Security.addProvider(caviumProvider);

		CommandLine.call(new CloudHSMTool(), args);
	}

	@Override
	public Void call() throws Exception {
		System.err.println("Please invoke a subcommand");
		CommandLine cmd = new CommandLine(new CloudHSMTool());
		cmd.usage(System.err);
		return null;
	}
}
