package uk.gov.ida.cloudhsmtool;

import com.cavium.provider.CaviumProvider;
import picocli.CommandLine;

import java.security.Provider;
import java.security.Security;
import java.util.concurrent.Callable;

@CommandLine.Command(subcommands = {
	GenKeyPair.class,
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
	public Void call() {
		System.err.println("Please invoke a subcommand");
		CommandLine cmd = new CommandLine(new CloudHSMTool());
		cmd.usage(System.err);
		return null;
	}
}
