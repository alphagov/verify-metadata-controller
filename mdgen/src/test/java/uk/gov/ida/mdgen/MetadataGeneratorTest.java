package uk.gov.ida.mdgen;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.opensaml.core.config.InitializationException;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static org.assertj.core.api.Assertions.assertThat;

public class MetadataGeneratorTest {

    private PrintStream realSystemOut;
    private final ByteArrayOutputStream captureSystemOut = new ByteArrayOutputStream();

    @Before
    public void setUpStreams() {
        realSystemOut = System.out;
        System.setOut(new PrintStream(captureSystemOut));
    }

    @After
    public void revertStreams() {
        System.setOut(realSystemOut);
    }

    //@Test
    public void shouldSignAndInsertCertsForTheProxyNodeMetadata() throws InitializationException {

        // "test/cert.rsa.pem" "test/key.rsa.pem" "rsa"

        MetadataGenerator.main(new String[] {
                "proxy",
                "test/proxy.yml",
                "test/cert.rsa.pem",
                "--algorithm rsa",
                "--credential file",
                "--key-file test/key.rsa.pem",
                "--key-pass 1234",
                //"--output temporary.output.file"
        });

        assertThat(captureSystemOut.toString().length()).isGreaterThan(0);


    }

}