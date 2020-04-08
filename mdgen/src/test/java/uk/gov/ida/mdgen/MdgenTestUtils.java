package uk.gov.ida.mdgen;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import uk.gov.ida.cloudhsmtool.CloudHSMWrapper;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

abstract class MdgenTestUtils {

    static final String PRIVATE_KEY_ALIAS = "label";

    BasicParserPool getParserPool() throws ComponentInitializationException {
        BasicParserPool parserPool = new BasicParserPool();
        parserPool.initialize();
        return parserPool;
    }

    MetadataGenerator createMetadataGenerator(CloudHSMWrapper cloudHSMWrapper) throws NoSuchFieldException, IllegalAccessException {
        MetadataGenerator metadataGenerator = new MetadataGenerator();
        Field field = MetadataGenerator.class.getDeclaredField("cloudHSMWrapper");
        field.setAccessible(true);
        field.set(metadataGenerator, cloudHSMWrapper);
        return metadataGenerator;
    }

    String createTempFile(String fileName) throws IOException {
        File temp = File.createTempFile(fileName, null);
        return temp.getAbsolutePath();
    }

    PrivateKey readPrivateKey(String filename, String algorithm) throws InvalidKeySpecException, IOException, NoSuchAlgorithmException {
        Path path = Paths.get(filename);
        String fileContent = Files.readString(path);
        fileContent = fileContent.replace("-----BEGIN PRIVATE KEY-----\n", "");
        fileContent = fileContent.replace("-----END PRIVATE KEY-----", "");
        fileContent = fileContent.replace("\n", "");

        PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(fileContent));
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePrivate(spec);
    }

    FileInputStream getFileFromPath(String filename) throws FileNotFoundException {
        return new FileInputStream(new File(filename));
    }
}
