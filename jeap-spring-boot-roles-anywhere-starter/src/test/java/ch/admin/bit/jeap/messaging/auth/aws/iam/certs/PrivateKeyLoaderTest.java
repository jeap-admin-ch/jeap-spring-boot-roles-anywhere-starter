package ch.admin.bit.jeap.messaging.auth.aws.iam.certs;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class PrivateKeyLoaderTest {

    private static String pemPrivateKey;

    @BeforeAll
    static void setup() throws IOException {
        Path keyPath = Path.of("src/test/resources/test_private_key.pem");
        pemPrivateKey = Files.readString(keyPath);
        assertNotNull(pemPrivateKey, "Private key could not be loaded.");
    }

    @Test
    void testNormalizePrivateKey_withPEM() {
        String base64Encoded = PrivateKeyLoader.normalizePrivateKey(pemPrivateKey);
        assertNotNull(base64Encoded);
        assertDoesNotThrow(() -> Base64.getDecoder().decode(base64Encoded));
    }

    @Test
    void testExtractPrivateKey() {
        PrivateKey key = PrivateKeyLoader.extractPrivateKey(pemPrivateKey);
        assertNotNull(key, "Private key extraction failed.");
        assertEquals("RSA", key.getAlgorithm(), "Unexpected key algorithm.");
    }
}
