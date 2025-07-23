package ch.admin.bit.jeap.messaging.auth.aws.iam.certs;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class PrivateKeyLoaderTest {

    private static String pemPrivateKey;
    private static PrivateKeyLoader privateKeyLoader;

    @BeforeAll
    static void setup() throws IOException {
        Path keyPath = Path.of("src/test/resources/test_private_key.pem");
        pemPrivateKey = Files.readString(keyPath);
        assertNotNull(pemPrivateKey, "Private key could not be loaded.");
        privateKeyLoader = new PrivateKeyLoader();
    }

    @Test
    void testNormalizePrivateKey_withPEM() {
        String base64Encoded = privateKeyLoader.normalizePrivateKey(pemPrivateKey);
        assertNotNull(base64Encoded);
        assertDoesNotThrow(() -> Base64.getDecoder().decode(base64Encoded));
    }

    @Test
    void testExtractPrivateKey() {
        String normalized = privateKeyLoader.normalizePrivateKey(pemPrivateKey);
        PrivateKey key = privateKeyLoader.extractPrivateKey(normalized);
        assertNotNull(key, "Private key extraction failed.");
        assertEquals("RSA", key.getAlgorithm(), "Unexpected key algorithm.");
    }

    @Test
    void testNormalizePrivateKey_withBase64() {
        String normalized = privateKeyLoader.normalizePrivateKey("  " + Base64.getEncoder().encodeToString("dummy".getBytes()) + "  ");
        assertNotNull(normalized);
        assertFalse(normalized.contains(" "));
    }

    @Test
    void testNormalizePrivateKey_shouldThrowOnEmptyInput() {
        assertThrows(IllegalArgumentException.class, () -> privateKeyLoader.normalizePrivateKey("   "));
    }

    @Test
    void testExtractPrivateKey_shouldThrowOnInvalidKey() {
        String invalidBase64 = Base64.getEncoder().encodeToString("not-a-key".getBytes());
        assertThrows(RuntimeException.class, () -> privateKeyLoader.extractPrivateKey(invalidBase64));
    }
}
