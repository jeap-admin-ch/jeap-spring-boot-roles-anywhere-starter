package ch.admin.bit.jeap.messaging.auth.aws.iam.signing;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.regions.Region;

import java.security.*;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class AwsV4SignerTest {

    private AwsV4Signer signer;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        signer = new AwsV4Signer();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        keyPair = keyGen.generateKeyPair();
    }

    @Test
    void testResolveAndValidateAlgorithm_validRSA() {
        String algorithm = AwsV4Signer.resolveAndValidateAlgorithm(keyPair.getPrivate());
        assertEquals("RSA", algorithm);
    }

    @Test
    void testResolveAndValidateAlgorithm_invalidKey() {
        PrivateKey invalidKey = new PrivateKey() {
            @Override public String getAlgorithm() { return "DSA"; }
            @Override public String getFormat() { return null; }
            @Override public byte[] getEncoded() { return new byte[0]; }
        };

        assertThrows(IllegalArgumentException.class, () ->
                AwsV4Signer.resolveAndValidateAlgorithm(invalidKey));
    }

    @Test
    void testResolveAwsAlgorithm() {
        String result = AwsV4Signer.resolveAwsAlgorithm(keyPair.getPrivate());
        assertEquals("AWS4-X509-RSA-SHA256", result);
    }

    @Test
    void testCredentialScope() {
        Instant instant = Instant.parse("2025-07-22T12:00:00Z");
        Region region = Region.EU_CENTRAL_1;
        String scope = AwsV4Signer.credentialScope(instant, region);
        assertEquals("20250722/eu-central-1/rolesanywhere/aws4_request", scope);
    }

    @Test
    void testSignRequest() throws Exception {
        Instant instant = Instant.parse("2025-07-22T12:00:00Z");
        Region region = Region.EU_CENTRAL_1;
        String canonicalRequest = "GET\n/sessions\n\nhost:example.com\n\nhost\nabc123";

        String signature = signer.signRequest(instant, region, canonicalRequest, keyPair.getPrivate());

        assertNotNull(signature);
        assertTrue(signature.matches("[a-f0-9]+")); // Hex encoded
    }
}
