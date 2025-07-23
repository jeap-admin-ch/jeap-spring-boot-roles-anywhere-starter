package ch.admin.bit.jeap.messaging.auth.aws.iam.request;

import ch.admin.bit.jeap.messaging.auth.aws.iam.certs.CertLoader;
import ch.admin.bit.jeap.messaging.auth.aws.iam.models.X509CertificateChain;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class AwsRolesAnywhereRequestFactoryTest {

    private static X509CertificateChain certificateChain;
    private static String hostFromContext;
    private static String authHeader;

    @BeforeAll
    static void setup() throws Exception {
        // Load certificate
        Path certPath = Path.of("src/test/resources/test_cert_chain.pem");
        String pemCertChain = Files.readString(certPath);
        String base64Encoded = new CertLoader().normalizeCertificate(pemCertChain);
        certificateChain = new CertLoader().resolveCertificateChain(base64Encoded);
        assertNotNull(certificateChain.getLeafCertificate(), "Leaf certificate is missing.");
        assertNotNull(certificateChain.getIntermediateCACertificate(), "Intermediate certificate is missing.");

        // Load context.json
        Path contextPath = Path.of("src/test/resources/test_context.json");
        String json = Files.readString(contextPath);
        JsonNode node = new ObjectMapper().readTree(json);

        // Simulate host and authHeader from context
        hostFromContext = "rolesanywhere." + node.path("context").asText("default") + ".example.com";
        authHeader = "Bearer dummy-token";
    }

    @Test
    void testBuildRequestWithRealCertificateChainAndContextJson() {
        AwsRolesAnywhereRequestFactory factory = new AwsRolesAnywhereRequestFactory();
        Instant instant = Instant.parse("2025-07-22T14:00:00Z");

        SdkHttpFullRequest request = factory.build(instant, hostFromContext, certificateChain, authHeader, true);

        assertEquals(SdkHttpMethod.POST, request.method());
        assertEquals("https://" + hostFromContext + "/sessions", request.getUri().toString());
        assertTrue(request.firstMatchingHeader("x-amz-x509").isPresent(), "Leaf certificate header missing");
        assertTrue(request.firstMatchingHeader("x-amz-x509-chain").isPresent(), "Intermediate certificate header missing");
        assertEquals(authHeader, request.firstMatchingHeader("Authorization").orElse(""));
    }
}
