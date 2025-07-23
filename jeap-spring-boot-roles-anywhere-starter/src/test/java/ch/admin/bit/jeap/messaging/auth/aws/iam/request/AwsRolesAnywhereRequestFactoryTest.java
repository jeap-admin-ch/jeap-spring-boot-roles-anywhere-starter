package ch.admin.bit.jeap.messaging.auth.aws.iam.request;

import ch.admin.bit.jeap.messaging.auth.aws.iam.certs.CertLoader;
import ch.admin.bit.jeap.messaging.auth.aws.iam.models.X509CertificateChain;
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

    @BeforeAll
    static void setup() throws Exception {
        Path certPath = Path.of("src/test/resources/test_cert_chain.pem");
        String pemCertChain = Files.readString(certPath);
        String base64Encoded = CertLoader.normalizeCertificate(pemCertChain);
        certificateChain = CertLoader.resolveCertificateChain(base64Encoded);
        assertNotNull(certificateChain.getLeafCertificate(), "Leaf certificate is missing.");
        assertNotNull(certificateChain.getIntermediateCACertificate(), "Intermediate certificate is missing.");
    }

    @Test
    void testBuildRequestWithRealCertificateChain() {
        // Arrange
        AwsRolesAnywhereRequestFactory factory = new AwsRolesAnywhereRequestFactory();
        Instant instant = Instant.parse("2025-07-22T14:00:00Z");
        String host = "example.com";
        String authHeader = "auth-header";

        // Act
        SdkHttpFullRequest request = factory.build(instant, host, certificateChain, authHeader, true);

        // Assert
        assertEquals(SdkHttpMethod.POST, request.method());
        assertEquals("https://example.com/sessions", request.getUri().toString());
        assertTrue(request.firstMatchingHeader("x-amz-x509").isPresent(), "Leaf certificate header missing");
        assertTrue(request.firstMatchingHeader("x-amz-x509-chain").isPresent(), "Intermediate certificate header missing");
        assertEquals(authHeader, request.firstMatchingHeader("Authorization").orElse(""));
    }
}
