package ch.admin.bit.jeap.messaging.auth.aws.iam.request;

import ch.admin.bit.jeap.messaging.auth.aws.iam.models.X509CertificateChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.regions.Region;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AwsRolesAnywhereHeaderFactoryTest {

    private AwsRolesAnywhereHeaderFactory factory;

    @BeforeEach
    void setUp() {
        factory = new AwsRolesAnywhereHeaderFactory();
    }

    @Test
    void testBuildSignedHeaders() {
        String headers = AwsRolesAnywhereHeaderFactory.buildSignedHeaders();
        assertEquals("content-type;host;x-amz-date;x-amz-x509", headers);
    }

    @Test
    void testBuildSignedHeadersWithChain() {
        String headers = AwsRolesAnywhereHeaderFactory.buildSignedHeadersWithChain();
        assertEquals("content-type;host;x-amz-date;x-amz-x509;x-amz-x509-chain", headers);
    }

    @Test
    void testBuildAuthHeader_withoutChain() {
        X509CertificateChain certChain = mock(X509CertificateChain.class);
        X509Certificate leafCert = mock(X509Certificate.class);
        PrivateKey privateKey = mock(PrivateKey.class);

        when(certChain.getIntermediateCACertificate()).thenReturn(null);
        when(certChain.getLeafCertificate()).thenReturn(leafCert);
        when(leafCert.getSerialNumber()).thenReturn(new BigInteger("123456789"));
        when(privateKey.getAlgorithm()).thenReturn("RSA");

        String result = factory.buildAuthHeader(
                Instant.parse("2025-07-22T12:00:00Z"),
                certChain,
                Region.EU_CENTRAL_1,
                privateKey,
                "deadbeef"
        );

        assertNotNull(result);
        assertTrue(result.contains("AWS4-X509-RSA-SHA256"));
        assertTrue(result.contains("Credential=123456789/20250722/eu-central-1/rolesanywhere/aws4_request"));
        assertTrue(result.contains("SignedHeaders=content-type;host;x-amz-date;x-amz-x509"));
        assertTrue(result.contains("Signature=deadbeef"));
    }

    @Test
    void testBuildAuthHeader_withChain() {
        X509CertificateChain certChain = mock(X509CertificateChain.class);
        X509Certificate leafCert = mock(X509Certificate.class);
        X509Certificate intermediateCert = mock(X509Certificate.class);
        PrivateKey privateKey = mock(PrivateKey.class);

        when(certChain.getIntermediateCACertificate()).thenReturn(intermediateCert);
        when(certChain.getLeafCertificate()).thenReturn(leafCert);
        when(leafCert.getSerialNumber()).thenReturn(new BigInteger("987654321"));
        when(privateKey.getAlgorithm()).thenReturn("RSA");

        String result = factory.buildAuthHeader(
                Instant.parse("2025-07-22T12:00:00Z"),
                certChain,
                Region.EU_WEST_1,
                privateKey,
                "cafebabe"
        );

        assertNotNull(result);
        assertTrue(result.contains("AWS4-X509-RSA-SHA256"));
        assertTrue(result.contains("Credential=987654321/20250722/eu-west-1/rolesanywhere/aws4_request"));
        assertTrue(result.contains("SignedHeaders=content-type;host;x-amz-date;x-amz-x509;x-amz-x509-chain"));
        assertTrue(result.contains("Signature=cafebabe"));
    }
}
