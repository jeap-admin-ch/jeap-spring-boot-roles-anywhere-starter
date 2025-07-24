package ch.admin.bit.jeap.messaging.auth.aws.iam.signing;

import ch.admin.bit.jeap.messaging.auth.aws.iam.certs.CertLoader;
import ch.admin.bit.jeap.messaging.auth.aws.iam.models.X509CertificateChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import software.amazon.awssdk.regions.Region;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.SortedMap;

import static ch.admin.bit.jeap.messaging.auth.aws.iam.certs.CertLoader.convertToBase64PEMString;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AwsCanonicalRequestFactoryTest {

    private AwsCanonicalRequestFactory factory;

    @BeforeEach
    void setUp() {
        factory = new AwsCanonicalRequestFactory();
    }

    @Test
    void testResolveHostBasedOnRegion() {
        Region region = Region.US_EAST_1;
        String host = AwsCanonicalRequestFactory.resolveHostBasedOnRegion(region);
        assertNotNull(host);
        assertTrue(host.contains("rolesanywhere"));
    }

    @Test
    void testCanonicalHeadersWithoutChain() {
        String host = "example.amazonaws.com";
        String contentType = "application/json";
        String date = "20250722T120000Z";
        String cert = "dummyCert";

        SortedMap<String, String> headers = AwsCanonicalRequestFactory.canonicalHeaders(host, contentType, date, cert);
        assertEquals(4, headers.size());
        assertEquals(contentType, headers.get("content-type"));
        assertEquals(host, headers.get("host"));
        assertEquals(date, headers.get("x-amz-date"));
        assertEquals(cert, headers.get("x-amz-x509"));
    }

    @Test
    void testBuildCanonicalHeadersWithoutChain() {
        String result = AwsCanonicalRequestFactory.buildCanonicalHeaders("host", "application/json", "date", "cert");
        assertTrue(result.contains("host:host"));
        assertTrue(result.contains("content-type:application/json"));
        assertTrue(result.contains("x-amz-date:date"));
        assertTrue(result.contains("x-amz-x509:cert"));
    }

    @Test
    void testBuildCanonicalHeadersWithChain() {
        String result = AwsCanonicalRequestFactory.buildCanonicalHeaders("host", "application/json", "date", "cert", "chainCert");
        assertTrue(result.contains("x-amz-x509-chain:chainCert"));
    }

    @Test
    void testBuildCanonicalRequestWithoutChain() throws Exception {
        X509CertificateChain certChain = mock(X509CertificateChain.class);
        when(certChain.getIntermediateCACertificate()).thenReturn(null);
        when(certChain.getBase64EncodedCertificate()).thenReturn("base64Cert");

        String result = factory.buildCanonicalRequest(
                Instant.parse("2025-07-22T12:00:00Z"),
                "host.amazonaws.com",
                "POST",
                "/sessions",
                "{\"key\":\"value\"}",
                certChain
        );

        assertNotNull(result);
        assertTrue(result.contains("POST"));
        assertTrue(result.contains("/sessions"));
        assertTrue(result.contains("base64Cert"));
    }


    @Test
    void testBuildCanonicalRequestWithChain() throws Exception {
        X509CertificateChain certChain = mock(X509CertificateChain.class);
        X509Certificate leafCert = mock(X509Certificate.class);
        X509Certificate intermediateCert = mock(X509Certificate.class);

        when(certChain.getIntermediateCACertificate()).thenReturn(intermediateCert);
        when(certChain.getLeafCertificate()).thenReturn(leafCert);

        try (MockedStatic<CertLoader> mocked = mockStatic(CertLoader.class)) {
            mocked.when(() -> convertToBase64PEMString(leafCert)).thenReturn("mockedLeafCert");
            mocked.when(() -> convertToBase64PEMString(intermediateCert)).thenReturn("mockedIntermediateCert");

            String result = factory.buildCanonicalRequest(
                    Instant.parse("2025-07-22T12:00:00Z"),
                    "host.amazonaws.com",
                    "POST",
                    "/sessions",
                    "{\"key\":\"value\"}",
                    certChain
            );

            assertNotNull(result);
            assertTrue(result.contains("mockedLeafCert"));
            assertTrue(result.contains("mockedIntermediateCert"));
            assertTrue(result.contains("POST"));
            assertTrue(result.contains("/sessions"));
        }
    }
}
