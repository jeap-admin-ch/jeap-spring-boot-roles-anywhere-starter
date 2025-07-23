package ch.admin.bit.jeap.messaging.auth.aws.iam.certs;

import ch.admin.bit.jeap.messaging.auth.aws.iam.models.X509CertificateChain;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class CertLoaderTest {

    private static String pemCertChain;
    private static CertLoader certLoader;

    @BeforeAll
    static void setup() throws IOException {
        Path certPath = Path.of("src/test/resources/test_cert_chain.pem");
        pemCertChain = Files.readString(certPath);
        assertNotNull(pemCertChain, "Certificate chain could not be loaded.");
        certLoader = new CertLoader();
    }

    @Test
    void testNormalizeCertificate_withPEM() {
        String base64Encoded = certLoader.normalizeCertificate(pemCertChain);
        assertNotNull(base64Encoded);
        assertDoesNotThrow(() -> Base64.getDecoder().decode(base64Encoded));
    }

    @Test
    void testResolveCertificateChain() throws Exception {
        String base64Encoded = certLoader.normalizeCertificate(pemCertChain);
        X509CertificateChain chain = certLoader.resolveCertificateChain(base64Encoded);

        assertNotNull(chain.getLeafCertificate(), "Leaf certificate is missing.");
        assertNotNull(chain.getIntermediateCACertificate(), "Intermediate certificate is missing.");
        assertNotNull(chain.getRootCACertificate(), "Root certificate is missing.");
    }

    @Test
    void testExtractCertificate_directly() {
        String base64Encoded = certLoader.normalizeCertificate(pemCertChain);
        X509Certificate cert = certLoader.extractCertificate(base64Encoded);
        assertNotNull(cert);
    }

    @Test
    void testPossibleChainOfCerts() {
        String base64Encoded = certLoader.normalizeCertificate(pemCertChain);
        boolean isChain = certLoader.possibleChainOfCerts(base64Encoded);
        assertTrue(isChain, "Expected a certificate chain.");
    }
}
