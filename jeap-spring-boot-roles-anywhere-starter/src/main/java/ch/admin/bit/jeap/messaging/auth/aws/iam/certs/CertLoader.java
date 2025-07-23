package ch.admin.bit.jeap.messaging.auth.aws.iam.certs;

import ch.admin.bit.jeap.messaging.auth.aws.iam.models.X509CertificateChain;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import software.amazon.awssdk.utils.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Slf4j
public class CertLoader {

    private CertLoader() {
    }

    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";

    public static String normalizeCertificate(String certInput) {
        if (StringUtils.isBlank(certInput)) {
            throw new IllegalArgumentException("Certificate input is empty or null");
        }

        boolean isPem = certInput.contains(BEGIN_CERT);
        if (isPem) {
            log.debug("Detected PEM format certificate, converting to Base64 encoded string");
            String cleaned = certInput.replaceAll("[ \\t]+", "")
                    .replace("-----BEGINCERTIFICATE-----", BEGIN_CERT)
                    .replace("-----ENDCERTIFICATE-----", END_CERT);
            String base64Encoded = Base64.getEncoder().encodeToString(cleaned.getBytes(StandardCharsets.UTF_8));
            log.debug("Normalized certificate (Base64 of cleaned PEM): {}", base64Encoded);
            return base64Encoded;
        } else {
            log.debug("Assuming input is already Base64 encoded, removing whitespace");
            return certInput.replaceAll("[ \\t]+", "");
        }
    }

    public static X509Certificate extractCertificate(final String base64EncodedCert) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            byte[] decodedCertificate = Base64.getDecoder().decode(base64EncodedCert);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decodedCertificate));
            log.info("Certificate expires at {}", cert.getNotAfter());
            return cert;
        } catch (CertificateException e) {
            log.error("Error while extracting certificate, {}", e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public static List<X509Certificate> extractCertificates(final String base64EncodedCert) throws CertificateException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        var inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(base64EncodedCert));

        List<X509Certificate> certificates = new ArrayList<>();
        for (var cert : cf.generateCertificates(inputStream)) {
            certificates.add((X509Certificate) cert);
        }

        return certificates;
    }

    public static boolean possibleChainOfCerts(final String base64EncodedCert) {
        String rawCertFile = new String(Base64.getDecoder().decode(base64EncodedCert));
        if (countOccurrencesOfBEGINCERT(rawCertFile) == 1) {
            log.debug("Only one cert provided");
        } else if (countOccurrencesOfBEGINCERT(rawCertFile) > 1) {
            log.debug("Possible chain of certificates");
            return true;
        } else {
            log.error("Cert not provided correctly");
            throw new RuntimeException("Cert not provided correctly");
        }
        return false;
    }

    public static X509CertificateChain resolveCertificateChain(final String base64EncodedCert) throws CertificateException, NoSuchProviderException {
        var x509CertificateChain = new X509CertificateChain();
        x509CertificateChain.setBase64EncodedCertificate(base64EncodedCert);
        if (possibleChainOfCerts(base64EncodedCert)) {
            var certs = extractCertificates(base64EncodedCert);
            for (var cert : certs) {
                // root CA is different from intermediate CA
                if (isRootCA(cert)) {
                    log.info("root CA expires at, {}", cert.getNotAfter());
                    x509CertificateChain.setRootCACertificate(cert);
                } else if (ifX509CertIsCA(cert)) { // for intermediate CA
                    log.info("intermediate CA expires at, {}", cert.getNotAfter());
                    x509CertificateChain.setIntermediateCACertificate(cert);
                } else {
                    log.info("leaf cert expires at, {}", cert.getNotAfter());
                    x509CertificateChain.setLeafCertificate(cert); // leaf certificate
                }
            }
        } else {
            x509CertificateChain.setLeafCertificate(extractCertificate(base64EncodedCert));
        }
        return x509CertificateChain;
    }

    public static String convertToBase64PEMString(X509Certificate x509Cert) {
        Security.addProvider(new BouncyCastleProvider());
        var sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(x509Cert);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return Base64.getEncoder().encodeToString(sw.toString().getBytes(StandardCharsets.UTF_8));
    }

    public static boolean ifX509CertIsCA(final X509Certificate cert) {
        return cert.getBasicConstraints() != -1 && cert.getKeyUsage()[5];
    }

    public static boolean isRootCA(final X509Certificate cert) {
        try {
            cert.verify(cert.getPublicKey());
            log.info("this is root CA");
            return true;
        } catch (InvalidKeyException e) {
            log.error("this is not root CA, invalid key");
        } catch (SignatureException e) {
            log.warn("the cert with name = {} is not Root CA signature issue", cert.getSubjectX500Principal().getName());
        } catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException e) {
            log.error("this is not Root CA, exception", e.getCause());
        }
        return false;
    }

    private static int countOccurrencesOfBEGINCERT(final String str) {
        // if main string or subString is empty, makes no sense of occurrence, hence hard stopped with 0 occurrence
        if (StringUtils.isBlank(str) || StringUtils.isBlank(BEGIN_CERT)) {
            return 0;
        }

        int count = 0;
        int pos = 0;
        int idx;
        while ((idx = str.indexOf(BEGIN_CERT, pos)) != -1) {
            ++count;
            pos = idx + BEGIN_CERT.length();
        }
        return count;
    }

}