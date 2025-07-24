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

    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";

    public String normalizeCertificate(String certInput) {
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

    public X509Certificate extractCertificate(String base64EncodedCert) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            byte[] decodedCertificate = Base64.getDecoder().decode(base64EncodedCert);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decodedCertificate));
            log.debug("Certificate expires at {}", cert.getNotAfter());
            return cert;
        } catch (CertificateException e) {
            log.error("Error while extracting certificate, {}", e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public List<X509Certificate> extractCertificates(String base64EncodedCert) throws CertificateException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        var inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(base64EncodedCert));

        List<X509Certificate> certificates = new ArrayList<>();
        for (var cert : cf.generateCertificates(inputStream)) {
            certificates.add((X509Certificate) cert);
        }

        return certificates;
    }

    public boolean possibleChainOfCerts(String base64EncodedCert) {
        String rawCertFile = new String(Base64.getDecoder().decode(base64EncodedCert));
        int count = countOccurrencesOfBEGINCERT(rawCertFile);

        if (count == 1) {
            log.debug("Only one cert provided");
            return false;
        } else if (count > 1) {
            log.debug("Possible chain of certificates");
            return true;
        } else {
            log.error("Cert not provided correctly");
            throw new RuntimeException("Cert not provided correctly");
        }
    }

    public X509CertificateChain resolveCertificateChain(String base64EncodedCert) throws CertificateException, NoSuchProviderException {
        var x509CertificateChain = new X509CertificateChain();
        x509CertificateChain.setBase64EncodedCertificate(base64EncodedCert);

        if (possibleChainOfCerts(base64EncodedCert)) {
            var certs = extractCertificates(base64EncodedCert);
            for (var cert : certs) {
                if (isRootCA(cert)) {
                    log.debug("root CA expires at {}", cert.getNotAfter());
                    x509CertificateChain.setRootCACertificate(cert);
                } else if (isIntermediateCA(cert)) {
                    log.debug("intermediate CA expires at {}", cert.getNotAfter());
                    x509CertificateChain.setIntermediateCACertificate(cert);
                } else {
                    log.debug("leaf cert expires at {}", cert.getNotAfter());
                    x509CertificateChain.setLeafCertificate(cert);
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

    public boolean isIntermediateCA(X509Certificate cert) {
        return cert.getBasicConstraints() != -1 && cert.getKeyUsage() != null && cert.getKeyUsage()[5];
    }

    public boolean isRootCA(X509Certificate cert) {
        try {
            cert.verify(cert.getPublicKey());
            log.info("this is root CA");
            return true;
        } catch (InvalidKeyException e) {
            log.error("this is not root CA, invalid key");
        } catch (SignatureException e) {
            log.warn("the cert with name = {} is not Root CA signature issue", cert.getSubjectX500Principal().getName());
        } catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException e) {
            log.error("this is not Root CA, exception", e);
        }
        return false;
    }

    private int countOccurrencesOfBEGINCERT(String str) {
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
