package ch.admin.bit.jeap.messaging.auth.aws.iam.request;

import ch.admin.bit.jeap.messaging.auth.aws.iam.models.X509CertificateChain;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.regions.Region;

import java.security.PrivateKey;
import java.time.Instant;

import static ch.admin.bit.jeap.messaging.auth.aws.iam.signing.AwsV4Signer.credentialScope;
import static ch.admin.bit.jeap.messaging.auth.aws.iam.signing.AwsV4Signer.resolveAwsAlgorithm;
import static software.amazon.awssdk.http.Header.CONTENT_TYPE;
import static software.amazon.awssdk.http.Header.HOST;
import static software.amazon.awssdk.http.auth.aws.signer.SignerConstant.X_AMZ_DATE;

@NoArgsConstructor
public class AwsRolesAnywhereHeaderFactory {

    private static final String SEMI_COLON = ";";
    private static final String CREDENTIAL_PREFIX = "Credential=";
    private static final String CREDENTIALS_DELIMITER = ", ";
    private static final String SIGNED_HEADERS_PREFIX = "SignedHeaders=";
    private static final String SIGNATURE_PREFIX = "Signature=";
    public static final String X_AMZ_X509 = "x-amz-x509";
    public static final String X_AMZ_X509_CHAIN = "x-amz-x509-chain";

    public String buildAuthHeader(
            Instant instant,
            X509CertificateChain certificateChain,
            Region region,
            PrivateKey privateKey,
            String signedContent) {

        boolean isChainPresent = certificateChain.getIntermediateCACertificate() != null;
        String signedHeaders = isChainPresent ? buildSignedHeadersWithChain() : buildSignedHeaders();
        String signingAlgorithm = resolveAwsAlgorithm(privateKey);

        String credentialPart = buildCredentialPart(certificateChain, region, instant);

        return signingAlgorithm + " " +
                CREDENTIAL_PREFIX + credentialPart + CREDENTIALS_DELIMITER +
                SIGNED_HEADERS_PREFIX + signedHeaders + CREDENTIALS_DELIMITER +
                SIGNATURE_PREFIX + signedContent;
    }

    private String buildCredentialPart(X509CertificateChain certificateChain, Region region, Instant instant) {
        var cert = certificateChain.getLeafCertificate();
        return cert.getSerialNumber() + "/" + credentialScope(instant, region);
    }

    public static String buildSignedHeaders() {
        return CONTENT_TYPE.toLowerCase() + SEMI_COLON + HOST.toLowerCase() + SEMI_COLON + X_AMZ_DATE.toLowerCase() + SEMI_COLON + X_AMZ_X509;
    }

    public static String buildSignedHeadersWithChain() {
        return buildSignedHeaders() + SEMI_COLON + X_AMZ_X509_CHAIN;
    }
}
