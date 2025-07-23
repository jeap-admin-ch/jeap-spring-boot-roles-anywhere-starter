package ch.admin.bit.jeap.messaging.auth.aws.iam.models;

import ch.admin.bit.jeap.messaging.auth.aws.iam.properties.AwsRolesAnywhereProperties;
import lombok.Builder;
import lombok.Getter;
import software.amazon.awssdk.regions.Region;

import java.security.PrivateKey;

import static ch.admin.bit.jeap.messaging.auth.aws.iam.certs.CertLoader.normalizeCertificate;
import static ch.admin.bit.jeap.messaging.auth.aws.iam.certs.CertLoader.resolveCertificateChain;
import static ch.admin.bit.jeap.messaging.auth.aws.iam.certs.PrivateKeyLoader.extractPrivateKey;
import static ch.admin.bit.jeap.messaging.auth.aws.iam.signing.AwsCanonicalRequestFactory.resolveHostBasedOnRegion;

@Getter
@Builder
public class RolesAnywhereAuthContext {

    private X509CertificateChain certificateChain;
    private String roleArn;
    private String trustAnchorArn;
    private String profileArn;
    private Integer durationSeconds;
    private PrivateKey privateKey;
    private Region region;
    private String host;
    private String roleSessionName;
    private String encodedPrivateKey;
    private String encodedX509Certificate;

    public static RolesAnywhereAuthContext from(AwsRolesAnywhereProperties props, String roleSessionName) {
        validateProperties(props);

        try {
            Region region = Region.of(props.getRegion());
            String normalizedCert = normalizeCertificate(props.getEncodedX509Certificate());

            return RolesAnywhereAuthContext.builder()
                    .durationSeconds(props.getSessionDuration())
                    .certificateChain(resolveCertificateChain(normalizedCert))
                    .encodedX509Certificate(normalizedCert)
                    .privateKey(extractPrivateKey(props.getEncodedPrivateKey()))
                    .region(region)
                    .host(resolveHostBasedOnRegion(region))
                    .roleArn(props.getRoleArn())
                    .profileArn(props.getProfileArn())
                    .trustAnchorArn(props.getTrustAnchorArn())
                    .roleSessionName(roleSessionName)
                    .build();

        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to create AwsRolesAnyWhereRequesterDetails: " + e.getMessage(), e);
        }
    }

    private static void validateProperties(AwsRolesAnywhereProperties props) {
        if (isNullOrEmpty(props.getRegion())) {
            throw new IllegalArgumentException("AWS region must not be null or empty.");
        }
        if (isNullOrEmpty(props.getRoleArn())) {
            throw new IllegalArgumentException("Role ARN must not be null or empty.");
        }
        if (isNullOrEmpty(props.getTrustAnchorArn())) {
            throw new IllegalArgumentException("Trust Anchor ARN must not be null or empty.");
        }
        if (isNullOrEmpty(props.getProfileArn())) {
            throw new IllegalArgumentException("Profile ARN must not be null or empty.");
        }
        if (isNullOrEmpty(props.getEncodedX509Certificate())) {
            throw new IllegalArgumentException("Encoded X.509 certificate must not be null or empty.");
        }
        if (isNullOrEmpty(props.getEncodedPrivateKey())) {
            throw new IllegalArgumentException("Encoded private key must not be null or empty.");
        }
    }

    private static boolean isNullOrEmpty(String value) {
        return value == null || value.trim().isEmpty();
    }
}

