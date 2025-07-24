package ch.admin.bit.jeap.messaging.auth.aws.iam.mapper;

import ch.admin.bit.jeap.messaging.auth.aws.iam.certs.CertLoader;
import ch.admin.bit.jeap.messaging.auth.aws.iam.certs.PrivateKeyLoader;
import ch.admin.bit.jeap.messaging.auth.aws.iam.models.RolesAnywhereAuthContext;
import ch.admin.bit.jeap.messaging.auth.aws.iam.models.X509CertificateChain;
import ch.admin.bit.jeap.messaging.auth.aws.iam.properties.AwsRolesAnywhereProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.common.util.StringUtils;
import software.amazon.awssdk.regions.Region;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;

import static ch.admin.bit.jeap.messaging.auth.aws.iam.signing.AwsCanonicalRequestFactory.resolveHostBasedOnRegion;

public class RolesAnywhereAuthContextMapper {

    private final ObjectMapper objectMapper;
    private final CertLoader certLoader;
    private final PrivateKeyLoader privateKeyLoader;

    public RolesAnywhereAuthContextMapper(ObjectMapper objectMapper,
                                          CertLoader certLoader,
                                          PrivateKeyLoader privateKeyLoader) {
        this.objectMapper = objectMapper;
        this.certLoader = certLoader;
        this.privateKeyLoader = privateKeyLoader;
    }

    public RolesAnywhereAuthContext map(AwsRolesAnywhereProperties props, String roleSessionName) {
        try {
            applyDefaultPathsIfMissing(props);

            if (StringUtils.isNotBlank(props.getArnJsonFilePath()) &&
                    (StringUtils.isBlank(props.getRoleArn()) ||
                            StringUtils.isBlank(props.getTrustAnchorArn()) ||
                            StringUtils.isBlank(props.getProfileArn()))) {
                loadArnsFromJson(props);
            }

            validateProperties(props);

            String certContent = StringUtils.isNotBlank(props.getEncodedX509Certificate())
                    ? props.getEncodedX509Certificate()
                    : Files.readString(Path.of(props.getCertificateFilePath()), StandardCharsets.UTF_8);

            String normalizedCert = certLoader.normalizeCertificate(certContent);
            X509CertificateChain certificateChain = certLoader.resolveCertificateChain(normalizedCert);

            String keyContent = StringUtils.isNotBlank(props.getEncodedPrivateKey())
                    ? props.getEncodedPrivateKey()
                    : Files.readString(Path.of(props.getPrivateKeyFilePath()), StandardCharsets.UTF_8);

            String normalizedKey = privateKeyLoader.normalizePrivateKey(keyContent);
            PrivateKey privateKey = privateKeyLoader.extractPrivateKey(normalizedKey);

            Region region = Region.of(props.getRegion());

            return RolesAnywhereAuthContext.builder()
                    .durationSeconds(props.getSessionDuration())
                    .certificateChain(certificateChain)
                    .encodedX509Certificate(normalizedCert)
                    .privateKey(privateKey)
                    .region(region)
                    .host(resolveHostBasedOnRegion(region))
                    .roleArn(props.getRoleArn())
                    .profileArn(props.getProfileArn())
                    .trustAnchorArn(props.getTrustAnchorArn())
                    .roleSessionName(roleSessionName)
                    .build();

        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to map AwsRolesAnywhereProperties to RolesAnywhereAuthContext: " + e.getMessage(), e);
        }
    }

    private void loadArnsFromJson(AwsRolesAnywhereProperties props) throws IOException {
        String jsonContent = Files.readString(Path.of(props.getArnJsonFilePath()), StandardCharsets.UTF_8);
        JsonNode root = objectMapper.readTree(jsonContent);

        if (StringUtils.isBlank(props.getRoleArn())) {
            props.setRoleArn(root.path("roleArn").asText(null));
        }
        if (StringUtils.isBlank(props.getProfileArn())) {
            props.setProfileArn(root.path("profileArn").asText(null));
        }
        if (StringUtils.isBlank(props.getTrustAnchorArn())) {
            props.setTrustAnchorArn(root.path("trustAnchorArn").asText(null));
        }
    }

    private void validateProperties(AwsRolesAnywhereProperties props) {
        if (StringUtils.isBlank(props.getRegion())) {
            throw new IllegalArgumentException("AWS region must not be null or empty.");
        }

        boolean hasArns = StringUtils.isNotBlank(props.getRoleArn()) &&
                StringUtils.isNotBlank(props.getTrustAnchorArn()) &&
                StringUtils.isNotBlank(props.getProfileArn());

        if (!hasArns && StringUtils.isBlank(props.getArnJsonFilePath())) {
            throw new IllegalArgumentException("Either ARNs must be set directly or a JSON file path must be provided.");
        }

        boolean hasCert = StringUtils.isNotBlank(props.getEncodedX509Certificate()) ||
                StringUtils.isNotBlank(props.getCertificateFilePath());

        if (!hasCert) {
            throw new IllegalArgumentException("Either encoded X.509 certificate or certificate file path must be provided.");
        }

        boolean hasKey = StringUtils.isNotBlank(props.getEncodedPrivateKey()) ||
                StringUtils.isNotBlank(props.getPrivateKeyFilePath());

        if (!hasKey) {
            throw new IllegalArgumentException("Either encoded private key or private key file path must be provided.");
        }
    }

    private void applyDefaultPathsIfMissing(AwsRolesAnywhereProperties props) {
        String userHome = System.getProperty("user.home");

        if (StringUtils.isBlank(props.getCertificateFilePath())) {
            props.setCertificateFilePath(userHome + "/.aws/roles-anywhere/userCert.pem");
        }
        if (StringUtils.isBlank(props.getPrivateKeyFilePath())) {
            props.setPrivateKeyFilePath(userHome + "/.aws/roles-anywhere/userKey.pem");
        }
        if (StringUtils.isBlank(props.getArnJsonFilePath())) {
            props.setArnJsonFilePath(userHome + "/.aws/roles-anywhere/context.json");
        }
    }
}
