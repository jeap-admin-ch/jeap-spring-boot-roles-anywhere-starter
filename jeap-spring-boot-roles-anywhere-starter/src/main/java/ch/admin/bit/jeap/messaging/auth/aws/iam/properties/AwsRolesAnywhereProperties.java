package ch.admin.bit.jeap.messaging.auth.aws.iam.properties;


import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "jeap.aws.rolesanywhere")
public class AwsRolesAnywhereProperties {
    private String region = "eu-central-2";
    private String roleArn;
    private String profileArn;
    private String trustAnchorArn;
    private final Integer sessionDuration = 3600;
    private String encodedX509Certificate;
    private String encodedPrivateKey;
    private String certificateFilePath;
    private String privateKeyFilePath;
    private String arnJsonFilePath;

}
