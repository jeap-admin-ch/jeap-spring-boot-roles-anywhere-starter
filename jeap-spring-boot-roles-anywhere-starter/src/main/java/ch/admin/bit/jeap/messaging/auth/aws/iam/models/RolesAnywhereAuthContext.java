package ch.admin.bit.jeap.messaging.auth.aws.iam.models;

import lombok.Builder;
import lombok.Getter;
import software.amazon.awssdk.regions.Region;

import java.security.PrivateKey;

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
}

