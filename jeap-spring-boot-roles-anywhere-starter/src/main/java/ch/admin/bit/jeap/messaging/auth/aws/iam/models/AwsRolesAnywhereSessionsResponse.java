package ch.admin.bit.jeap.messaging.auth.aws.iam.models;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.util.List;

@Getter
@Setter
@Accessors(chain = true)
public class AwsRolesAnywhereSessionsResponse {
    private String message;

    private List<CredentialSet> credentialSet;

    private String subjectArn;
}