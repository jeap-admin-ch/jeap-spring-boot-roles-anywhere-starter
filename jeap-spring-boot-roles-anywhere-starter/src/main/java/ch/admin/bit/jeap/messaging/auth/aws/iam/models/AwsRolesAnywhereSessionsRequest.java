package ch.admin.bit.jeap.messaging.auth.aws.iam.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Getter;
import lombok.Builder;
import lombok.experimental.Accessors;

@Getter
@Builder
@Accessors(chain = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"roleArn", "profileArn", "trustAnchorArn", "sessionDuration"})
public class AwsRolesAnywhereSessionsRequest {

    private String roleArn;
    private String profileArn;
    private String trustAnchorArn;
    private Integer durationSeconds = 900;

    public static AwsRolesAnywhereSessionsRequest from(RolesAnywhereAuthContext context) {
        return AwsRolesAnywhereSessionsRequest.builder()
                .roleArn(context.getRoleArn())
                .profileArn(context.getProfileArn())
                .trustAnchorArn(context.getTrustAnchorArn())
                .durationSeconds(context.getDurationSeconds())
                .build();
    }
}
