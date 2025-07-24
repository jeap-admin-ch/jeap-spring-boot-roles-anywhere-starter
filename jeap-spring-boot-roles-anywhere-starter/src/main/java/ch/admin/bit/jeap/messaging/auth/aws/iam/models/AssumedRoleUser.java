package ch.admin.bit.jeap.messaging.auth.aws.iam.models;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

@Getter
@Setter
@Accessors(chain = true)
public class AssumedRoleUser {

    private String arn;
    private String assumedRoleId;

}