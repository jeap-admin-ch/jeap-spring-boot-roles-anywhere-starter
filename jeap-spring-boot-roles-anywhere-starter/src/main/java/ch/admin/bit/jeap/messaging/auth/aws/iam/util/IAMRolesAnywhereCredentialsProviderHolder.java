package ch.admin.bit.jeap.messaging.auth.aws.iam.util;

import lombok.Setter;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;

public class IAMRolesAnywhereCredentialsProviderHolder {
    @Setter
    private static AwsCredentialsProvider provider;

    public static AwsCredentialsProvider getProvider() {
        if (provider == null) {
            throw new IllegalStateException("Provider not initialized");
        }
        return provider;
    }
}

