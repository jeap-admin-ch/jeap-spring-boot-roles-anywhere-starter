package ch.admin.bit.jeap.messaging.auth.aws.iam;

import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public class IAMRolesAnywhereSessionsCredentialsProvider extends RolesAnywhereCredentialsProvider {
    private final AwsRolesAnywhereSessionOrchestrator awsRolesAnywhereSessionOrchestrator;

    public IAMRolesAnywhereSessionsCredentialsProvider(
            AwsRolesAnywhereSessionOrchestrator awsRolesAnywhereSessionOrchestrator
    ) {
        super("iam-rolesanywhere-thread");
        this.awsRolesAnywhereSessionOrchestrator = awsRolesAnywhereSessionOrchestrator;
        prefetchCredentials();
    }

    @Override
    protected AwsSessionCredentials getUpdatedCredentials() {
        var response = awsRolesAnywhereSessionOrchestrator.getIamRolesAnywhereSessions();
        var credentials = response.getCredentialSet().getFirst().getCredentials();

        return AwsSessionCredentials.builder()
                .accessKeyId(credentials.getAccessKeyId())
                .secretAccessKey(credentials.getSecretAccessKey())
                .sessionToken(credentials.getSessionToken())
                .expirationTime(parseExpiration(credentials.getExpiration()))
                .build();
    }

    private Instant parseExpiration(String expiration) {
        return LocalDateTime.parse(expiration, DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'"))
                .atZone(ZoneId.of("UTC"))
                .toInstant();
    }

    @Override
    protected String providerName() {
        return "iam-rolesanywhere-provider";
    }
}

