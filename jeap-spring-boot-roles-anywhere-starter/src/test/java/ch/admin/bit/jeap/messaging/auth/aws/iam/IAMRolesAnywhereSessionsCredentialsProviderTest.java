package ch.admin.bit.jeap.messaging.auth.aws.iam;

import ch.admin.bit.jeap.messaging.auth.aws.iam.models.AwsRolesAnywhereSessionsResponse;
import ch.admin.bit.jeap.messaging.auth.aws.iam.models.CredentialSet;
import ch.admin.bit.jeap.messaging.auth.aws.iam.models.Credentials;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class IAMRolesAnywhereSessionsCredentialsProviderTest {

    private AwsRolesAnywhereSessionOrchestrator orchestratorMock;
    private IAMRolesAnywhereSessionsCredentialsProvider provider;

    @BeforeEach
    void setUp() {
        orchestratorMock = mock(AwsRolesAnywhereSessionOrchestrator.class);

        Credentials credentials = new Credentials()
                .setAccessKeyId("AKIA_TEST")
                .setSecretAccessKey("SECRET_TEST")
                .setSessionToken("TOKEN_TEST")
                .setExpiration("2030-01-01T12:00:00Z");

        CredentialSet credentialSet = new CredentialSet()
                .setCredentials(credentials);

        AwsRolesAnywhereSessionsResponse response = new AwsRolesAnywhereSessionsResponse()
                .setCredentialSet(List.of(credentialSet));

        when(orchestratorMock.getIamRolesAnywhereSessions()).thenReturn(response);

        provider = new IAMRolesAnywhereSessionsCredentialsProvider(orchestratorMock);
    }

    @Test
    void testResolveCredentialsReturnsValidSessionCredentials() {
        AwsSessionCredentials sessionCredentials = (AwsSessionCredentials) provider.resolveCredentials();

        assertNotNull(sessionCredentials);
        assertEquals("AKIA_TEST", sessionCredentials.accessKeyId());
        assertEquals("SECRET_TEST", sessionCredentials.secretAccessKey());
        assertEquals("TOKEN_TEST", sessionCredentials.sessionToken());
        assertTrue(sessionCredentials.expirationTime().isPresent());
        assertEquals(Instant.parse("2030-01-01T12:00:00Z"), sessionCredentials.expirationTime().get());
    }

    @Test
    void testProviderName() {
        assertEquals("iam-rolesanywhere-provider", provider.providerName());
    }
}
