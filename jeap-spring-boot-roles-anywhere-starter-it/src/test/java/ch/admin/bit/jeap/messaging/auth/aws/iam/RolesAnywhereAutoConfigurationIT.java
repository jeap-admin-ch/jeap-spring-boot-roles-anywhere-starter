package ch.admin.bit.jeap.messaging.auth.aws.iam;

import ch.admin.bit.jeap.messaging.auth.aws.iam.models.AwsRolesAnywhereSessionsResponse;
import ch.admin.bit.jeap.messaging.auth.aws.iam.models.CredentialSet;
import ch.admin.bit.jeap.messaging.auth.aws.iam.models.Credentials;
import ch.admin.bit.jeap.messaging.auth.aws.iam.properties.RolesAnywhereAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@SpringBootTest(classes = {
        TestApp.class,
        RolesAnywhereAutoConfiguration.class,
        RolesAnywhereAutoConfigurationIT.MockConfig.class
})
@TestPropertySource(properties = {
        "spring.main.allow-bean-definition-overriding=true",
        "jeap.aws.rolesanywhere.enabled=true",
})
@DirtiesContext
class RolesAnywhereAutoConfigurationIT {

    public static final String MOCK_ACCESS_KEY = "mockAccessKey";
    public static final String MOCK_SECRET_KEY = "mockSecretKey";
    public static final String EXPIRATION = "2025-12-31T23:59:59Z";

    @Autowired
    private ApplicationContext context;

    @Autowired
    private AwsCredentialsProvider awsCredentialsProvider;


    @TestConfiguration
    static class MockConfig {

        @Bean
        public AwsRolesAnywhereSessionOrchestrator awsRolesAnywhereSessionOrchestrator() {
            AwsRolesAnywhereSessionOrchestrator mock = Mockito.mock(AwsRolesAnywhereSessionOrchestrator.class);

            var credentials = new Credentials();
            credentials.setAccessKeyId(MOCK_ACCESS_KEY);
            credentials.setSecretAccessKey(MOCK_SECRET_KEY);
            credentials.setSessionToken("mockSessionToken");
            credentials.setExpiration(EXPIRATION);

            var credentialSet = new CredentialSet();
            credentialSet.setCredentials(credentials);

            var response = new AwsRolesAnywhereSessionsResponse();
            response.setCredentialSet(List.of(credentialSet));

            when(mock.getIamRolesAnywhereSessions()).thenReturn(response);

            return mock;
        }
    }

    @Test
    void autoConfigurationIsActive() {
        assertThat(context.containsBean("awsCredentialsProvider")).isTrue();
    }

    @Test
    void awsCredentialsProviderIsCorrectlyConfigured() {
        assertThat(awsCredentialsProvider).isInstanceOf(IAMRolesAnywhereSessionsCredentialsProvider.class);
    }

    @Test
    void awsCredentialsProviderReturnsMockedCredentials() {
        AwsCredentials credentials = awsCredentialsProvider.resolveCredentials();
        assertThat(credentials.accessKeyId()).isEqualTo("mockAccessKey");
        assertThat(credentials.secretAccessKey()).isEqualTo("mockSecretKey");
        assertThat(credentials.expirationTime()).isEqualTo(Optional.of(Instant.parse(EXPIRATION)));
    }
}
