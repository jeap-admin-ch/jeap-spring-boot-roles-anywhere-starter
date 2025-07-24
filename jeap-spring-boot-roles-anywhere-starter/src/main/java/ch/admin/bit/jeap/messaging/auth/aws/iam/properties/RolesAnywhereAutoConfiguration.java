package ch.admin.bit.jeap.messaging.auth.aws.iam.properties;

import ch.admin.bit.jeap.messaging.auth.aws.iam.AwsRolesAnywhereSessionOrchestrator;
import ch.admin.bit.jeap.messaging.auth.aws.iam.certs.CertLoader;
import ch.admin.bit.jeap.messaging.auth.aws.iam.certs.PrivateKeyLoader;
import ch.admin.bit.jeap.messaging.auth.aws.iam.util.IAMRolesAnywhereCredentialsProviderHolder;
import ch.admin.bit.jeap.messaging.auth.aws.iam.IAMRolesAnywhereSessionsCredentialsProvider;
import ch.admin.bit.jeap.messaging.auth.aws.iam.models.RolesAnywhereAuthContext;
import ch.admin.bit.jeap.messaging.auth.aws.iam.mapper.RolesAnywhereAuthContextMapper;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.common.util.StringUtils;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.kafka.KafkaAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;

@AutoConfiguration
@AutoConfigureBefore(KafkaAutoConfiguration.class)
@Configuration
@EnableConfigurationProperties(AwsRolesAnywhereProperties.class)
@ConditionalOnProperty(name = "jeap.aws.rolesanywhere.enabled", havingValue = "true")
public class RolesAnywhereAutoConfiguration {

    private final Environment environment;

    public RolesAnywhereAutoConfiguration(Environment environment) {
        this.environment = environment;
    }

    @Bean
    public AwsRolesAnywhereSessionOrchestrator awsRolesAnywhereSessionOrchestrator(
            AwsRolesAnywhereProperties props,
            ObjectMapper objectMapper,
            Environment environment
    ) {
        var mapper = new RolesAnywhereAuthContextMapper(objectMapper, new CertLoader(), new PrivateKeyLoader());

        RolesAnywhereAuthContext requesterDetails = mapper.map(
                props,
                environment.getProperty("spring.application.name", "default-session")
        );

        return new AwsRolesAnywhereSessionOrchestrator(
                requesterDetails,
                UrlConnectionHttpClient.builder().build(),
                objectMapper
        );
    }


    @Bean
    @Primary
    public AwsCredentialsProvider awsCredentialsProvider(
            AwsRolesAnywhereSessionOrchestrator orchestrator
    ) {
        try {
            IAMRolesAnywhereSessionsCredentialsProvider provider =
                    new IAMRolesAnywhereSessionsCredentialsProvider(orchestrator);

            IAMRolesAnywhereCredentialsProviderHolder.setProvider(provider);
            return provider;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create AwsCredentialsProvider", e);
        }
    }

}
