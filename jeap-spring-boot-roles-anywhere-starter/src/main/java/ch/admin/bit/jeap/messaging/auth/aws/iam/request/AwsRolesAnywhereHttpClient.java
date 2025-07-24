package ch.admin.bit.jeap.messaging.auth.aws.iam.request;

import ch.admin.bit.jeap.messaging.auth.aws.iam.models.AwsRolesAnywhereSessionsResponse;
import ch.admin.bit.jeap.messaging.auth.aws.iam.models.X509CertificateChain;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.http.HttpExecuteRequest;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.utils.IoUtils;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;


@Slf4j
public class AwsRolesAnywhereHttpClient {

    private final SdkHttpClient sdkHttpClient;
    private final ObjectMapper objectMapper;
    private final AwsRolesAnywhereRequestFactory requestFactory;

    public AwsRolesAnywhereHttpClient(SdkHttpClient sdkHttpClient, ObjectMapper objectMapper, AwsRolesAnywhereRequestFactory requestFactory) {
        this.sdkHttpClient = sdkHttpClient;
        this.objectMapper = objectMapper;
        this.requestFactory = requestFactory;
    }

    public AwsRolesAnywhereSessionsResponse sendAndParse(
            Instant instant,
            String jsonBody,
            String host,
            X509CertificateChain certificateChain,
            String authHeader) {

        try {
            boolean includesChain = certificateChain.getIntermediateCACertificate() != null;
            SdkHttpFullRequest request = requestFactory.build(instant, host, certificateChain, authHeader, includesChain);
            ByteArrayInputStream requestBodyStream = new ByteArrayInputStream(jsonBody.getBytes(StandardCharsets.UTF_8));
            HttpExecuteRequest executeRequest = HttpExecuteRequest.builder()
                    .request(request)
                    .contentStreamProvider(() -> requestBodyStream)
                    .build();

            var response = sdkHttpClient.prepareRequest(executeRequest).call();

            if (response.responseBody().isPresent()) {
                var content = response.responseBody().get();
                var responseBody = IoUtils.toUtf8String(content);
                log.debug("Response Body: {}", responseBody);
                return objectMapper.readValue(responseBody, AwsRolesAnywhereSessionsResponse.class);
            } else {
                throw new RuntimeException("Empty response body from AWS Roles Anywhere");
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to send or parse AWS Roles Anywhere response", e);
        }
    }
}
