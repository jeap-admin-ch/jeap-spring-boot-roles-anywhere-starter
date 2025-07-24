package ch.admin.bit.jeap.messaging.auth.aws.iam;

import ch.admin.bit.jeap.messaging.auth.aws.iam.models.AwsRolesAnywhereSessionsRequest;
import ch.admin.bit.jeap.messaging.auth.aws.iam.models.AwsRolesAnywhereSessionsResponse;
import ch.admin.bit.jeap.messaging.auth.aws.iam.models.RolesAnywhereAuthContext;
import ch.admin.bit.jeap.messaging.auth.aws.iam.request.AwsRolesAnywhereHeaderFactory;
import ch.admin.bit.jeap.messaging.auth.aws.iam.request.AwsRolesAnywhereHttpClient;
import ch.admin.bit.jeap.messaging.auth.aws.iam.request.AwsRolesAnywhereRequestFactory;
import ch.admin.bit.jeap.messaging.auth.aws.iam.signing.AwsCanonicalRequestFactory;
import ch.admin.bit.jeap.messaging.auth.aws.iam.signing.AwsV4Signer;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpMethod;

import java.time.Instant;

@Slf4j
public class AwsRolesAnywhereSessionOrchestrator {

    private final RolesAnywhereAuthContext authContext;
    private final SdkHttpClient sdkHttpClient;
    private final ObjectMapper objectMapper;

    public AwsRolesAnywhereSessionOrchestrator(RolesAnywhereAuthContext authContext, SdkHttpClient sdkHttpClient, ObjectMapper objectMapper) {
        this.authContext = authContext;
        this.sdkHttpClient = sdkHttpClient;
        this.objectMapper = objectMapper;
    }

    public AwsRolesAnywhereSessionsResponse getIamRolesAnywhereSessions() {

        try {
            // Create the request JSON
            String requestJson = this.objectMapper.writeValueAsString(
                    AwsRolesAnywhereSessionsRequest.from(this.authContext));
            Instant instant = Instant.now();

            // Create the canonical request
            AwsCanonicalRequestFactory awsCanonicalRequestFactory = new AwsCanonicalRequestFactory();
            String canonicalRequest = awsCanonicalRequestFactory.buildCanonicalRequest(
                    instant,
                    this.authContext.getHost(),
                    SdkHttpMethod.POST.name(),
                    "/sessions",
                    requestJson,
                    this.authContext.getCertificateChain()
            );

            // Sign the request
            AwsV4Signer awsV4Signer = new AwsV4Signer();
            String signedContent = awsV4Signer.signRequest(
                    instant,
                    this.authContext.getRegion(),
                    canonicalRequest,
                    this.authContext.getPrivateKey()
            );

            // Build the auth header
            AwsRolesAnywhereHeaderFactory awsRolesAnywhereHeaderFactory = new AwsRolesAnywhereHeaderFactory();
            String authHeader = awsRolesAnywhereHeaderFactory.buildAuthHeader(
                    instant,
                    this.authContext.getCertificateChain(),
                    this.authContext.getRegion(),
                    this.authContext.getPrivateKey(),
                    signedContent);

            // Send request and parse response
            AwsRolesAnywhereHttpClient awsRolesAnywhereHttpClient = new AwsRolesAnywhereHttpClient(
                    this.sdkHttpClient,
                    this.objectMapper,
                    new AwsRolesAnywhereRequestFactory());
            return awsRolesAnywhereHttpClient.sendAndParse(
                    instant,
                    requestJson,
                    this.authContext.getHost(),
                    this.authContext.getCertificateChain(),
                    authHeader
            );

        } catch (Exception e) {
            throw new RuntimeException("Failed to get IAM Roles Anywhere session", e);
        }
    }
}
