package ch.admin.bit.jeap.messaging.auth.aws.iam.request;

import ch.admin.bit.jeap.messaging.auth.aws.iam.models.X509CertificateChain;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;

import java.time.Instant;

import static ch.admin.bit.jeap.messaging.auth.aws.iam.certs.CertLoader.convertToBase64PEMString;
import static ch.admin.bit.jeap.messaging.auth.aws.iam.util.AwsDateUtils.getDateAndTime;
import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;
import static software.amazon.awssdk.http.auth.aws.signer.SignerConstant.AUTHORIZATION;
import static software.amazon.awssdk.http.Header.CONTENT_TYPE;

@Slf4j
@NoArgsConstructor
public class AwsRolesAnywhereRequestFactory {

    public SdkHttpFullRequest build(
            Instant instant,
            String host,
            X509CertificateChain certificateChain,
            String authHeader,
            boolean includeChain) {

        SdkHttpFullRequest.Builder builder = (SdkHttpFullRequest.Builder) SdkHttpFullRequest.builder()
                .uri("https://" + host + "/sessions")
                .method(SdkHttpMethod.POST)
                .putHeader(CONTENT_TYPE.toLowerCase(), APPLICATION_JSON_VALUE)
                .putHeader("x-amz-x509", convertToBase64PEMString(certificateChain.getLeafCertificate()))
                .putHeader("x-amz-date", getDateAndTime(instant))
                .putHeader(AUTHORIZATION, authHeader);

        if (includeChain) {
            builder.putHeader("x-amz-x509-chain", convertToBase64PEMString(certificateChain.getIntermediateCACertificate()));
        }

        return builder.build();
    }
}


