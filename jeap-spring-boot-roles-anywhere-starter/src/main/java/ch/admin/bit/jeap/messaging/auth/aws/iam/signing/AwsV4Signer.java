package ch.admin.bit.jeap.messaging.auth.aws.iam.signing;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.utils.BinaryUtils;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;

import static ch.admin.bit.jeap.messaging.auth.aws.iam.util.AwsDateUtils.getDate;
import static ch.admin.bit.jeap.messaging.auth.aws.iam.util.AwsDateUtils.getDateAndTime;
import static ch.admin.bit.jeap.messaging.auth.aws.iam.util.AwsHashUtils.hashContent;
import static software.amazon.awssdk.auth.signer.internal.SignerConstant.AWS4_TERMINATOR;

@Slf4j
@NoArgsConstructor
public class AwsV4Signer {

    public static final String AWS4_X509_PREFIX = "AWS4-X509-";
    public static final String AWS4_X509_SUFFIX = "-SHA256";
    public static final String ROLES_ANYWHERE_SERVICE = "rolesanywhere";
    public static final String SHA256_RSA = "SHA256withRSA";
    public static final String RSA = "RSA";

    public String signRequest(final Instant instant,
                              final Region region,
                              final String canonicalRequest,
                              final PrivateKey key) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        String algorithm = resolveAwsAlgorithm(key);
        String contentToSign = buildContentToSign(instant, region, algorithm, canonicalRequest);
        return sign(contentToSign, key);
    }

    private String buildContentToSign(final Instant instant,
                                      final Region region,
                                      final String algorithm,
                                      final String canonicalRequest) throws NoSuchAlgorithmException {
        return algorithm + '\n' +
                getDateAndTime(instant) + '\n' +
                credentialScope(instant, region) + '\n' +
                hashContent(canonicalRequest);
    }

    private String sign(final String contentToSign,
                        final PrivateKey key) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        var signature = Signature.getInstance(SHA256_RSA);
        signature.initSign(key);
        signature.update(contentToSign.getBytes(StandardCharsets.UTF_8));
        var signatureBytes = signature.sign();
        return BinaryUtils.toHex(signatureBytes);
    }

    public static String credentialScope(final Instant instant,
                                   final Region region) {
        var credentialScope = getDate(instant) + "/" + region.id() + "/" + ROLES_ANYWHERE_SERVICE + "/" + AWS4_TERMINATOR;
        log.debug("credentialScope: {}", credentialScope);
        return credentialScope;
    }

    public static String resolveAwsAlgorithm(final PrivateKey key) {
        return AWS4_X509_PREFIX + resolveAndValidateAlgorithm(key) + AWS4_X509_SUFFIX;
    }


    public static String resolveAndValidateAlgorithm(final PrivateKey key) {
        if (RSA.equals(key.getAlgorithm())) {
            return key.getAlgorithm();
        } else {
            throw new IllegalArgumentException("Key algorithm not recognized");
        }
    }
}
