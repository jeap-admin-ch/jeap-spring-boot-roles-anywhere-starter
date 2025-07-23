package ch.admin.bit.jeap.messaging.auth.aws.iam.util;

import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.utils.BinaryUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Slf4j
public class AwsHashUtils {
    private static final String SHA_256 = "SHA-256";

    public static byte[] hash(final String text) throws NoSuchAlgorithmException {
        var digest = MessageDigest.getInstance(SHA_256);
        return digest.digest(text.getBytes(StandardCharsets.UTF_8));
    }
    public static String hashContent(final String canonicalRequest) throws NoSuchAlgorithmException {
        return BinaryUtils.toHex(hash(canonicalRequest));
    }
}
