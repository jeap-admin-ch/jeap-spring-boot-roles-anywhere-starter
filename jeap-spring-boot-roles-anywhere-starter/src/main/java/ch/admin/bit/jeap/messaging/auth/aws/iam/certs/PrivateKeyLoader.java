package ch.admin.bit.jeap.messaging.auth.aws.iam.certs;

import io.micrometer.common.util.StringUtils;
import lombok.extern.slf4j.Slf4j;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@Slf4j
public class PrivateKeyLoader {

    public static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    public static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";

    public PrivateKey extractPrivateKey(final String normalizedKey) {
        byte[] privateKeyBytes = Base64.getDecoder().decode(normalizedKey);
        try {
            return privateKeyResolver(privateKeyBytes);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("Failed to extract private key", e);
        }
    }

    public String normalizePrivateKey(String keyInput) {
        if (StringUtils.isBlank(keyInput)) {
            throw new IllegalArgumentException("Private key input is empty or null");
        }

        boolean isPem = keyInput.contains(BEGIN_PRIVATE_KEY);
        if (isPem) {
            log.debug("Detected PEM format private key, converting to Base64 encoded string");
            return keyInput
                    .replace(BEGIN_PRIVATE_KEY, "")
                    .replace(END_PRIVATE_KEY, "")
                    .replaceAll("\\s+", "");
        } else {
            log.debug("Assuming input is already Base64 encoded, removing whitespace");
            return keyInput.replaceAll("\\s+", "");
        }
    }

    private PrivateKey privateKeyResolver(final byte[] keyBytes) throws InvalidKeySpecException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new InvalidKeySpecException("Could not generate private key", e);
        }
    }
}
