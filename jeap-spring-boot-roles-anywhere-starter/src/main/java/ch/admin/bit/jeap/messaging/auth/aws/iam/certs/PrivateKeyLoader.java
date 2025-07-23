package ch.admin.bit.jeap.messaging.auth.aws.iam.certs;

import io.micrometer.common.util.StringUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@Slf4j
public class PrivateKeyLoader {

    public static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    public static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";

    private static PrivateKey privateKeyResolver(final byte[] key) throws InvalidKeySpecException, IOException, NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());

        var byteArrayInputStream = new ByteArrayInputStream(key);
        var pemParser = new PEMParser(new InputStreamReader(byteArrayInputStream));
        var inputPemObject = pemParser.readObject();

        PrivateKeyInfo privateKeyInfo;
        String originalFormat;

        if (inputPemObject instanceof PEMKeyPair keyPair) {
            originalFormat = "PKCS#1";
            privateKeyInfo = keyPair.getPrivateKeyInfo();
            log.debug("Private key Input format: PKCS#1 (Traditional format)");
        } else if (inputPemObject instanceof PrivateKeyInfo instancePrivateKeyInfo) {
            originalFormat = "PKCS#8";
            privateKeyInfo = instancePrivateKeyInfo;
            log.debug("Private key Input format: PKCS#8 (Modern format)");
        } else {
            throw new IllegalArgumentException("Unsupported key format: " + inputPemObject.getClass().getName() +
                    ". Supported formats: PKCS#1 (RSA/EC PRIVATE KEY) and PKCS#8 (PRIVATE KEY)");
        }

        // Extract algorithm and create key
        var encodedKey = privateKeyInfo.getEncoded();

        var keySpec = new PKCS8EncodedKeySpec(encodedKey);
        var keyFactory = KeyFactory.getInstance("RSA", "BC");
        var privateKey = keyFactory.generatePrivate(keySpec);

        log.info("Private key successfully loaded. Original format: {}, Private key algorithm: {}, internal format: {}", originalFormat, privateKey.getAlgorithm(), privateKey.getFormat());

        return privateKey;
    }

    public static PrivateKey extractPrivateKey(final String privateKey) {
        String normalizedKey = normalizePrivateKey(privateKey);
        var privateKeyBytes = Base64.getDecoder().decode(normalizedKey);
        try {
            return privateKeyResolver(privateKeyBytes);
        } catch (InvalidKeySpecException | IOException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    static String normalizePrivateKey(String keyInput) {
        if (StringUtils.isBlank(keyInput)) {
            throw new IllegalArgumentException("Private key input is empty or null");
        }

        boolean isPem = keyInput.contains(BEGIN_PRIVATE_KEY);
        if (isPem) {
            log.debug("Detected PEM format private key, converting to Base64 encoded string");
            String cleaned = keyInput.replaceAll("[ \\t]+", "")
                    .replace("-----BEGINPRIVATEKEY-----", BEGIN_PRIVATE_KEY)
                    .replace("-----ENDPRIVATEKEY-----", END_PRIVATE_KEY);
            String base64Encoded = Base64.getEncoder().encodeToString(cleaned.getBytes(StandardCharsets.UTF_8));
            log.debug("Normalized private key (Base64 of cleaned PEM): {}", base64Encoded);
            return base64Encoded;
        } else {
            log.debug("Assuming input is already Base64 encoded, removing whitespace");
            return keyInput.replaceAll("[ \\t]+", "");
        }
    }
}
