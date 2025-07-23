package ch.admin.bit.jeap.messaging.auth.aws.iam.mapper;

import ch.admin.bit.jeap.messaging.auth.aws.iam.certs.CertLoader;
import ch.admin.bit.jeap.messaging.auth.aws.iam.certs.PrivateKeyLoader;
import ch.admin.bit.jeap.messaging.auth.aws.iam.models.RolesAnywhereAuthContext;
import ch.admin.bit.jeap.messaging.auth.aws.iam.properties.AwsRolesAnywhereProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class RolesAnywhereAuthContextMapperTest {

    private RolesAnywhereAuthContextMapper mapper;
    private AwsRolesAnywhereProperties props;
    private String pemCertChain;
    private String pemPrivateKey;

    @BeforeEach
    void setup() throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        CertLoader certLoader = new CertLoader();
        PrivateKeyLoader privateKeyLoader = new PrivateKeyLoader();

        mapper = new RolesAnywhereAuthContextMapper(objectMapper, certLoader, privateKeyLoader);

        pemCertChain = Files.readString(Path.of("src/test/resources/test_cert_chain.pem"));
        pemPrivateKey = Files.readString(Path.of("src/test/resources/test_private_key.pem"));

        props = new AwsRolesAnywhereProperties();
        props.setRegion("eu-central-1");
        props.setRoleArn("arn:aws:iam::123456789012:role/test-role");
        props.setProfileArn("arn:aws:rolesanywhere::profile/test");
        props.setTrustAnchorArn("arn:aws:rolesanywhere::trust-anchor/test");
        props.setEncodedX509Certificate(pemCertChain);
        props.setEncodedPrivateKey(pemPrivateKey);
    }

    @Test
    void testMap_withAllPropertiesSet_shouldSucceed() {
        RolesAnywhereAuthContext context = mapper.map(props, "test-session");

        assertNotNull(context);
        assertEquals("test-session", context.getRoleSessionName());
        assertNotNull(context.getCertificateChain());
        assertNotNull(context.getPrivateKey());
        assertEquals("eu-central-1", context.getRegion().id());
    }

    @Test
    void testMap_withCertAndKeyFromFiles_shouldSucceed() throws IOException {
        Path certPath = Files.writeString(Files.createTempFile("cert", ".pem"), pemCertChain);
        Path keyPath = Files.writeString(Files.createTempFile("key", ".pem"), pemPrivateKey);

        props.setEncodedX509Certificate(null);
        props.setEncodedPrivateKey(null);
        props.setCertificateFilePath(certPath.toString());
        props.setPrivateKeyFilePath(keyPath.toString());

        RolesAnywhereAuthContext context = mapper.map(props, "file-session");

        assertNotNull(context.getCertificateChain());
        assertNotNull(context.getPrivateKey());
    }

    @Test
    void testMap_withMissingRegion_shouldFail() {
        props.setRegion(null);
        Exception ex = assertThrows(IllegalArgumentException.class, () -> mapper.map(props, "fail"));
        assertTrue(ex.getMessage().contains("region"));
    }

    @Test
    void testMap_withMissingArnsAndNoJson_shouldFail() {
        props.setRoleArn(null);
        props.setProfileArn(null);
        props.setTrustAnchorArn(null);
        props.setArnJsonFilePath(null);

        Exception ex = assertThrows(IllegalArgumentException.class, () -> mapper.map(props, "fail"));
        assertTrue(ex.getMessage().contains("ARNs"));
    }

    @Test
    void testMap_withArnsFromJsonFile_shouldSucceed() throws IOException {
        Path jsonPath = Path.of("src/test/resources/test_context.json");

        props.setRoleArn(null);
        props.setProfileArn(null);
        props.setTrustAnchorArn(null);
        props.setArnJsonFilePath(jsonPath.toString());

        RolesAnywhereAuthContext context = mapper.map(props, "json-session");

        assertEquals("arn:aws:iam::123456789012:role/test-role", context.getRoleArn());
        assertEquals("arn:aws:rolesanywhere:eu-central-1:123456789012:profile/test-profile", context.getProfileArn());
        assertEquals("arn:aws:rolesanywhere:eu-central-1:123456789012:trust-anchor/test-anchor", context.getTrustAnchorArn());
    }
}
