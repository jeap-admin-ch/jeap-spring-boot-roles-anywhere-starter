package ch.admin.bit.jeap.messaging.auth.aws.iam.models;

import ch.admin.bit.jeap.messaging.auth.aws.iam.properties.AwsRolesAnywhereProperties;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RolesAnywhereAuthContextValidationTest {

    private AwsRolesAnywhereProperties createValidProps() {
        AwsRolesAnywhereProperties props = new AwsRolesAnywhereProperties();
        props.setRegion("eu-central-1");
        props.setRoleArn("arn:aws:iam::123456789012:role/MyRole");
        props.setTrustAnchorArn("arn:aws:rolesanywhere:trust-anchor/abc123");
        props.setProfileArn("arn:aws:rolesanywhere:profile/xyz456");
        props.setEncodedX509Certificate("-----BEGIN CERTIFICATE-----\nMIIB...==\n-----END CERTIFICATE-----");
        props.setEncodedPrivateKey("-----BEGIN PRIVATE KEY-----\nMIIE...==\n-----END PRIVATE KEY-----");
        return props;
    }

    @Test
    void testMissingRegionThrowsException() {
        AwsRolesAnywhereProperties props = createValidProps();
        props.setRegion(null);

        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                RolesAnywhereAuthContext.from(props, "session"));
        assertTrue(ex.getMessage().contains("region"));
    }

    @Test
    void testMissingRoleArnThrowsException() {
        AwsRolesAnywhereProperties props = createValidProps();
        props.setRoleArn(null);

        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                RolesAnywhereAuthContext.from(props, "session"));
        assertTrue(ex.getMessage().contains("Role ARN"));
    }

    @Test
    void testMissingTrustAnchorArnThrowsException() {
        AwsRolesAnywhereProperties props = createValidProps();
        props.setTrustAnchorArn("");

        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                RolesAnywhereAuthContext.from(props, "session"));
        assertTrue(ex.getMessage().contains("Trust Anchor ARN"));
    }

    @Test
    void testMissingProfileArnThrowsException() {
        AwsRolesAnywhereProperties props = createValidProps();
        props.setProfileArn(" ");

        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                RolesAnywhereAuthContext.from(props, "session"));
        assertTrue(ex.getMessage().contains("Profile ARN"));
    }

    @Test
    void testMissingCertificateThrowsException() {
        AwsRolesAnywhereProperties props = createValidProps();
        props.setEncodedX509Certificate(null);

        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                RolesAnywhereAuthContext.from(props, "session"));
        assertTrue(ex.getMessage().contains("X.509 certificate"));
    }

    @Test
    void testMissingPrivateKeyThrowsException() {
        AwsRolesAnywhereProperties props = createValidProps();
        props.setEncodedPrivateKey("");

        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                RolesAnywhereAuthContext.from(props, "session"));
        assertTrue(ex.getMessage().contains("private key"));
    }
}
