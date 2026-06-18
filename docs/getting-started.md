# Getting started

This page shows how to add the Roles Anywhere starter to a Spring Boot service so it can obtain
temporary AWS credentials from outside AWS. For the credential exchange itself see
[How it works](how-it-works.md); for the full property list see the
[Configuration reference](configuration.md).

## Prerequisites

AWS IAM Roles Anywhere must already be set up: a **trust anchor** referencing your CA, an IAM **role**
the service is allowed to assume, and an IAM Roles Anywhere **profile**. You also need the service's
X.509 **client certificate** and its **private key** (PKCS#8). The starter signs the request and
assumes the role on your behalf.

## 1. Add the dependency

```xml
<dependency>
    <groupId>ch.admin.bit.jeap</groupId>
    <artifactId>jeap-spring-boot-roles-anywhere-starter</artifactId>
</dependency>
```

The version is managed by the jEAP Spring Boot parent. When used together with jEAP Messaging, the
starter is supported from jEAP Messaging version `8.52.0`.

## 2. Configure the starter

The integration is off by default; set `jeap.aws.rolesanywhere.enabled=true` and provide the three
ARNs plus a certificate and key. The simplest, most portable setup uses the default PEM file paths
under `${user.home}/.aws/roles-anywhere/` (see [Certificates and keys](certificates-and-keys.md)):

```yaml
jeap:
  aws:
    rolesanywhere:
      enabled: true
      roleArn: "arn:aws:iam::123456789012:role/roles-anywhere/msk-access-user"
      trustAnchorArn: "arn:aws:rolesanywhere:eu-central-2:123456789012:trust-anchor/uuid"
      profileArn: "arn:aws:rolesanywhere:eu-central-2:123456789012:profile/uuid"
```

The certificate and key can also be supplied inline or from custom paths, and the ARNs can be loaded
from a JSON file — see the [Configuration reference](configuration.md).

## 3. Use the credentials

When enabled, the starter registers a `@Primary`
`software.amazon.awssdk.auth.credentials.AwsCredentialsProvider` bean. AWS SDK v2 clients pick it up
automatically, so you can just inject and build a client:

```java
@Component
@RequiredArgsConstructor
class S3Access {
    private final AwsCredentialsProvider awsCredentialsProvider;

    S3Client client() {
        return S3Client.builder()
                .region(Region.EU_CENTRAL_2)
                .credentialsProvider(awsCredentialsProvider)
                .build();
    }
}
```

For Kafka MSK IAM authentication via jEAP Messaging the wiring is automatic — see
[Messaging integration](messaging-integration.md).

## Related

- [Configuration reference](configuration.md)
- [How it works](how-it-works.md)
- [Certificates and keys](certificates-and-keys.md)
- [Messaging integration](messaging-integration.md)
