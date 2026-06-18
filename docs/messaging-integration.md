# Messaging integration

The primary use case for this starter is letting a jEAP service running outside AWS connect to a
managed Kafka cluster (AWS MSK) that uses **IAM authentication**, from an on-prem VM or other non-AWS
environment.

## How it fits together

jEAP Messaging's AWS MSK IAM authentication delegates credential resolution to an AWS SDK v2
`AwsCredentialsProvider`. Because this starter registers its provider as `@Primary` and runs
`@AutoConfigureBefore(KafkaAutoConfiguration.class)`, the Kafka clients automatically use the
Roles Anywhere credentials. The provider is also exposed through the static
`IAMRolesAnywhereCredentialsProviderHolder`, so the MSK IAM client callback can obtain it outside the
Spring context.

When combined with jEAP Messaging, this starter is supported from jEAP Messaging version `8.52.0`.

## Example configuration

```yaml
jeap:
  messaging:
    kafka:
      systemName: jme
      cluster:
        awsMskBazg:
          defaultCluster: true
          bootstrapServers: "b-1.kafka...amazonaws.com:9098,b-2.kafka...amazonaws.com:9098"
          aws:
            glue:
              registryName: kafka-dev
              region: "eu-central-1"
            msk:
              iamAuthEnabled: true
  aws:
    rolesanywhere:
      enabled: true
      roleArn: "arn:aws:iam::123456789012:role/roles-anywhere/msk-access-user"
      trustAnchorArn: "arn:aws:rolesanywhere:eu-central-2:123456789012:trust-anchor/uuid"
      profileArn: "arn:aws:rolesanywhere:eu-central-2:123456789012:profile/uuid"
```

With `jeap.messaging.kafka.cluster.<name>.aws.msk.iamAuthEnabled: true`, the Kafka client authenticates
to MSK using IAM, drawing temporary credentials from the Roles Anywhere provider. The provider also
serves any other AWS SDK v2 client in the application (for example AWS Glue Schema Registry or S3).

For the messaging-side properties (MSK IAM auth, Glue Schema Registry) refer to the jEAP Messaging
documentation; this page only covers the credential provider that this starter contributes.

## Related

- [Getting started](getting-started.md)
- [How it works](how-it-works.md)
- [Configuration reference](configuration.md)
