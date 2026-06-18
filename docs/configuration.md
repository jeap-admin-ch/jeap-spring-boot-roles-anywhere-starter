# Configuration reference

All properties use the prefix `jeap.aws.rolesanywhere` and are bound by `AwsRolesAnywhereProperties`.
The auto-configuration only activates when `jeap.aws.rolesanywhere.enabled=true`.

## Properties

| Name                     | Default                                             | Description                                                                                      |
|--------------------------|-----------------------------------------------------|--------------------------------------------------------------------------------------------------|
| `enabled`                | `false`                                             | Enables the Roles Anywhere integration. Must be `true` for the auto-configuration to activate     |
| `region`                 | `eu-central-2`                                       | AWS region; selects the IAM Roles Anywhere endpoint                                               |
| `roleArn`                | —                                                   | ARN of the IAM role to assume                                                                     |
| `trustAnchorArn`         | —                                                   | ARN of the trust anchor used to validate the client certificate                                  |
| `profileArn`             | —                                                   | ARN of the IAM Roles Anywhere profile                                                             |
| `sessionDuration`        | `3600`                                              | Requested session duration in seconds                                                             |
| `encodedX509Certificate` | —                                                   | Client certificate, inline as PEM or Base64. Overrides `certificateFilePath`                      |
| `encodedPrivateKey`      | —                                                   | Private key (PKCS#8 RSA), inline as PEM or Base64. Overrides `privateKeyFilePath`                  |
| `certificateFilePath`    | `${user.home}/.aws/roles-anywhere/userCert.pem`     | Path to the certificate PEM file                                                                  |
| `privateKeyFilePath`     | `${user.home}/.aws/roles-anywhere/userKey.pem`      | Path to the private key PEM file                                                                  |
| `arnJsonFilePath`        | `${user.home}/.aws/roles-anywhere/context.json`     | Optional JSON file providing `roleArn`, `profileArn` and `trustAnchorArn`                          |

> `sessionDuration` is a fixed default of `3600` seconds in the current version and is not overridable
> through configuration.

## How values are resolved

The properties are mapped into the internal auth context by `RolesAnywhereAuthContextMapper`, which
applies the following precedence:

- **Certificate**: `encodedX509Certificate` if set, otherwise the contents of `certificateFilePath`.
- **Private key**: `encodedPrivateKey` if set, otherwise the contents of `privateKeyFilePath`.
- **ARNs**: the directly configured `roleArn` / `profileArn` / `trustAnchorArn` take precedence; any
  that are still blank are read from the `arnJsonFilePath` JSON (keys `roleArn`, `profileArn`,
  `trustAnchorArn`). Inline values always win over file-based values.

Validation fails fast at startup if the region is blank, if neither the ARNs nor an ARN JSON file are
available, or if no certificate / private key source is provided.

## Minimal vs. inline configuration

```yaml
# Minimal: ARNs inline, certificate and key from the default file paths
jeap:
  aws:
    rolesanywhere:
      enabled: true
      roleArn: "arn:aws:iam::123456789012:role/roles-anywhere/msk-access-user"
      trustAnchorArn: "arn:aws:rolesanywhere:eu-central-2:123456789012:trust-anchor/uuid"
      profileArn: "arn:aws:rolesanywhere:eu-central-2:123456789012:profile/uuid"
```

```yaml
# Fully inline: no external files needed
jeap:
  aws:
    rolesanywhere:
      enabled: true
      roleArn: "arn:aws:iam::123456789012:role/roles-anywhere/msk-access-user"
      trustAnchorArn: "arn:aws:rolesanywhere:eu-central-2:123456789012:trust-anchor/uuid"
      profileArn: "arn:aws:rolesanywhere:eu-central-2:123456789012:profile/uuid"
      encodedX509Certificate: |
        -----BEGIN CERTIFICATE-----
        MIIF...
        -----END CERTIFICATE-----
      encodedPrivateKey: |
        -----BEGIN PRIVATE KEY-----
        MIIEv...
        -----END PRIVATE KEY-----
```

## Related

- [Getting started](getting-started.md)
- [Certificates and keys](certificates-and-keys.md)
- [How it works](how-it-works.md)
