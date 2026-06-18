# Certificates and keys

The starter needs the service's X.509 client certificate and its private key to sign the IAM Roles
Anywhere request. This page covers the accepted formats, the certificate chain handling and the
default file layout.

## Accepted formats

Both the certificate and the key may be supplied either **inline** (via `encodedX509Certificate` /
`encodedPrivateKey`) or as **PEM files** (via `certificateFilePath` / `privateKeyFilePath`). Inline
values take precedence over the file paths.

- **Certificate** (`CertLoader`): accepts PEM (`-----BEGIN CERTIFICATE-----` … `-----END
  CERTIFICATE-----`) or an already Base64-encoded value. PEM input is normalized and Base64-encoded
  internally; whitespace is stripped.
- **Private key** (`PrivateKeyLoader`): accepts PEM (`-----BEGIN PRIVATE KEY-----` … `-----END PRIVATE
  KEY-----`) or a raw Base64 value. The key must be a **PKCS#8 RSA** key — it is parsed with
  `PKCS8EncodedKeySpec` and the `RSA` `KeyFactory`.

## Certificate chains

If the provided certificate contains more than one certificate, `CertLoader` resolves a full
`X509CertificateChain`, classifying each entry as the **leaf** certificate, an **intermediate CA**, or
the **root CA** (a self-signed certificate). When an intermediate CA is present, it is included in the
signed request via the `X-Amz-X509-Chain` header; otherwise only the leaf certificate is sent in the
`X-Amz-X509` header. A single certificate is treated as the leaf.

## Default file layout

When no inline values and no explicit file paths are configured, the mapper falls back to these
defaults under the user's home directory:

| File              | Default path                                       |
|-------------------|----------------------------------------------------|
| Certificate (PEM) | `${user.home}/.aws/roles-anywhere/userCert.pem`    |
| Private key (PEM) | `${user.home}/.aws/roles-anywhere/userKey.pem`     |
| ARN JSON          | `${user.home}/.aws/roles-anywhere/context.json`    |

## Loading ARNs from JSON

Instead of (or in addition to) configuring `roleArn`, `profileArn` and `trustAnchorArn` directly, they
can be read from the `arnJsonFilePath` JSON file. Any ARN left blank in the properties is filled from
the matching JSON field; directly configured values always win.

```json
{
  "roleArn": "arn:aws:iam::123456789012:role/roles-anywhere/msk-access-user",
  "profileArn": "arn:aws:rolesanywhere:eu-central-2:123456789012:profile/uuid",
  "trustAnchorArn": "arn:aws:rolesanywhere:eu-central-2:123456789012:trust-anchor/uuid"
}
```

## Related

- [Configuration reference](configuration.md)
- [How it works](how-it-works.md)
- [Getting started](getting-started.md)
