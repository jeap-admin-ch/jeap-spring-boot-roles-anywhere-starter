# jEAP Spring Boot Roles Anywhere Starter

jEAP Spring Boot Roles Anywhere Starter is a Spring Boot starter that lets a jEAP service obtain
temporary AWS credentials via [AWS IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html).
Using an X.509 client certificate and its private key, a service running outside AWS (for example an
on-prem VM) can authenticate against a trust anchor and assume an IAM role, without long-lived AWS
access keys and without the external `aws_signing_helper` credential helper. It provides:

* Spring Boot auto-configuration that registers a `@Primary` `AwsCredentialsProvider` bean
* Certificate-based authentication using AWS IAM Roles Anywhere (SigV4 X.509 request signing)
* Credentials sourced from inline properties or from PEM files (with sensible default paths)
* Automatic, non-blocking background refresh of the temporary session credentials before they expire
* Works with AWS SDK v2 clients (used by jEAP Messaging for Kafka MSK IAM auth, Glue, S3, etc.)

## Documentation

Start with [Getting started](docs/getting-started.md), then follow the links below.

| Topic                                                       | File                                                       |
|-------------------------------------------------------------|------------------------------------------------------------|
| Getting started (add the dependency, configure, use)        | [docs/getting-started.md](docs/getting-started.md)         |
| Configuration reference (`jeap.aws.rolesanywhere.*`)        | [docs/configuration.md](docs/configuration.md)             |
| How it works (credential exchange & refresh)                | [docs/how-it-works.md](docs/how-it-works.md)               |
| Certificates and keys (formats, chains, file layout)        | [docs/certificates-and-keys.md](docs/certificates-and-keys.md) |
| Messaging integration (Kafka MSK IAM)                       | [docs/messaging-integration.md](docs/messaging-integration.md) |

## Modules

Group id for all modules is `ch.admin.bit.jeap`; the version is managed by the jEAP Spring Boot parent.
Consumers depend on the `jeap-spring-boot-roles-anywhere-starter` artifact.

| Module                                       | Purpose                                                                        |
|----------------------------------------------|--------------------------------------------------------------------------------|
| `jeap-spring-boot-roles-anywhere-starter`    | The starter: auto-configuration, credentials provider, certificate/key handling |
| `jeap-spring-boot-roles-anywhere-starter-it` | Spring Boot integration tests for the auto-configuration                       |

## Changes

This library is versioned using [Semantic Versioning](http://semver.org/) and all changes are documented in
[CHANGELOG.md](./CHANGELOG.md) following the format defined in [Keep a Changelog](http://keepachangelog.com/).

## Note

This repository is part the open source distribution of jEAP. See [github.com/jeap-admin-ch/jeap](https://github.com/jeap-admin-ch/jeap)
for more information.

## Attributions
This project includes code from the following open-source projects:

[AWS IAM Roles Anywhere Java Client]
Link: https://github.com/neuw/aws-iam-roles-anywhere
License: Apache 2.0
Included Code: jEAP includes parts of the aws-iam-roles-anywhere project, primarily for integrating AWS certificate-based authentication.
Changes: Modifications were made to adapt the code to project-specific requirements and Spring Boot integration.

## License

This repository is Open Source Software licensed under the [Apache License 2.0](./LICENSE).
