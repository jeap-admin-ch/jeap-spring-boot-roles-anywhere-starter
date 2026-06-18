# AGENTS.md

Guidance for AI coding agents working **in this repository**. For how to *use* the library in a
consuming service, read [README.md](README.md) and the [docs/](docs/) folder instead.

## Project

jEAP Spring Boot Roles Anywhere Starter is a Spring Boot starter that provisions temporary AWS
credentials via AWS IAM Roles Anywhere. A service outside AWS authenticates with an X.509 client
certificate and its private key against an IAM Roles Anywhere trust anchor, assumes an IAM role and
receives short-lived session credentials. The starter signs the `CreateSession` request itself (AWS
SigV4 with the X.509 certificate) and exposes the result as a `@Primary`
`software.amazon.awssdk.auth.credentials.AwsCredentialsProvider` bean that AWS SDK v2 clients pick up
automatically. It replaces the external `aws_signing_helper` credential helper.

## Repository layout

```
pom.xml                                          # Parent POM (packaging=pom); declares the modules below
jeap-spring-boot-roles-anywhere-starter/         # The starter
  .../iam/properties/RolesAnywhereAutoConfiguration.java   # @AutoConfiguration; wires the beans
  .../iam/properties/AwsRolesAnywhereProperties.java       # @ConfigurationProperties("jeap.aws.rolesanywhere")
  .../iam/AwsRolesAnywhereSessionOrchestrator.java         # Builds, signs and sends the CreateSession request
  .../iam/IAMRolesAnywhereSessionsCredentialsProvider.java # Provider backed by the orchestrator
  .../iam/RolesAnywhereCredentialsProvider.java            # Abstract base; CachedSupplier-based refresh
  .../iam/mapper/RolesAnywhereAuthContextMapper.java       # Properties -> RolesAnywhereAuthContext
  .../iam/certs/CertLoader.java, PrivateKeyLoader.java     # PEM/Base64 normalization, X.509 chain, PKCS#8 key
  .../iam/signing/, request/, util/, models/               # SigV4 signing, HTTP request, helpers, DTOs
jeap-spring-boot-roles-anywhere-starter-it/      # Spring Boot integration tests (mocked orchestrator)
Jenkinsfile, CHANGELOG.md, LICENSE
```

## Build & test

```bash
./mvnw verify                                              # full build incl. tests
./mvnw -pl jeap-spring-boot-roles-anywhere-starter test    # unit tests
./mvnw -pl jeap-spring-boot-roles-anywhere-starter-it test # integration tests
```

- Parent: `ch.admin.bit.jeap:jeap-internal-spring-boot-parent`.
- The `-it` module verifies the auto-configuration with a mocked `AwsRolesAnywhereSessionOrchestrator`
  (no real AWS call); see `RolesAnywhereAutoConfigurationIT`.

## jEAP conventions

- Java packages live under `ch.admin.bit.jeap.messaging.auth.aws.iam...`.
- Configuration properties use the prefix `jeap.aws.rolesanywhere.*` (see
  `AwsRolesAnywhereProperties`).
- Auto-configuration is registered via `@AutoConfiguration` and
  `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`; it activates only
  when `jeap.aws.rolesanywhere.enabled=true` and runs `@AutoConfigureBefore(KafkaAutoConfiguration.class)`.
- The HTTP client is the JDK `UrlConnectionHttpClient` (the Apache and Netty AWS SDK clients are
  excluded in the module POM).
- Private keys must be PKCS#8 RSA; certificates may be PEM or Base64 and may include a chain.

## Docs

When changing public behaviour (properties, bean wiring, credential flow), update the matching focused
file under [docs/](docs/) (one topic per file) and the documentation index in the README.

## Versioning

- Semantic Versioning; all changes documented in [CHANGELOG.md](./CHANGELOG.md) (Keep a Changelog format).
- `setPomVersions.sh <version>` updates the version across all module POMs.
- When working on a feature branch, increase the version to `x.y.z-SNAPSHOT` in the POMs. Always keep
  the `-SNAPSHOT` postfix in the POMs; CI removes it when releasing. Do not use the SNAPSHOT postfix
  elsewhere (CHANGELOG etc).
- Keep changelog entries concise and follow existing patterns.
- Keep commit messages short, use the JIRA ID from the branch name as a prefix, do not use conventional
  commits (for example: "JEAP-1234 Added feature X").
