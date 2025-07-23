package ch.admin.bit.jeap.messaging.auth.aws.iam;

import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.utils.Logger;
import software.amazon.awssdk.utils.cache.CachedSupplier;
import software.amazon.awssdk.utils.cache.NonBlocking;
import software.amazon.awssdk.utils.cache.RefreshResult;

import java.time.Duration;
import java.time.Instant;

public abstract class RolesAnywhereCredentialsProvider implements AwsCredentialsProvider, AutoCloseable {

    private static final Logger log = Logger.loggerFor(RolesAnywhereCredentialsProvider.class);

    private static final Duration DEFAULT_STALE_TIME = Duration.ofMinutes(1);
    private static final Duration DEFAULT_PREFETCH_TIME = Duration.ofMinutes(5);

    private final CachedSupplier<AwsSessionCredentials> sessionCache;

    protected RolesAnywhereCredentialsProvider(
            String asyncThreadName
    ) {
        this.sessionCache = CachedSupplier.builder(this::updateSessionCredentials)
                .prefetchStrategy(new NonBlocking(asyncThreadName))
                .cachedValueName(providerName())
                .build();
    }

    private RefreshResult<AwsSessionCredentials> updateSessionCredentials() {
        AwsSessionCredentials credentials = getUpdatedCredentials();
        Instant expiration = credentials.expirationTime()
                .orElseThrow(() -> new IllegalStateException("Credentials must have an expiration time"));

        return RefreshResult.builder(credentials)
                .staleTime(expiration.minus(DEFAULT_STALE_TIME))
                .prefetchTime(expiration.minus(DEFAULT_PREFETCH_TIME))
                .build();
    }

    @Override
    public AwsCredentials resolveCredentials() {
        AwsSessionCredentials credentials = sessionCache.get();
        credentials.expirationTime().ifPresent(exp ->
                log.info(() -> "Using Roles Anywhere credentials with expiration: " + exp));
        return credentials;
    }

    @Override
    public void close() {
        sessionCache.close();
    }

    protected void prefetchCredentials() {
        sessionCache.get();
    }

    protected abstract AwsSessionCredentials getUpdatedCredentials();

    protected abstract String providerName();
}
