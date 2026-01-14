package ch.admin.bit.jeap.messaging.auth.aws.iam.signing;

import ch.admin.bit.jeap.messaging.auth.aws.iam.models.X509CertificateChain;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.ServiceEndpointKey;
import software.amazon.awssdk.regions.servicemetadata.RolesanywhereServiceMetadata;

import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.stream.Collectors;

import static ch.admin.bit.jeap.messaging.auth.aws.iam.certs.CertLoader.convertToBase64PEMString;
import static ch.admin.bit.jeap.messaging.auth.aws.iam.request.AwsRolesAnywhereHeaderFactory.*;
import static ch.admin.bit.jeap.messaging.auth.aws.iam.util.AwsDateUtils.getDateAndTime;
import static ch.admin.bit.jeap.messaging.auth.aws.iam.util.AwsHashUtils.hashContent;
import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;
import static software.amazon.awssdk.http.Header.CONTENT_TYPE;
import static software.amazon.awssdk.http.Header.HOST;
import static software.amazon.awssdk.http.auth.aws.signer.SignerConstant.X_AMZ_DATE;

@Slf4j
@NoArgsConstructor
public class AwsCanonicalRequestFactory {
    private static final String LINE_SEPARATOR = "\n";
    public static final String EMPTY_STRING = "";

    public static String resolveHostBasedOnRegion(final Region region) {
        return new RolesanywhereServiceMetadata().endpointFor(ServiceEndpointKey.builder().region(region).build()).getPath();
    }

    public String buildCanonicalRequest(final Instant instant,
                                        final String host,
                                        final String method,
                                        final String uri,
                                        final String body,
                                        final X509CertificateChain x509CertificateChain) throws NoSuchAlgorithmException {
        var dateAndTime = getDateAndTime(instant);
        var canonicalHeaders = "";
        var canonicalRequestBuilder = new StringBuilder();
        canonicalRequestBuilder.append(method).append(LINE_SEPARATOR)
                .append(uri).append(LINE_SEPARATOR)
                .append(EMPTY_STRING).append(LINE_SEPARATOR);

        if (x509CertificateChain.getIntermediateCACertificate() == null) {
            canonicalHeaders = buildCanonicalHeaders(
                    host,
                    APPLICATION_JSON_VALUE,
                    dateAndTime,
                    x509CertificateChain.getBase64EncodedCertificate()
            );
            canonicalRequestBuilder
                    .append(canonicalHeaders).append(LINE_SEPARATOR)
                    .append(buildSignedHeaders().toLowerCase()).append(LINE_SEPARATOR);
        } else {
            var chainCerts = convertToBase64PEMString(x509CertificateChain.getIntermediateCACertificate());
            canonicalHeaders = buildCanonicalHeaders(
                    host,
                    APPLICATION_JSON_VALUE,
                    dateAndTime,
                    convertToBase64PEMString(x509CertificateChain.getLeafCertificate()),
                    chainCerts
            );
            canonicalRequestBuilder
                    .append(canonicalHeaders).append(LINE_SEPARATOR)
                    .append(buildSignedHeadersWithChain().toLowerCase()).append(LINE_SEPARATOR);
        }
        log.debug("canonicalHeaders = {}", canonicalHeaders);
        log.debug("sessions request = {}", body);
        canonicalRequestBuilder.append(hashContent(body));
        return canonicalRequestBuilder.toString();
    }

    public static SortedMap<String, String> canonicalHeaders(final String host,
                                                             final String contentType,
                                                             final String date,
                                                             final String derX509) {
        var headers = new TreeMap<String, String>();
        headers.put(CONTENT_TYPE.toLowerCase(), contentType);
        headers.put(HOST.toLowerCase(), host);
        headers.put(X_AMZ_DATE.toLowerCase(), date);
        headers.put(X_AMZ_X509.toLowerCase(), derX509);
        return headers;
    }

    public static String buildCanonicalHeaders(final String host,
                                               final String contentType,
                                               final String date,
                                               final String derX509) {
        var headers = canonicalHeaders(host, contentType, date, derX509);
        return headers.entrySet().stream()
                .map(entry -> entry.getKey() + ":" + entry.getValue())
                .collect(Collectors.joining(LINE_SEPARATOR)) + LINE_SEPARATOR;
    }

    public static String buildCanonicalHeaders(final String host,
                                               final String contentType,
                                               final String date,
                                               final String derX509,
                                               final String chainDerX509CommaSeparated) {
        var headers = canonicalHeaders(host, contentType, date, derX509);
        headers.put(X_AMZ_X509_CHAIN.toLowerCase(), chainDerX509CommaSeparated);
        return headers.entrySet().stream()
                .map(entry -> entry.getKey() + ":" + entry.getValue())
                .collect(Collectors.joining(LINE_SEPARATOR)) + LINE_SEPARATOR;
    }
}
