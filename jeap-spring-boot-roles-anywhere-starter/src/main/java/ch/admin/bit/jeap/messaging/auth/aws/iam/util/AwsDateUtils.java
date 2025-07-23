package ch.admin.bit.jeap.messaging.auth.aws.iam.util;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

public final class AwsDateUtils {
    private static final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

    public static String getDateAndTime(final Instant instant) {
        return dateTimeFormatter.format(instant);
    }

    public static String getDate(final Instant instant) {
        return getDateAndTime(instant).substring(0, 8);
    }
}
