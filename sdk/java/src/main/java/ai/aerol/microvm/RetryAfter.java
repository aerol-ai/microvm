package ai.aerol.microvm;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

/**
 * How {@link MicroVMClient} paces its retries: the server's
 * {@code Retry-After} on a 429 or 503, or the client's own backoff.
 */
final class RetryAfter {
    /**
     * Default cap on one retry's wait for the server's Retry-After. An
     * overloaded node asks for about a second, so the cap only bites on a long
     * ask (maintenance, a misconfigured proxy), which should not hold a call
     * for minutes per retry.
     */
    static final int DEFAULT_MAX_RETRY_AFTER_MS = 30_000;

    /** Longer delta-seconds values are clamped: no cap is that long anyway. */
    static final long MAX_RETRY_AFTER_SECONDS = 1_000_000_000L;

    private RetryAfter() {
    }

    /**
     * The response's {@code Retry-After} when the status is one the server
     * paces clients with: 429 (this caller is over its share) and 503 (the
     * node is shedding load). A 421, 502 or 504 comes from a routing or proxy
     * hop, so a Retry-After on it is not the server's and the backoff applies.
     */
    static String hint(HttpResponse<?> response) {
        int status = response.statusCode();
        if (status != 429 && status != 503) {
            return null;
        }
        return response.headers().firstValue("Retry-After").orElse(null);
    }

    /**
     * Reads a Retry-After value in either form RFC 9110 allows: delta-seconds
     * ({@code "120"}) or an HTTP date ({@code "Sun, 06 Nov 1994 08:49:37
     * GMT"}). A date already past is a zero wait; null for an absent or
     * malformed value.
     */
    static Duration parse(String value, Instant now) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        if (!trimmed.isEmpty() && trimmed.chars().allMatch(c -> c >= '0' && c <= '9')) {
            long seconds;
            try {
                seconds = Long.parseLong(trimmed);
            } catch (NumberFormatException overflow) {
                seconds = MAX_RETRY_AFTER_SECONDS;
            }
            return Duration.ofSeconds(Math.min(seconds, MAX_RETRY_AFTER_SECONDS));
        }
        try {
            Instant when = ZonedDateTime.parse(trimmed, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
            return when.isAfter(now) ? Duration.between(now, when) : Duration.ZERO;
        } catch (DateTimeParseException malformed) {
            return null;
        }
    }

    /**
     * Milliseconds to wait before re-sending. {@code attempt} counts from 0,
     * {@code retryAfter} is {@link #hint}'s result (null for a transport
     * error) and {@code random} is uniform in [0, 1).
     *
     * <p>Without a usable header it is the exponential backoff ±25%. With
     * one, it never retries sooner than the server asked (nor sooner than the
     * backoff) and adds up to a fifth so clients told the same value spread
     * out. {@code maxRetryAfterMs} is a hard ceiling: when the server asks for
     * at least that long the client is early anyway, so the spread goes below
     * it instead.
     */
    static long waitMillis(int baseDelayMs, int maxDelayMs, int maxRetryAfterMs, int attempt, String retryAfter, Instant now, double random) {
        long factor = attempt >= 62 ? Long.MAX_VALUE : 1L << attempt;
        double backoff = Math.min((double) baseDelayMs * factor, maxDelayMs);
        Duration hint = maxRetryAfterMs > 0 ? parse(retryAfter, now) : null;
        if (hint == null) {
            return (long) (backoff * (0.75 + 0.5 * random));
        }
        double limit = maxRetryAfterMs;
        double target = Math.max(hint.toMillis(), backoff);
        if (target >= limit) {
            return (long) (limit - limit * 0.2 * random);
        }
        double upper = Math.min(target * 1.2, limit);
        return (long) (target + (upper - target) * random);
    }
}
