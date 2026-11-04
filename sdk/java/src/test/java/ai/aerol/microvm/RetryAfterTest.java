package ai.aerol.microvm;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

import ai.aerol.microvm.model.RetryConfig;

class RetryAfterTest {
    // Mon, 02 Nov 2026 12:00:00 GMT
    private static final Instant NOW = Instant.parse("2026-11-02T12:00:00Z");

    @Test
    void parseReadsDeltaSecondsAndHttpDates() {
        Object[][] cases = {
            {null, null},
            {"", null},
            {"   ", null},
            {"3", Duration.ofSeconds(3)},
            {" 3 ", Duration.ofSeconds(3)},
            {"0", Duration.ZERO},
            {"-1", null},
            {"+3", null},
            {"1.5", null},
            {"²", null},
            {"soon", null},
            {"99999999999999999999", Duration.ofSeconds(RetryAfter.MAX_RETRY_AFTER_SECONDS)},
            {"Mon, 02 Nov 2026 12:00:07 GMT", Duration.ofSeconds(7)},
            {"Mon, 02 Nov 2026 11:59:00 GMT", Duration.ZERO},
            {"Mon, 32 Nov 2026 12:00:07 GMT", null},
        };
        for (Object[] c : cases) {
            assertEquals(c[1], RetryAfter.parse((String) c[0], NOW), String.valueOf(c[0]));
        }
    }

    @Test
    void waitHonoursRetryAfterBetweenBackoffAndCap() {
        // {name, maxRetryAfterMs, attempt, header, random, want ms}
        Object[][] cases = {
            {"no header: backoff minus a quarter", 2000, 0, null, 0.0, 75L},
            {"no header: backoff plus a quarter", 2000, 0, null, 1.0, 125L},
            {"no header: doubles per attempt", 2000, 2, null, 0.5, 400L},
            {"no header: capped by maxDelayMs", 2000, 5, null, 0.5, 1000L},
            {"no header: huge attempt saturates", 2000, 200, null, 0.5, 1000L},
            {"malformed header falls back", 2000, 0, "soon", 0.0, 75L},
            {"seconds: never sooner than asked", 2000, 0, "1", 0.0, 1000L},
            {"seconds: at most a fifth later", 2000, 0, "1", 1.0, 1200L},
            {"HTTP date", 2000, 0, "Mon, 02 Nov 2026 12:00:01 GMT", 0.0, 1000L},
            {"backoff is the floor", 2000, 2, "0", 0.0, 400L},
            {"spread stops at the cap", 1100, 0, "1", 1.0, 1100L},
            {"long ask is cut to the cap", 2000, 0, "120", 0.0, 2000L},
            {"long ask spreads below the cap", 2000, 0, "120", 1.0, 1600L},
            {"cap 0 ignores the header", 0, 0, "120", 0.0, 75L},
        };
        for (Object[] c : cases) {
            long got = RetryAfter.waitMillis(100, 1000, (Integer) c[1], (Integer) c[2], (String) c[3], NOW, (Double) c[4]);
            assertEquals((long) (Long) c[5], got, (String) c[0]);
        }
    }

    @Test
    void retryConfigDefaultsToThirtySecondCap() {
        assertEquals(RetryAfter.DEFAULT_MAX_RETRY_AFTER_MS, (int) new RetryConfig().maxRetryAfterMs);
    }
}
