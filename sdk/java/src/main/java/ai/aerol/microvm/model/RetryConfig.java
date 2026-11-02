package ai.aerol.microvm.model;

public class RetryConfig {
    public Integer maxRetries = 3;
    public Integer baseDelayMs = 200;
    public Integer maxDelayMs = 5000;
    /**
     * Cap in milliseconds on the wait before re-sending a 429 or 503. The
     * client waits as long as the server's {@code Retry-After} header asks
     * (seconds or an HTTP date), never less than its own backoff, plus up to a
     * fifth more so clients told the same value spread out; a longer ask is
     * cut to this. A missing or malformed header uses the backoff. Defaults
     * to 30000; 0 ignores {@code Retry-After}. Interrupting the calling
     * thread (for example {@code Future.cancel(true)}) ends the wait at once.
     */
    public Integer maxRetryAfterMs = 30000;

    public RetryConfig setMaxRetries(Integer maxRetries) {
        this.maxRetries = maxRetries;
        return this;
    }

    public RetryConfig setBaseDelayMs(Integer baseDelayMs) {
        this.baseDelayMs = baseDelayMs;
        return this;
    }

    public RetryConfig setMaxDelayMs(Integer maxDelayMs) {
        this.maxDelayMs = maxDelayMs;
        return this;
    }

    public RetryConfig setMaxRetryAfterMs(Integer maxRetryAfterMs) {
        this.maxRetryAfterMs = maxRetryAfterMs;
        return this;
    }
}
