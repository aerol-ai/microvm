package ai.aerol.microvm.model;

public class RetryConfig {
    public Integer maxRetries = 3;
    public Integer baseDelayMs = 200;
    public Integer maxDelayMs = 5000;

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
}
