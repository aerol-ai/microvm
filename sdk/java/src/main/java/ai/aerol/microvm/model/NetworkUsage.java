package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class NetworkUsage {
    @JsonProperty("sandbox_id")
    public String sandboxId;
    @JsonProperty("bytes_in")
    public long bytesIn;
    @JsonProperty("bytes_out")
    public long bytesOut;
    @JsonProperty("bytes_in_limit")
    public long bytesInLimit;
    @JsonProperty("bytes_out_limit")
    public long bytesOutLimit;
    @JsonProperty("quota_exceeded")
    public boolean quotaExceeded;
    @JsonProperty("quota_exceeded_at")
    public String quotaExceededAt;
    /** Null until the netstats poller has produced at least one sample. */
    @JsonProperty("last_sampled_at")
    public String lastSampledAt;
}
