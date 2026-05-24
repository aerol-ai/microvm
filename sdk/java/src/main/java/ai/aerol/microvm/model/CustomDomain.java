package ai.aerol.microvm.model;

import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Operator-supplied hostname attached to a sandbox's HTTP entrypoint. The
 * server lowercases {@link #hostname} on write, so the value returned here
 * is the canonical form to render or compare against. {@link #lastError} is
 * populated only when {@link #status} is {@link CustomDomainStatus#FAILED}.
 */
public class CustomDomain {
    public String hostname;
    public CustomDomainStatus status;
    @JsonProperty("last_error")
    public String lastError;
    @JsonProperty("created_at")
    public Instant createdAt;
    @JsonProperty("updated_at")
    public Instant updatedAt;
}
