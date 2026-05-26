package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Background-push state for a template's artifacts (rootfs.ext4 + the
 * snapshot files). {@link #ACTIVE} means push succeeded or push is
 * disabled; {@link #PENDING} / {@link #PUSHING} are in-flight; {@link #ERROR}
 * carries a populated {@code pushError} on the template row for the last
 * failure.
 */
public enum TemplatePushState {
    @JsonProperty("active") ACTIVE,
    @JsonProperty("pending") PENDING,
    @JsonProperty("pushing") PUSHING,
    @JsonProperty("error") ERROR,
}
