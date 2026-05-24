package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Lifecycle state of a custom domain attachment. The daemon advances a
 * hostname through {@link #PENDING_DNS} (waiting for the operator to point
 * an A/CNAME at the cluster) into {@link #ISSUING} (Caddy is fetching an
 * ACME certificate on-demand) and finally {@link #READY} once a cert is in
 * the on-demand cache. {@link #FAILED} is sticky and accompanied by a
 * {@code last_error}.
 */
public enum CustomDomainStatus {
    PENDING_DNS("pending_dns"),
    ISSUING("issuing"),
    READY("ready"),
    FAILED("failed");

    private final String wireValue;

    CustomDomainStatus(String wireValue) {
        this.wireValue = wireValue;
    }

    @JsonValue
    public String getWireValue() {
        return wireValue;
    }

    @JsonCreator
    public static CustomDomainStatus fromWire(String value) {
        if (value == null) {
            return null;
        }
        switch (value) {
            case "pending_dns":
                return PENDING_DNS;
            case "issuing":
                return ISSUING;
            case "ready":
                return READY;
            case "failed":
                return FAILED;
            default:
                throw new IllegalArgumentException("unknown custom domain status: " + value);
        }
    }
}
