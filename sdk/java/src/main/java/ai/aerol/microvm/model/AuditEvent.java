package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * One record from a sandbox's audit log ({@code Sandbox.audit}). Kind
 * {@code "egress"} covers outbound connections and denials; a denial has
 * result {@code "failure"} and the policy reason ({@code "host_not_allowed"},
 * {@code "sni_not_allowed"}, ...).
 */
public class AuditEvent {
    public String time;
    public String kind;
    public String result;
    public String reason;
    public String destination;
    public String network;
    public String actor;
    public String ref;
    @JsonProperty("event_id")
    public String eventId;
    @JsonProperty("incarnation_id")
    public String incarnationId;
    /** Records lost at this point (a gap record). */
    public long dropped;
}
