package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * One DNS record an operator needs to publish to validate a custom domain.
 * {@link #type} carries the RR type (e.g. {@code CNAME}, {@code A}) and is
 * bound explicitly via {@link JsonProperty} for symmetry with the wire field,
 * even though Jackson would map a bare {@code type} field already.
 */
public class DnsRecord {
    public String hostname;
    @JsonProperty("type")
    public String type;
    public String name;
    public String value;
    public String notes;
}
