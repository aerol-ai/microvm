package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * One DNS record an operator needs to publish to validate a custom domain.
 * {@link #type} carries the RR type — one of {@code CNAME}, {@code A},
 * {@code AAAA}, {@code ANAME}, or {@code ALIAS}. {@code ANAME}/{@code ALIAS}
 * appear only for an apex domain on a hostname ingress, as mutually-exclusive
 * flattening alternatives to {@code CNAME} (add the one your provider supports,
 * see {@link #notes}). It is bound explicitly via {@link JsonProperty} for
 * symmetry with the wire field, even though Jackson would map a bare
 * {@code type} field already.
 */
public class DnsRecord {
    public String hostname;
    @JsonProperty("type")
    public String type;
    public String name;
    public String value;
    public String notes;
}
