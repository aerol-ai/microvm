package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A rule's credential injection. The sandbox's env holds
 * {@code aerolvm-placeholder:<KEY>} in place of the value, and the egress
 * gateway replaces {@code header} with the real value on each request the rule
 * allows, so code in the sandbox never holds the secret.
 */
public class EgressInject {
    /**
     * The header to replace, such as {@code Authorization}. It is replaced, never
     * added to a body or URL. Headers that frame or route the request, such as
     * {@code Host} or {@code Content-Length}, can't be injected.
     */
    public String header;
    /**
     * {@code env:<KEY>}: a key in the create's env, whose value is the whole
     * header value (for example {@code Bearer ghp_...}). Rotating it means
     * recreating the sandbox.
     */
    @JsonProperty("secret_ref")
    public String secretRef;

    public EgressInject setHeader(String header) {
        this.header = header;
        return this;
    }

    public EgressInject setSecretRef(String secretRef) {
        this.secretRef = secretRef;
        return this;
    }
}
