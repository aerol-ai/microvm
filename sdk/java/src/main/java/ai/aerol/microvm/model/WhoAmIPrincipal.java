package ai.aerol.microvm.model;

/** Who the caller is, as {@code client.whoami()} reports it. */
public class WhoAmIPrincipal {
    /** {@code "operator"}, {@code "token"}, {@code "oidc"}, {@code "controlplane"}, ... */
    public String kind;
    /** Stable id: {@code "operator"}, {@code "tok_…"}, {@code "oidc:<issuer>:<sub>"}, ... */
    public String id;
    /** Display name; null when the server has none. */
    public String name;
}
