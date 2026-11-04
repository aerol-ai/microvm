package ai.aerol.microvm.model;

/** One scoped API token as {@code client.tokens().list()} returns it. Never the secret. */
public class ApiToken {
    /** Public id ({@code tok_…}): what {@code tokens().revoke} takes and audit records name. */
    public String id;
    public String name;
    public String role;
    /** A team name, or {@code "*"} for every team. */
    public String team;
    public String createdBy;
    public String createdAt;
    public String expiresAt;
    /** Expired tokens no longer work; they stay listed for 30 days. */
    public boolean expired;
}
