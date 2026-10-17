package ai.aerol.microvm.model;

/** The body of {@code GET /v1/whoami}: the caller's own resolved identity. */
public class WhoAmI {
    public WhoAmIPrincipal principal = new WhoAmIPrincipal();
    /** {@code viewer}, {@code runner}, {@code auditor} or {@code admin}. */
    public String role;
    /** {@code "*"} for every team, a team name, or null for a managed account. */
    public String team;
    /** When the credential stops working (RFC 3339); null if it never does. */
    public String expiresAt;
}
