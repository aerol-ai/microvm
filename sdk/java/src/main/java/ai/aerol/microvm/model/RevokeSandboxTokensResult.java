package ai.aerol.microvm.model;

/**
 * {@code sandbox.revokeTokens()}'s result: every token issued for the
 * sandbox before {@link #tokensNotBefore} no longer works. A token made
 * after the call works.
 */
public class RevokeSandboxTokensResult {
    public String sandboxId;
    /** RFC 3339 time. Tokens issued before it are refused. */
    public String tokensNotBefore;
}
