package ai.aerol.microvm.model;

/** A sandbox's cloud identity as {@code get} shows it. Never the token. */
public class SandboxIdentity {
    public String roleTag;
    public String audience;
    /** The token's {@code sub}: what your cloud's trust policy matches. */
    public String subject;
    public String awsRoleArn;
    public String azureClientId;
    public String azureTenantId;
    public String tokenFile;
    /** When the token now in the sandbox expires; null until the first one. */
    public String tokenExpiresAt;
    public String lastError;

    public SandboxIdentity copy() {
        SandboxIdentity c = new SandboxIdentity();
        c.roleTag = roleTag;
        c.audience = audience;
        c.subject = subject;
        c.awsRoleArn = awsRoleArn;
        c.azureClientId = azureClientId;
        c.azureTenantId = azureTenantId;
        c.tokenFile = tokenFile;
        c.tokenExpiresAt = tokenExpiresAt;
        c.lastError = lastError;
        return c;
    }
}
