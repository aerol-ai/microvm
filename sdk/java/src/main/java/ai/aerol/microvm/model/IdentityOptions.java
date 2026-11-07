package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * A cloud identity for a sandbox ({@link CreateOptions#setIdentity}). The
 * server signs a one-hour token whose subject is your team and
 * {@code roleTag}, writes it to {@code /run/aerolvm/identity/token} inside the
 * sandbox and refreshes it. The role tag must be on your team's allow list
 * ({@code putIdentityRole}).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IdentityOptions {
    private String roleTag;
    private String audience;
    private String awsRoleArn;
    private String azureClientId;
    private String azureTenantId;

    public String getRoleTag() {
        return roleTag;
    }

    public IdentityOptions setRoleTag(String roleTag) {
        this.roleTag = roleTag;
        return this;
    }

    /** The token's {@code aud}; null means {@code "sts.amazonaws.com"}. */
    public String getAudience() {
        return audience;
    }

    public IdentityOptions setAudience(String audience) {
        this.audience = audience;
        return this;
    }

    /** Also sets {@code AWS_ROLE_ARN} and {@code AWS_WEB_IDENTITY_TOKEN_FILE} for the AWS SDKs. */
    public String getAwsRoleArn() {
        return awsRoleArn;
    }

    public IdentityOptions setAwsRoleArn(String awsRoleArn) {
        this.awsRoleArn = awsRoleArn;
        return this;
    }

    /** Set with {@link #setAzureTenantId} to give the Azure SDKs their workload identity variables. */
    public String getAzureClientId() {
        return azureClientId;
    }

    public IdentityOptions setAzureClientId(String azureClientId) {
        this.azureClientId = azureClientId;
        return this;
    }

    public String getAzureTenantId() {
        return azureTenantId;
    }

    public IdentityOptions setAzureTenantId(String azureTenantId) {
        this.azureTenantId = azureTenantId;
        return this;
    }
}
