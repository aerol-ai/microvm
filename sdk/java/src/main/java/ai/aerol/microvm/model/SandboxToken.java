package ai.aerol.microvm.model;

import java.util.List;

/**
 * {@code sandbox.createToken()}'s result. {@link #token} ({@code avmst_…})
 * is shown only here: the server keeps no copy. {@link #tokenId}
 * ({@code stk_…}) is what audit records name and is safe to log. A token
 * cannot be revoked: it stops working when it expires or its sandbox is
 * deleted.
 */
public class SandboxToken {
    public String token;
    public String tokenId;
    public String sandboxId;
    /** Set for a public-port token; {@code null} for a toolbox token. */
    public Integer port;
    public String pathPrefix;
    public List<String> methods;
    /** RFC 3339 time the token stops working. */
    public String expiresAt;
}
