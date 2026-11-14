package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * The body of {@code putIdentityRole}, and the team whose list it changes
 * (null is the operator namespace: sandboxes the operator token creates).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IdentityRoleOptions {
    private String minRole;
    private String team;

    /** {@code "runner"} or {@code "admin"}. */
    public String getMinRole() {
        return minRole;
    }

    public IdentityRoleOptions setMinRole(String minRole) {
        this.minRole = minRole;
        return this;
    }

    /** Sent as the {@code team} query parameter, never in the body. */
    @JsonIgnore
    public String getTeam() {
        return team;
    }

    public IdentityRoleOptions setTeam(String team) {
        this.team = team;
        return this;
    }
}
