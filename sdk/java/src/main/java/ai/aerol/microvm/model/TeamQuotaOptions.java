package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * A team quota's limits, the body of {@code putTeamQuota}. Leave a limit
 * null (or 0) for no limit on it. At least one must be set.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TeamQuotaOptions {
    /** Most sandboxes the team may hold, running or stopped. */
    public Integer maxSandboxes;
    /** Most CPU the team's sandboxes may ask for in total. */
    public Double maxCpu;
    /** Most memory, in MB, the team's sandboxes may ask for in total. */
    public Integer maxMemoryMb;

    public TeamQuotaOptions setMaxSandboxes(Integer maxSandboxes) {
        this.maxSandboxes = maxSandboxes;
        return this;
    }

    public TeamQuotaOptions setMaxCpu(Double maxCpu) {
        this.maxCpu = maxCpu;
        return this;
    }

    public TeamQuotaOptions setMaxMemoryMb(Integer maxMemoryMb) {
        this.maxMemoryMb = maxMemoryMb;
        return this;
    }
}
