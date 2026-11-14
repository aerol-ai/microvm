package ai.aerol.microvm.model;

/** A team's quota, and what the team holds now ({@code usage}) when read back. */
public class TeamQuota {
    public String team;
    /** 0 means no limit on sandboxes. */
    public int maxSandboxes;
    /** 0 means no limit on CPU. */
    public double maxCpu;
    /** 0 means no limit on memory. */
    public int maxMemoryMb;
    public long generation;
    public String createdAt;
    public String updatedAt;
    public TeamQuotaUsage usage;
}
