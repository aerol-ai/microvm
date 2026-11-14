package ai.aerol.microvm.model;

/** What a team holds: every sandbox not deleted, at the size it asked for. */
public class TeamQuotaUsage {
    public int sandboxes;
    public double cpu;
    public int memoryMb;
}
