package ai.aerol.microvm.model;

/** One role tag on a team's cloud identity allow list. */
public class IdentityRole {
    public String tag;
    /** The least caller role that may create a sandbox with this tag: {@code "runner"} or {@code "admin"}. */
    public String minRole;
    public String team;
    public String createdAt;
    public String updatedAt;
}
