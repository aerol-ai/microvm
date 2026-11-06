package ai.aerol.microvm.model;

/** One server's pool for an image. */
public class WarmPoolServerStatus {
    public String nodeId;
    public int ready;
    public int target;
    /** The server's last report is too old to trust; the numbers are its last ones. */
    public boolean stale;
}
