package ai.aerol.microvm.model;

import java.util.ArrayList;
import java.util.List;

/** The policy a sandbox enforces after {@code setNetworkPolicy}. */
public class NetworkPolicy {
    public boolean networkBlockAll;
    public List<String> networkAllowOut = new ArrayList<>();
    public List<String> networkDenyOut = new ArrayList<>();
    public List<String> egressProfiles = new ArrayList<>();
    /** Hostname entries in force: inline plus every profile's (at most 1024). */
    public int effectiveHostnameCount;
    /** "active", "held" or "unavailable" for hostname rules on a container, or null. */
    public String egressStatus;
}
