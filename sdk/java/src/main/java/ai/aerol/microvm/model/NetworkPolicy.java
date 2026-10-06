package ai.aerol.microvm.model;

import java.util.ArrayList;
import java.util.List;

/** The policy a sandbox enforces after {@code setNetworkPolicy}. */
public class NetworkPolicy {
    public boolean networkBlockAll;
    public List<String> networkAllowOut = new ArrayList<>();
    public List<String> networkDenyOut = new ArrayList<>();
    /** "active", "held" or "unavailable" for hostname rules on a container, or null. */
    public String egressStatus;
}
