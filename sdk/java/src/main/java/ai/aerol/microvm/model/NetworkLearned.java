package ai.aerol.microvm.model;

import java.util.ArrayList;
import java.util.List;

/**
 * What a sandbox reached in learn mode, and the allow list that would have
 * allowed it: {@code suggestedAllowOut} when it fits 64 hostnames, otherwise
 * {@code suggestedProfile} (a body for {@code putEgressProfile}).
 */
public class NetworkLearned {
    public String mode;
    /** Recording stopped at its cap. */
    public boolean truncated;
    public List<NetworkLearnedEntry> entries = new ArrayList<>();
    public List<String> cidrs = new ArrayList<>();
    public List<String> suggestedAllowOut = new ArrayList<>();
    public EgressProfile suggestedProfile;
}
