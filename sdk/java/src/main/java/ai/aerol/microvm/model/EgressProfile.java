package ai.aerol.microvm.model;

import java.util.ArrayList;
import java.util.List;

/**
 * A named allowlist sandboxes reference through {@code egressProfiles}.
 * Profiles belong to your account; {@code generation} goes up on every change.
 */
public class EgressProfile {
    public String name;
    /** Hostnames, {@code *.} wildcards, {@code host:port} entries and CIDRs (at most 512 hostnames). */
    public List<String> allowOut = new ArrayList<>();
    public String description;
    public long generation;
    public String createdAt;
    public String updatedAt;
}
