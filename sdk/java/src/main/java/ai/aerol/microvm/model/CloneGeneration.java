package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Clone-generation marker for a sandbox.
 *
 * <p>The {@code generation} token changes every time the sandbox is resumed
 * from a snapshot (i.e. it is a clone). A long-lived process running
 * <em>inside</em> the sandbox can poll this and reseed its own userspace PRNGs
 * when the token changes — two clones otherwise share the snapshot's frozen
 * seed state. Read-only: the SDK cannot reseed an in-guest process from the
 * client side. See the "Randomness in cloned sandboxes" docs page.
 */
public class CloneGeneration {
    /** Opaque token that changes on every resume-from-snapshot. */
    public String generation = "";

    /** Host wall-clock of the last resume, in unix nanoseconds. 0 = never resumed. */
    @JsonProperty("resumed_at")
    public long resumedAt;
}
