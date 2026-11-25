package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Fixed limits a runtime has, whatever the operator sets. */
public class RuntimeLimits {
    /**
     * The most memory, in MiB, a checkpoint can restore. A bigger sandbox
     * still runs, but cannot come back from a passivation or a move.
     * {@code null} when the runtime has no such limit.
     */
    @JsonProperty("max_checkpoint_memory_mb")
    public Integer maxCheckpointMemoryMb;
}
