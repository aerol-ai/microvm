package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * What a runtime can do, as {@code client.runtimes().list()} reports it.
 * The warm pool is what the runtime can use; the operator decides whether
 * one runs.
 */
public class RuntimeFeatures {
    /** A snapshot saves the sandbox as a named image that new sandboxes can start from. */
    public boolean snapshots;
    /** A stop keeps memory and running programs, and the next start resumes them. */
    public boolean pause;
    /**
     * What a sandbox keeps when the cluster moves it to another node:
     * {@code "memory"} (running programs and memory), {@code "disk"} (files
     * only) or {@code "none"}.
     */
    public String moves;
    /**
     * How a create can start warm: {@code "snapshot"} (a VM restored from a
     * saved memory snapshot), {@code "parked"} (a sandbox started ahead of
     * time) or {@code "none"} (every create starts cold).
     */
    @JsonProperty("warm_pool")
    public String warmPool;
    /** Memory is sealed from the host. No runtime offers this yet. */
    public boolean confidential;
}
