package ai.aerol.microvm.model;

/**
 * A warm-pool entry: how many ready sandboxes every server with a warm pool
 * keeps for one image. The server's {@code SB_DOCKER_POOL_*} /
 * {@code SB_CONTAINERD_POOL_*} settings stay the default for every other
 * image. Admin only.
 */
public class WarmPool {
    /** The image, exactly as creates name it ({@code python:3.12}, {@code ghcr.io/acme/agent:1}). */
    public String image;
    /** Warm slots each server keeps for this image; 0 turns warming off for it. */
    public int depth;
    /**
     * With {@code maxDepth}, each server sets its own target from recent
     * demand, never below {@code minDepth} and never above {@code maxDepth}.
     */
    public int minDepth;
    public int maxDepth;
    /** What happens to warm sandboxes when the image changes: {@code replace_now} or {@code replace_as_used}. */
    public String onImageChange;
    /** Goes up by one on every change; the same put twice leaves it alone. */
    public long generation;
    public String createdAt;
    public String updatedAt;
    /** How full the pools are. Set by {@code getWarmPool} and {@code listWarmPools}; null on a put. */
    public WarmPoolStatus status;
}
