package ai.aerol.microvm.model;

/**
 * The body of {@code putWarmPool}: a full replace. Set {@code depth} for a
 * fixed size, or {@code minDepth} and {@code maxDepth} to follow demand, not
 * both.
 */
public class WarmPoolOptions {
    private int depth;
    private int minDepth;
    private int maxDepth;

    /** Warm slots each server keeps for this image (0 to 128). */
    public int getDepth() {
        return depth;
    }

    public WarmPoolOptions setDepth(int depth) {
        this.depth = depth;
        return this;
    }

    /** The fewest warm slots a server keeps when demand is low (0 lets it reach zero). */
    public int getMinDepth() {
        return minDepth;
    }

    public WarmPoolOptions setMinDepth(int minDepth) {
        this.minDepth = minDepth;
        return this;
    }

    /** The most warm slots a server keeps when demand is high (1 to 128). */
    public int getMaxDepth() {
        return maxDepth;
    }

    public WarmPoolOptions setMaxDepth(int maxDepth) {
        this.maxDepth = maxDepth;
        return this;
    }
}
