package ai.aerol.microvm.model;

/** The body of {@code putWarmPool}: a full replace. */
public class WarmPoolOptions {
    private int depth;

    /** Warm slots each server keeps for this image (0 to 128). */
    public int getDepth() {
        return depth;
    }

    public WarmPoolOptions setDepth(int depth) {
        this.depth = depth;
        return this;
    }
}
