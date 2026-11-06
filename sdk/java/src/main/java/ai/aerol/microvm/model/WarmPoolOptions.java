package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * The body of {@code putWarmPool}: a full replace. Set {@code depth} for a
 * fixed size, or {@code minDepth} and {@code maxDepth} to follow demand, not
 * both.
 */
public class WarmPoolOptions {
    /** Swap every waiting sandbox for one on the new image at once (the default). */
    public static final String REPLACE_NOW = "replace_now";
    /** Keep handing out the old waiting sandboxes, and replace each as it is used. */
    public static final String REPLACE_AS_USED = "replace_as_used";

    private int depth;
    private int minDepth;
    private int maxDepth;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String onImageChange;

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

    /** What happens to warm sandboxes when the image changes; null is {@link #REPLACE_NOW}. */
    public String getOnImageChange() {
        return onImageChange;
    }

    public WarmPoolOptions setOnImageChange(String onImageChange) {
        this.onImageChange = onImageChange;
        return this;
    }
}
