package ai.aerol.microvm.model;

/** Options for {@code watchFiles}. */
public class WatchOptions {
    /** Also watch every folder below the path, and new ones as they appear. */
    public boolean recursive;

    public WatchOptions setRecursive(boolean recursive) {
        this.recursive = recursive;
        return this;
    }
}
