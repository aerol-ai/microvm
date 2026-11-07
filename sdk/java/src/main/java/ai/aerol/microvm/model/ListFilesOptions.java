package ai.aerol.microvm.model;

/** Options for {@code listFiles}. The defaults list one level, up to 10,000 entries. */
public class ListFilesOptions {
    /** Levels to go down; 1 (the default) is the folder's own entries. Symlinked folders are listed but never entered. */
    public int depth = 1;
    /** The most entries to return. */
    public int limit = 10_000;

    public ListFilesOptions setDepth(int depth) {
        this.depth = depth;
        return this;
    }

    public ListFilesOptions setLimit(int limit) {
        this.limit = limit;
        return this;
    }
}
