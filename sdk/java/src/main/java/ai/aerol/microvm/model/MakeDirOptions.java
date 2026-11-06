package ai.aerol.microvm.model;

/** Options for {@code makeDir}. */
public class MakeDirOptions {
    /** Also make missing parent folders, and accept an existing folder ({@code mkdir -p}). */
    public boolean parents;
    /** Permissions such as {@code 0750}; {@code null} means 0755. */
    public Integer mode;

    public MakeDirOptions setParents(boolean parents) {
        this.parents = parents;
        return this;
    }

    public MakeDirOptions setMode(Integer mode) {
        this.mode = mode;
        return this;
    }
}
