package ai.aerol.microvm.model;

/** Options for {@code copyFile}. */
public class CopyFileOptions {
    /** Replace an existing destination. Without it an existing destination is refused (HTTP 409). */
    public boolean overwrite;
    /** Copy a folder and everything in it, keeping modes and symlinks. Without it a folder is refused (HTTP 409). */
    public boolean recursive;

    public CopyFileOptions setOverwrite(boolean overwrite) {
        this.overwrite = overwrite;
        return this;
    }

    public CopyFileOptions setRecursive(boolean recursive) {
        this.recursive = recursive;
        return this;
    }
}
