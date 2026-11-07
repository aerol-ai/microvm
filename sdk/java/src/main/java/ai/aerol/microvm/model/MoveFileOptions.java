package ai.aerol.microvm.model;

/** Options for {@code moveFile}. */
public class MoveFileOptions {
    /** Replace an existing destination. Without it an existing destination is refused (HTTP 409). */
    public boolean overwrite;

    public MoveFileOptions setOverwrite(boolean overwrite) {
        this.overwrite = overwrite;
        return this;
    }
}
