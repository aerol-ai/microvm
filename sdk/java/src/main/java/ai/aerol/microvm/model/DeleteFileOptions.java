package ai.aerol.microvm.model;

/** Options for {@code deleteFile}. */
public class DeleteFileOptions {
    /** Delete a folder and everything in it. Without it a folder is refused (HTTP 409). */
    public boolean recursive;

    public DeleteFileOptions setRecursive(boolean recursive) {
        this.recursive = recursive;
        return this;
    }
}
