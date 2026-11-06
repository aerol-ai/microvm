package ai.aerol.microvm.model;

/**
 * How an upload writes its file. With none set, missing folders are made and
 * an existing file is replaced in place.
 */
public class UploadFileOptions {
    /** Add to the end of the file instead of replacing it. */
    public boolean append;
    /** Write only if the file does not exist yet (HTTP 412 otherwise). Of two uploads racing for one new path, exactly one wins. */
    public boolean createOnly;
    /** Write a temp file and rename it into place, so a reader never sees half a file. Cannot be combined with {@code append}. */
    public boolean atomic;
    /** Permissions such as {@code 0600}; {@code null} keeps an existing file's and gives a new one 0644. */
    public Integer mode;

    public UploadFileOptions setAppend(boolean append) {
        this.append = append;
        return this;
    }

    public UploadFileOptions setCreateOnly(boolean createOnly) {
        this.createOnly = createOnly;
        return this;
    }

    public UploadFileOptions setAtomic(boolean atomic) {
        this.atomic = atomic;
        return this;
    }

    public UploadFileOptions setMode(Integer mode) {
        this.mode = mode;
        return this;
    }
}
