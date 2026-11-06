package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * One change a file watch reports. {@link #type} is one of the constants
 * below; a newer server may add types, so treat an unknown one as "something
 * changed". A rename shows as {@code rename} for the old name and
 * {@code create} for the new one.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FileEvent {
    public static final String CREATE = "create";
    public static final String WRITE = "write";
    public static final String REMOVE = "remove";
    public static final String RENAME = "rename";
    public static final String CHMOD = "chmod";
    /**
     * Some events were lost. List the folder again to catch up.
     * {@link #reason} says why: {@code kernel_queue}, {@code event_buffer}
     * or {@code watch_limit} (then {@link #path} is the folder that could
     * not be watched).
     */
    public static final String OVERFLOW = "overflow";

    public String type;
    /** The absolute path that changed; may be empty for an overflow. */
    public String path;
    public boolean isDir;
    /** Why events were lost; set on overflow events only. */
    public String reason;

    @Override
    public String toString() {
        return "FileEvent{type=" + type + ", path=" + path + ", isDir=" + isDir
            + (reason == null ? "" : ", reason=" + reason) + "}";
    }
}
