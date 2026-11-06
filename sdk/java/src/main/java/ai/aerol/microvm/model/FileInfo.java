package ai.aerol.microvm.model;

/** One file, folder or symlink in a sandbox. */
public class FileInfo {
    public String name;
    /** The full path in the sandbox. */
    public String path;
    public boolean isDir;
    /** Bytes. */
    public long size;
    /** Type and permission string, such as {@code -rw-r--r--}. */
    public String mode;
    /** Octal permission bits, such as {@code 0644}. */
    public String permissions;
    public String owner;
    public String group;
    /** Last change time, RFC 3339 in UTC. */
    public String modTime;
    /**
     * Where a symlink points, or {@code null}. Only on {@code listFiles}
     * entries: {@code getFileInfo} follows a symlink and describes what it
     * names.
     */
    public String symlinkTarget;
}
