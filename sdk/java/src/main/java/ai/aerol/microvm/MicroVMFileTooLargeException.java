package ai.aerol.microvm;

/**
 * A download was larger than its {@code maxBytes}. Thrown before reading when
 * the server states the size, otherwise as soon as more arrives.
 */
public class MicroVMFileTooLargeException extends MicroVMException {
    private final String path;
    private final long maxBytes;

    public MicroVMFileTooLargeException(String path, long maxBytes) {
        super(path + " is larger than maxBytes (" + maxBytes + " bytes)");
        this.path = path;
        this.maxBytes = maxBytes;
    }

    public String getPath() {
        return path;
    }

    public long getMaxBytes() {
        return maxBytes;
    }
}
