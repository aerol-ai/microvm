package ai.aerol.microvm.model;

/** Options for a download. */
public class DownloadFileOptions {
    /**
     * Refuse a file larger than this many bytes: before reading when the
     * server states the size, otherwise as soon as more arrives. {@code null}
     * is no limit. A guard against a file larger than expected filling memory.
     */
    public Long maxBytes;

    public DownloadFileOptions setMaxBytes(Long maxBytes) {
        this.maxBytes = maxBytes;
        return this;
    }
}
