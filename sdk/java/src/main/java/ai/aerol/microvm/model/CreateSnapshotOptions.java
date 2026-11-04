package ai.aerol.microvm.model;

/**
 * Options for {@code createSnapshot}.
 */
public class CreateSnapshotOptions {
    /**
     * Whether the snapshot may pause a running sandbox. {@code null} (the
     * default) or {@code true}: a running sandbox is paused while it is copied
     * (its disk writes wait; Docker pauses the container) and keeps running
     * afterwards. {@code false}: a sandbox that is not stopped is refused with
     * HTTP 409 instead, for a workload that must never stall.
     */
    public Boolean allowPause;

    public CreateSnapshotOptions setAllowPause(Boolean allowPause) {
        this.allowPause = allowPause;
        return this;
    }
}
