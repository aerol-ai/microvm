package ai.aerol.microvm;

/** What {@link MicroVMClient#getOrCreate(String, ai.aerol.microvm.model.CreateOptions)} found or made. */
public final class GetOrCreateResult {
    private final Sandbox sandbox;
    private final boolean created;

    GetOrCreateResult(Sandbox sandbox, boolean created) {
        this.sandbox = sandbox;
        this.created = created;
    }

    /** The sandbox with the requested name. */
    public Sandbox getSandbox() {
        return sandbox;
    }

    /** True only when this call created the sandbox. */
    public boolean isCreated() {
        return created;
    }
}
