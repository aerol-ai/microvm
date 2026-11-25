package ai.aerol.microvm.model;

/**
 * One runtime as {@code client.runtimes().list()} returns it: a name you can
 * pass as {@code runtime} on create, what it can do, and whether this
 * deployment offers it now.
 */
public class RuntimeInfo {
    /** The name to pass on create, such as {@code "firecracker"} or {@code "gvisor"}. */
    public String name;
    /**
     * What stands between the sandbox and the server: {@code "container"},
     * {@code "user-space-kernel"}, {@code "hardware-vm"}, {@code "wasm"} or
     * {@code "v8-isolate"}.
     */
    public String isolation;
    /** The hardware a VM runtime runs on, such as {@code "kvm"}. {@code null} for runtimes that are not VMs. */
    public String backend;
    /** What the runtime can do. Never {@code null}. */
    public RuntimeFeatures features = new RuntimeFeatures();
    /** Fixed limits, or {@code null} when it has none. */
    public RuntimeLimits limits;
    /** True when at least one node that runs sandboxes offers it now. */
    public boolean available;
    /**
     * How many nodes offer it. The server sends this only to fleet admins;
     * for everyone else it is {@code null}. Node names are never sent.
     */
    public Integer nodes;
}
