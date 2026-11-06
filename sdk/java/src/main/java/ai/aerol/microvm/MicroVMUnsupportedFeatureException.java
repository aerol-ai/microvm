package ai.aerol.microvm;

import java.util.Collections;
import java.util.List;

/**
 * The sandbox's agent (toolboxd) is older than an option the call needs. An
 * older agent would silently ignore the option (an overwrite guard, an
 * output cap), so the SDK refuses instead of sending it. Restart the
 * sandbox, or re-create its Firecracker template, to get the current agent.
 * {@link #getFeatures()} lists what was missing.
 */
public class MicroVMUnsupportedFeatureException extends MicroVMException {
    private static final long serialVersionUID = 1L;

    private final String sandboxId;
    private final List<String> features;
    private final String agentVersion;
    private final String runtime;

    public MicroVMUnsupportedFeatureException(String sandboxId, List<String> features, String agentVersion) {
        this(sandboxId, features, agentVersion, "");
    }

    public MicroVMUnsupportedFeatureException(String sandboxId, List<String> features, String agentVersion, String runtime) {
        super(message(sandboxId, features, agentVersion, runtime));
        this.sandboxId = sandboxId;
        this.features = Collections.unmodifiableList(List.copyOf(features));
        this.agentVersion = agentVersion == null ? "" : agentVersion;
        this.runtime = runtime == null ? "" : runtime;
    }

    private static String message(String sandboxId, List<String> features, String agentVersion, String runtime) {
        if (runtime != null && !runtime.isEmpty()) {
            String name = "wasm".equals(runtime) ? "WebAssembly" : "isolate".equals(runtime) ? "V8 isolate" : runtime;
            return "sandbox " + sandboxId + " is a " + name + " sandbox, which does not support " + String.join(", ", features);
        }
        String agent = agentVersion == null || agentVersion.isEmpty() ? "an older toolboxd" : "toolboxd " + agentVersion;
        return "sandbox " + sandboxId + " runs " + agent + ", which does not support " + String.join(", ", features)
            + "; restart the sandbox, or re-create its Firecracker template, to get the current agent";
    }

    /** The sandbox whose agent is too old. */
    public String getSandboxId() {
        return sandboxId;
    }

    /** The features the agent did not list. */
    public List<String> getFeatures() {
        return features;
    }

    /** The agent's version, empty when it did not say. */
    public String getAgentVersion() {
        return agentVersion;
    }

    /**
     * Set (for example "wasm") when the sandbox's runtime cannot offer the
     * features at all; a restart does not help there. Empty otherwise.
     */
    public String getRuntime() {
        return runtime;
    }
}
