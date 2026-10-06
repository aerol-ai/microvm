package ai.aerol.microvm.model;

import java.util.ArrayList;
import java.util.List;

/**
 * A sandbox's whole egress policy, for {@code setNetworkPolicy}. It replaces
 * the current policy: a field left unset is cleared, so a fresh instance means
 * open egress. The grammar is the create one (hostnames, {@code *.} wildcards,
 * {@code host:port} and CIDRs in the allow list; CIDRs only in the deny list).
 */
public class NetworkPolicyOptions {
    private boolean networkBlockAll;
    private List<String> networkAllowOut = new ArrayList<>();
    private List<String> networkDenyOut = new ArrayList<>();
    private List<String> egressProfiles = new ArrayList<>();
    private String networkEgressMode;
    private List<EgressRule> networkEgressRules = new ArrayList<>();

    public boolean getNetworkBlockAll() {
        return networkBlockAll;
    }

    public NetworkPolicyOptions setNetworkBlockAll(boolean networkBlockAll) {
        this.networkBlockAll = networkBlockAll;
        return this;
    }

    public List<String> getNetworkAllowOut() {
        return networkAllowOut;
    }

    public NetworkPolicyOptions setNetworkAllowOut(List<String> networkAllowOut) {
        this.networkAllowOut = networkAllowOut == null ? new ArrayList<>() : networkAllowOut;
        return this;
    }

    public List<String> getNetworkDenyOut() {
        return networkDenyOut;
    }

    public NetworkPolicyOptions setNetworkDenyOut(List<String> networkDenyOut) {
        this.networkDenyOut = networkDenyOut == null ? new ArrayList<>() : networkDenyOut;
        return this;
    }

    public List<String> getEgressProfiles() {
        return egressProfiles;
    }

    public NetworkPolicyOptions setEgressProfiles(List<String> egressProfiles) {
        this.egressProfiles = egressProfiles == null ? new ArrayList<>() : egressProfiles;
        return this;
    }

    /** "learn" for open egress that is recorded; null or "enforce" otherwise. */
    public String getNetworkEgressMode() {
        return networkEgressMode;
    }

    public NetworkPolicyOptions setNetworkEgressMode(String networkEgressMode) {
        this.networkEgressMode = networkEgressMode;
        return this;
    }

    /**
     * Method and path rules; replaces the sandbox's. Adding an inspect rule to a
     * container sandbox created without one is refused with 409: recreate it
     * with the rule.
     */
    public List<EgressRule> getNetworkEgressRules() {
        return networkEgressRules;
    }

    public NetworkPolicyOptions setNetworkEgressRules(List<EgressRule> networkEgressRules) {
        this.networkEgressRules = networkEgressRules == null ? new ArrayList<>() : networkEgressRules;
        return this;
    }
}
