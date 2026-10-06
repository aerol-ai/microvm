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
}
