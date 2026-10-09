package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;

/**
 * Asks whether a sandbox created with these egress fields would reach the
 * destination ("host", "host:port", "IP" or "IP:port").
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class NetworkPolicyCheckOptions {
    private Boolean networkBlockAll;
    private List<String> networkAllowOut;
    private List<String> networkDenyOut;
    private String destination;

    public Boolean getNetworkBlockAll() {
        return networkBlockAll;
    }

    public NetworkPolicyCheckOptions setNetworkBlockAll(Boolean networkBlockAll) {
        this.networkBlockAll = networkBlockAll;
        return this;
    }

    public List<String> getNetworkAllowOut() {
        return networkAllowOut;
    }

    public NetworkPolicyCheckOptions setNetworkAllowOut(List<String> networkAllowOut) {
        this.networkAllowOut = networkAllowOut;
        return this;
    }

    public List<String> getNetworkDenyOut() {
        return networkDenyOut;
    }

    public NetworkPolicyCheckOptions setNetworkDenyOut(List<String> networkDenyOut) {
        this.networkDenyOut = networkDenyOut;
        return this;
    }

    public String getDestination() {
        return destination;
    }

    public NetworkPolicyCheckOptions setDestination(String destination) {
        this.destination = destination;
        return this;
    }
}
