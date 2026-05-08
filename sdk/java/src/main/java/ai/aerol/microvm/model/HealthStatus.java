package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class HealthStatus {
    public String status;
    public int sandboxes;
    public String docker;
    public String caddy;
    @JsonProperty("ssh_gateway")
    public String sshGateway = "";
    public String version;
}