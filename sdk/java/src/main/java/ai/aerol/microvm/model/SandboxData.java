package ai.aerol.microvm.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SandboxData {
    public String id;
    public String image;
    public String status;
    @JsonProperty("public_url")
    public String publicUrl;
    @JsonProperty("container_id")
    public String containerId;
    @JsonProperty("container_ip")
    public String containerIp;
    public double cpu;
    @JsonProperty("memory_mb")
    public int memoryMb;
    @JsonProperty("disk_gb")
    public int diskGb;
    public String osUser;
    public Map<String, String> env;
    public boolean networkBlockAll;
    public boolean toolboxEnabled;
    public String sshPublicKey;
    public String sshPrivateKey;
    public List<ExposedPort> exposedPorts;
    public Instant createdAt;
    public Instant updatedAt;
    public Instant lastActiveAt;
    public String lastError;
    public List<String> containerCommand;
    public Lifecycle lifecycle = new Lifecycle();
    public Failover failover;
    public String runtime = "";
    public String durability;
    /** GPU configuration this sandbox was created with. Null means no GPU. */
    public GpuOptions gpus;

    public SandboxData copy() {
        SandboxData copy = new SandboxData();
        copy.copyFrom(this);
        return copy;
    }

    public void copyFrom(SandboxData other) {
        if (other == null) {
            return;
        }
        id = other.id;
        image = other.image;
        status = other.status;
        publicUrl = other.publicUrl;
        containerId = other.containerId;
        containerIp = other.containerIp;
        cpu = other.cpu;
        memoryMb = other.memoryMb;
        diskGb = other.diskGb;
        osUser = other.osUser;
        env = other.env == null ? null : new LinkedHashMap<>(other.env);
        networkBlockAll = other.networkBlockAll;
        toolboxEnabled = other.toolboxEnabled;
        sshPublicKey = other.sshPublicKey;
        sshPrivateKey = other.sshPrivateKey;
        exposedPorts = other.exposedPorts == null ? null : new ArrayList<>(other.exposedPorts);
        createdAt = other.createdAt;
        updatedAt = other.updatedAt;
        lastActiveAt = other.lastActiveAt;
        lastError = other.lastError;
        containerCommand = other.containerCommand == null ? null : new ArrayList<>(other.containerCommand);
        lifecycle = other.lifecycle == null ? new Lifecycle() : other.lifecycle.copy();
        failover = other.failover == null ? null : other.failover.copy();
        runtime = other.runtime == null ? "" : other.runtime;
        durability = other.durability;
        gpus = other.gpus == null ? null : other.gpus.copy();
    }
}
