package ai.aerol.microvm.model;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class CreateOptions {
    public String image;
    public Double cpu;
    @JsonProperty("memory_mb")
    public Integer memoryMb;
    @JsonProperty("disk_gb")
    public Integer diskGb;
    public Map<String, String> env;
    public String osUser;
    public Boolean networkBlockAll;
    @JsonProperty("network_bytes_in_limit")
    public Long networkBytesInLimit;
    @JsonProperty("network_bytes_out_limit")
    public Long networkBytesOutLimit;
    public RegistryAuth registry;
    public List<String> containerCommand;
    public List<MountSpec> mounts;
    public Lifecycle lifecycle;
    public String runtime;
    /** Attach GPU resources to the sandbox. Null means no GPU (CPU-only). */
    public GpuOptions gpus;

    public CreateOptions setImage(String image) {
        this.image = image;
        return this;
    }

    public CreateOptions setCpu(Double cpu) {
        this.cpu = cpu;
        return this;
    }

    public CreateOptions setMemoryMb(Integer memoryMb) {
        this.memoryMb = memoryMb;
        return this;
    }

    public CreateOptions setDiskGb(Integer diskGb) {
        this.diskGb = diskGb;
        return this;
    }

    public CreateOptions setEnv(Map<String, String> env) {
        this.env = env;
        return this;
    }

    public CreateOptions setOsUser(String osUser) {
        this.osUser = osUser;
        return this;
    }

    public CreateOptions setNetworkBlockAll(Boolean networkBlockAll) {
        this.networkBlockAll = networkBlockAll;
        return this;
    }

    public CreateOptions setNetworkBytesInLimit(Long networkBytesInLimit) {
        this.networkBytesInLimit = networkBytesInLimit;
        return this;
    }

    public CreateOptions setNetworkBytesOutLimit(Long networkBytesOutLimit) {
        this.networkBytesOutLimit = networkBytesOutLimit;
        return this;
    }

    public CreateOptions setRegistry(RegistryAuth registry) {
        this.registry = registry;
        return this;
    }

    public CreateOptions setContainerCommand(List<String> containerCommand) {
        this.containerCommand = containerCommand;
        return this;
    }

    public CreateOptions setMounts(List<MountSpec> mounts) {
        this.mounts = mounts;
        return this;
    }

    public CreateOptions setLifecycle(Lifecycle lifecycle) {
        this.lifecycle = lifecycle;
        return this;
    }

    public CreateOptions setRuntime(String runtime) {
        this.runtime = runtime;
        return this;
    }

    public CreateOptions setGpus(GpuOptions gpus) {
        this.gpus = gpus;
        return this;
    }
}