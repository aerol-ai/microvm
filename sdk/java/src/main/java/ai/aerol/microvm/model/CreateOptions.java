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
    /** Egress allowlist of CIDRs; sandbox may reach only these. Mutually exclusive with networkDenyOut. */
    @JsonProperty("network_allow_out")
    public List<String> networkAllowOut;
    /** Egress blocklist of CIDRs; sandbox may reach anything except these. Mutually exclusive with networkAllowOut. */
    @JsonProperty("network_deny_out")
    public List<String> networkDenyOut;
    /** Whether the sandbox may be exposed publicly. Omitted defaults to private; true opts in; false permanently refuses exposePort. */
    @JsonProperty("allow_public_traffic")
    public Boolean allowPublicTraffic;
    /** Rewrite the upstream Host header on ingress to exposed HTTP ports to this value
     * so frameworks that validate Host (Vite, Django, webpack-dev-server) accept the
     * request. Null/empty passes it through. HTTP-only; TCP/TLS exposures ignore it. */
    @JsonProperty("mask_request_host")
    public String maskRequestHost;
    @JsonProperty("network_bytes_in_limit")
    public Long networkBytesInLimit;
    @JsonProperty("network_bytes_out_limit")
    public Long networkBytesOutLimit;
    public RegistryAuth registry;
    public List<String> containerCommand;
    public List<MountSpec> mounts;
    /** Named, operator-backed persistent volumes to attach by name. Requires the
     * operator to have enabled platform volumes (else the create returns 412). */
    @JsonProperty("platform_volumes")
    public List<PlatformVolumeMount> platformVolumes;
    public Lifecycle lifecycle;
    public Failover failover;
    public String runtime;
    /** Survival class across daemon restarts. Null uses the runtime default. */
    public String durability;
    /** WASM module / isolate bundle reference. When runtime is wasm or isolate, may be used instead of image. */
    @JsonProperty("module_ref")
    public String moduleRef;
    /**
     * Isolate-group key for {@code runtime=isolate}. Server-authorized; when
     * omitted the group key falls back to the authenticated identity. Ignored
     * by other runtimes.
     */
    @JsonProperty("tenant_id")
    public String tenantId;
    /** Attach GPU resources to the sandbox. Null means no GPU (CPU-only). */
    public GpuOptions gpus;
    /**
     * Operator-supplied hostnames to attach to the sandbox's HTTP entrypoint
     * at creation time. Each entry travels through the same lifecycle as
     * {@link ai.aerol.microvm.MicroVMClient#addCustomDomain(String, String)}
     * (pending_dns → issuing → ready). The server lowercases each entry on
     * write.
     */
    @JsonProperty("custom_domains")
    public List<String> customDomains;

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

    public CreateOptions setNetworkAllowOut(List<String> networkAllowOut) {
        this.networkAllowOut = networkAllowOut;
        return this;
    }

    public CreateOptions setNetworkDenyOut(List<String> networkDenyOut) {
        this.networkDenyOut = networkDenyOut;
        return this;
    }

    public CreateOptions setAllowPublicTraffic(Boolean allowPublicTraffic) {
        this.allowPublicTraffic = allowPublicTraffic;
        return this;
    }

    public CreateOptions setMaskRequestHost(String maskRequestHost) {
        this.maskRequestHost = maskRequestHost;
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

    public CreateOptions setPlatformVolumes(List<PlatformVolumeMount> platformVolumes) {
        this.platformVolumes = platformVolumes;
        return this;
    }

    public CreateOptions setLifecycle(Lifecycle lifecycle) {
        this.lifecycle = lifecycle;
        return this;
    }

    public CreateOptions setFailover(Failover failover) {
        this.failover = failover;
        return this;
    }

    public CreateOptions setRuntime(String runtime) {
        this.runtime = runtime;
        return this;
    }

    public CreateOptions setDurability(String durability) {
        this.durability = durability;
        return this;
    }

    public CreateOptions setModuleRef(String moduleRef) {
        this.moduleRef = moduleRef;
        return this;
    }

    public CreateOptions setTenantId(String tenantId) {
        this.tenantId = tenantId;
        return this;
    }

    public CreateOptions setGpus(GpuOptions gpus) {
        this.gpus = gpus;
        return this;
    }

    public CreateOptions setCustomDomains(List<String> customDomains) {
        this.customDomains = customDomains;
        return this;
    }
}
