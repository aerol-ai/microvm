package ai.aerol.microvm.model;

import java.time.Instant;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SandboxSnapshot {
    public String name;
    public String image;
    @JsonProperty("image_id")
    public String imageId;
    @JsonProperty("source_sandbox_id")
    public String sourceSandboxId;
    @JsonProperty("created_at")
    public Instant createdAt;
    public List<String> entrypoint;
    @JsonProperty("region_id")
    public String regionId;
    public Double cpu;
    public Double gpu;
    @JsonProperty("memory_mb")
    public Integer memoryMb;
    @JsonProperty("disk_gb")
    public Integer diskGb;

    public SandboxSnapshot setName(String name) {
        this.name = name;
        return this;
    }

    public SandboxSnapshot setImage(String image) {
        this.image = image;
        return this;
    }

    public SandboxSnapshot setImageId(String imageId) {
        this.imageId = imageId;
        return this;
    }

    public SandboxSnapshot setSourceSandboxId(String sourceSandboxId) {
        this.sourceSandboxId = sourceSandboxId;
        return this;
    }

    public SandboxSnapshot setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
        return this;
    }

    public SandboxSnapshot setEntrypoint(List<String> entrypoint) {
        this.entrypoint = entrypoint;
        return this;
    }

    public SandboxSnapshot setRegionId(String regionId) {
        this.regionId = regionId;
        return this;
    }

    public SandboxSnapshot setCpu(Double cpu) {
        this.cpu = cpu;
        return this;
    }

    public SandboxSnapshot setGpu(Double gpu) {
        this.gpu = gpu;
        return this;
    }

    public SandboxSnapshot setMemoryMb(Integer memoryMb) {
        this.memoryMb = memoryMb;
        return this;
    }

    public SandboxSnapshot setDiskGb(Integer diskGb) {
        this.diskGb = diskGb;
        return this;
    }
}