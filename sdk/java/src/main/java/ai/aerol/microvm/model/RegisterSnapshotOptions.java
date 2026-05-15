package ai.aerol.microvm.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class RegisterSnapshotOptions {
    public String name;
    public String image;
    @JsonProperty("dockerfile_content")
    public String dockerfileContent;
    @JsonProperty("context_hashes")
    public List<String> contextHashes;
    public List<String> entrypoint;
    @JsonProperty("region_id")
    public String regionId;
    public Double cpu;
    public Double gpu;
    @JsonProperty("memory_mb")
    public Integer memoryMb;
    @JsonProperty("disk_gb")
    public Integer diskGb;

    public RegisterSnapshotOptions setName(String name) {
        this.name = name;
        return this;
    }

    public RegisterSnapshotOptions setImage(String image) {
        this.image = image;
        return this;
    }

    public RegisterSnapshotOptions setDockerfileContent(String dockerfileContent) {
        this.dockerfileContent = dockerfileContent;
        return this;
    }

    public RegisterSnapshotOptions setContextHashes(List<String> contextHashes) {
        this.contextHashes = contextHashes;
        return this;
    }

    public RegisterSnapshotOptions setEntrypoint(List<String> entrypoint) {
        this.entrypoint = entrypoint;
        return this;
    }

    public RegisterSnapshotOptions setRegionId(String regionId) {
        this.regionId = regionId;
        return this;
    }

    public RegisterSnapshotOptions setCpu(Double cpu) {
        this.cpu = cpu;
        return this;
    }

    public RegisterSnapshotOptions setGpu(Double gpu) {
        this.gpu = gpu;
        return this;
    }

    public RegisterSnapshotOptions setMemoryMb(Integer memoryMb) {
        this.memoryMb = memoryMb;
        return this;
    }

    public RegisterSnapshotOptions setDiskGb(Integer diskGb) {
        this.diskGb = diskGb;
        return this;
    }
}