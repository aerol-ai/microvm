package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ResizeOptions {
    public Double cpu;
    @JsonProperty("memory_mb")
    public Integer memoryMb;
    @JsonProperty("disk_gb")
    public Integer diskGb;

    public ResizeOptions setCpu(Double cpu) {
        this.cpu = cpu;
        return this;
    }

    public ResizeOptions setMemoryMb(Integer memoryMb) {
        this.memoryMb = memoryMb;
        return this;
    }

    public ResizeOptions setDiskGb(Integer diskGb) {
        this.diskGb = diskGb;
        return this;
    }
}