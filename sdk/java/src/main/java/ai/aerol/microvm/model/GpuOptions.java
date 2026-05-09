package ai.aerol.microvm.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * GPU resources to attach to a sandbox at creation time. Not compatible with
 * runtime="gvisor" — the API returns an error if both gpus and
 * runtime="gvisor" are set.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GpuOptions {
    /**
     * GPU hardware vendor. Required. Allowed values:
     * <ul>
     *   <li>"nvidia" — NVIDIA GPUs via nvidia-container-runtime. Requires
     *       nvidia-container-toolkit on the host.</li>
     *   <li>"amd" — AMD GPUs via ROCm (/dev/kfd + /dev/dri). Requires ROCm
     *       drivers on the host.</li>
     *   <li>"apple" — Apple Silicon GPU via Docker Desktop's experimental Metal
     *       support. Only functional on macOS with Docker Desktop.</li>
     * </ul>
     */
    public String vendor;

    /**
     * Number of GPUs to allocate. Use -1 to request all GPUs on the host.
     * Omit or set 0 for the default (1 GPU). Ignored for AMD (all AMD GPUs on
     * the host are exposed via /dev/kfd and /dev/dri).
     */
    public Integer count;

    /**
     * Pin the sandbox to specific GPU device indices or UUIDs. For NVIDIA:
     * indices ("0", "1") or UUIDs ("GPU-abc123..."). For AMD and Apple: ignored.
     */
    @JsonProperty("device_ids")
    public List<String> deviceIds;

    public GpuOptions setVendor(String vendor) {
        this.vendor = vendor;
        return this;
    }

    public GpuOptions setCount(Integer count) {
        this.count = count;
        return this;
    }

    public GpuOptions setDeviceIds(List<String> deviceIds) {
        this.deviceIds = deviceIds;
        return this;
    }

    public GpuOptions copy() {
        return new GpuOptions()
            .setVendor(vendor)
            .setCount(count)
            .setDeviceIds(deviceIds == null ? null : new java.util.ArrayList<>(deviceIds));
    }
}
