package ai.aerol.microvm.model;

import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A WASM module catalogue entry on the host. Build with
 * {@link ai.aerol.microvm.MicroVMClient#createWasmModule}.
 */
public class WasmModule {
    public String id;
    @JsonProperty("module_ref")
    public String moduleRef;
    public WasmModuleStatus status;
    @JsonProperty("module_size_bytes")
    public Long moduleSizeBytes;
    public String digest;
    public String entrypoint;
    @JsonProperty("has_warm")
    public boolean hasWarm;
    @JsonProperty("last_error")
    public String lastError;
    @JsonProperty("created_at")
    public Instant createdAt;
    @JsonProperty("updated_at")
    public Instant updatedAt;
    @JsonProperty("ready_at")
    public Instant readyAt;
}
