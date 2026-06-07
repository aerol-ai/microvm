package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Catalogue lifecycle for POST /v1/wasm-modules rows.
 */
public enum WasmModuleStatus {
    @JsonProperty("ready")
    READY,
    @JsonProperty("failed")
    FAILED
}
