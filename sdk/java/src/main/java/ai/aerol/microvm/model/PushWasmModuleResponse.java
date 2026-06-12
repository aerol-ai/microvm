package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Result of {@link ai.aerol.microvm.MicroVMClient#pushWasmModule}.
 */
public class PushWasmModuleResponse {
    /** The {@code oci://} ref to pass as {@code moduleRef} on create. */
    @JsonProperty("module_ref")
    public String moduleRef;
    /** sha256 content digest of the uploaded module. */
    public String digest;
    /** Uploaded size in bytes. */
    @JsonProperty("size_bytes")
    public long sizeBytes;
}
