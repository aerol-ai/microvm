package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Request body for {@link ai.aerol.microvm.MicroVMClient#createWasmModule}.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CreateWasmModuleOptions {
    public String id;
    @JsonProperty("module_ref")
    public String moduleRef;
    public String entrypoint;

    public CreateWasmModuleOptions setId(String id) {
        this.id = id;
        return this;
    }

    public CreateWasmModuleOptions setModuleRef(String moduleRef) {
        this.moduleRef = moduleRef;
        return this;
    }

    public CreateWasmModuleOptions setEntrypoint(String entrypoint) {
        this.entrypoint = entrypoint;
        return this;
    }
}
