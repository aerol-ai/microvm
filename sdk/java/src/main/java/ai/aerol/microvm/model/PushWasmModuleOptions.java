package ai.aerol.microvm.model;

/**
 * Input for {@link ai.aerol.microvm.MicroVMClient#pushWasmModule}: a BYO
 * compiled core-wasip1 upload. The daemon validates and forwards the bytes to
 * the registry under your own credentials; it never stores them.
 */
public class PushWasmModuleOptions {
    /** Target repository path, e.g. {@code tenant/my-app}. */
    public String name;
    /** Image tag; defaults to {@code latest} when null/blank. */
    public String tag;
    /** The compiled core-wasip1 module bytes. */
    public byte[] module;
    /** Registry login (your AOCR username). */
    public String registryUsername;
    /** Registry token (your AOCR PAT). Required. */
    public String registryToken;

    public PushWasmModuleOptions setName(String name) {
        this.name = name;
        return this;
    }

    public PushWasmModuleOptions setTag(String tag) {
        this.tag = tag;
        return this;
    }

    public PushWasmModuleOptions setModule(byte[] module) {
        this.module = module;
        return this;
    }

    public PushWasmModuleOptions setRegistryUsername(String registryUsername) {
        this.registryUsername = registryUsername;
        return this;
    }

    public PushWasmModuleOptions setRegistryToken(String registryToken) {
        this.registryToken = registryToken;
        return this;
    }

    public String getName() {
        return name;
    }

    public String getTag() {
        return tag;
    }

    public byte[] getModule() {
        return module;
    }

    public String getRegistryUsername() {
        return registryUsername;
    }

    public String getRegistryToken() {
        return registryToken;
    }
}
