package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A named, operator-backed persistent volume to attach by name. The operator
 * configures the shared backend (S3/NFS); the caller supplies nothing else.
 * Persists across the sandbox lifecycle and can be re-attached by name.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PlatformVolumeMount {
    public String name;
    public String path;
    @JsonProperty("read_only")
    public Boolean readOnly;
    /**
     * {@code true} deletes the volume (its files and its record) once the last
     * sandbox using it is deleted. It is set when the volume is first made; a
     * later sandbox naming the same volume must pass the same value, or the
     * create fails with HTTP 409. Null is false: the volume outlives its
     * sandboxes.
     */
    @JsonProperty("delete_with_sandbox")
    public Boolean deleteWithSandbox;

    public PlatformVolumeMount setName(String name) {
        this.name = name;
        return this;
    }

    public PlatformVolumeMount setPath(String path) {
        this.path = path;
        return this;
    }

    public PlatformVolumeMount setReadOnly(Boolean readOnly) {
        this.readOnly = readOnly;
        return this;
    }

    public PlatformVolumeMount setDeleteWithSandbox(Boolean deleteWithSandbox) {
        this.deleteWithSandbox = deleteWithSandbox;
        return this;
    }
}
