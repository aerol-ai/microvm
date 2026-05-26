package ai.aerol.microvm.model;

import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A Firecracker rootfs template. Created once from an OCI image and
 * boot-shared across many sandboxes. Build with
 * {@link ai.aerol.microvm.MicroVMClient#createTemplate}; poll
 * {@link ai.aerol.microvm.MicroVMClient#getTemplate} until {@code status}
 * reaches {@link TemplateStatus#READY} (fast-boot available) or
 * {@link TemplateStatus#READY_NO_SNAPSHOT} (cold boot only — see
 * {@code snapshotError}).
 */
public class Template {
    public String id;
    public String image;
    public TemplateStatus status;
    @JsonProperty("rootfs_size_bytes")
    public Long rootfsSizeBytes;
    @JsonProperty("min_size_mib")
    public Integer minSizeMib;
    @JsonProperty("last_error")
    public String lastError;
    @JsonProperty("created_at")
    public Instant createdAt;
    @JsonProperty("updated_at")
    public Instant updatedAt;
    @JsonProperty("ready_at")
    public Instant readyAt;
    @JsonProperty("snapshot_size_bytes")
    public Long snapshotSizeBytes;
    @JsonProperty("snapshot_error")
    public String snapshotError;
    @JsonProperty("has_snapshot")
    public boolean hasSnapshot;
    @JsonProperty("has_overlay")
    public boolean hasOverlay;
    @JsonProperty("push_state")
    public TemplatePushState pushState;
    @JsonProperty("push_error")
    public String pushError;
}
