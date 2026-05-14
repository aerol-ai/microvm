package ai.aerol.microvm.model;

import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SandboxSnapshot {
    public String name;
    public String image;
    @JsonProperty("image_id")
    public String imageId;
    @JsonProperty("source_sandbox_id")
    public String sourceSandboxId;
    @JsonProperty("created_at")
    public Instant createdAt;

    public SandboxSnapshot setName(String name) {
        this.name = name;
        return this;
    }

    public SandboxSnapshot setImage(String image) {
        this.image = image;
        return this;
    }

    public SandboxSnapshot setImageId(String imageId) {
        this.imageId = imageId;
        return this;
    }

    public SandboxSnapshot setSourceSandboxId(String sourceSandboxId) {
        this.sourceSandboxId = sourceSandboxId;
        return this;
    }

    public SandboxSnapshot setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
        return this;
    }
}