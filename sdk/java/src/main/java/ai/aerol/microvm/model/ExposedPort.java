package ai.aerol.microvm.model;

import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ExposedPort {
    @JsonProperty("sandbox_id")
    public String sandboxId;
    public int port;
    @JsonProperty("public_url")
    public String publicUrl;
    public Instant createdAt;
}