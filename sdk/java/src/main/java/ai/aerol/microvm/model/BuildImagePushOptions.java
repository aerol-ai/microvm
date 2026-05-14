package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Per-request push directive for {@code MicroVMClient.buildImage(Image, BuildImageOptions)}.
 * Credentials are forwarded to the daemon as a one-shot {@code X-Registry-Auth}
 * header on the underlying push call and are never persisted server-side.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class BuildImagePushOptions {
    /** Destination repository, e.g. {@code "ghcr.io/my-org/my-image"}. Required. */
    public String registry;
    /** Destination tag. Defaults to {@code "latest"} on the daemon when null/empty. */
    public String tag;
    /** Registry serveraddress (e.g. {@code "ghcr.io"}). Sent inside X-Registry-Auth. */
    public String server;
    public String username;
    public String password;

    public BuildImagePushOptions setRegistry(String registry) {
        this.registry = registry;
        return this;
    }

    public BuildImagePushOptions setTag(String tag) {
        this.tag = tag;
        return this;
    }

    public BuildImagePushOptions setServer(String server) {
        this.server = server;
        return this;
    }

    public BuildImagePushOptions setUsername(String username) {
        this.username = username;
        return this;
    }

    public BuildImagePushOptions setPassword(String password) {
        this.password = password;
        return this;
    }
}
