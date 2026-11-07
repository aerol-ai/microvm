package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;

/**
 * The body of {@code sandbox.createToken()}: a signed token for one sandbox
 * that you can hand to a browser or an end user. Only {@code expiresIn} is
 * required; every other field narrows the token, and a field left unset
 * leaves that part unrestricted.
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class CreateSandboxTokenOptions {
    private String expiresIn;
    private Integer port;
    private String pathPrefix;
    private List<String> methods;

    public String getExpiresIn() {
        return expiresIn;
    }

    /** Required lifetime: {@code "15m"}, {@code "2h"} or {@code "1d"}. The server caps it (24 hours by default). */
    public CreateSandboxTokenOptions setExpiresIn(String expiresIn) {
        this.expiresIn = expiresIn;
        return this;
    }

    public Integer getPort() {
        return port;
    }

    /**
     * A port token opens that port's public URL (a port exposed with token
     * visibility). Without a port the token is for the sandbox's toolbox:
     * commands, files and terminal sessions.
     */
    public CreateSandboxTokenOptions setPort(Integer port) {
        this.port = port;
        return this;
    }

    public String getPathPrefix() {
        return pathPrefix;
    }

    /** Only paths under this one, for example {@code "/files"} (toolbox) or {@code "/app"} (public URL). */
    public CreateSandboxTokenOptions setPathPrefix(String pathPrefix) {
        this.pathPrefix = pathPrefix;
        return this;
    }

    public List<String> getMethods() {
        return methods;
    }

    /** Only these HTTP methods, for example {@code List.of("GET")}. */
    public CreateSandboxTokenOptions setMethods(List<String> methods) {
        this.methods = methods;
        return this;
    }
}
