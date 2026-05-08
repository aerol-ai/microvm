package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class RegistryAuth {
    public String server;
    public String username;
    public String password;

    public RegistryAuth setServer(String server) {
        this.server = server;
        return this;
    }

    public RegistryAuth setUsername(String username) {
        this.username = username;
        return this;
    }

    public RegistryAuth setPassword(String password) {
        this.password = password;
        return this;
    }
}