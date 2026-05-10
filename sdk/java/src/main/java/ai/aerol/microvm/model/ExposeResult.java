package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Outcome of a successful expose call. {@link #host} and {@link #hostPort}
 * are populated only when {@link #protocol} is {@link ExposeProtocol#TCP} —
 * native protocol clients (psql, redis-cli, mysql, mongosh) need them to
 * dial. For HTTP and TLS exposures the dialable URL is in {@link #url}.
 */
public class ExposeResult {
    public ExposeProtocol protocol;
    @JsonProperty("public_url")
    public String url;
    public String host;
    @JsonProperty("host_port")
    public Integer hostPort;
}
