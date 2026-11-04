package ai.aerol.microvm;

import java.net.http.HttpClient;

public class MicroVMConfig {
    /**
     * The bearer every request carries: the operator PAT, an {@code avm_} API
     * token or an OIDC ID token. Null or blank falls back to
     * {@code SB_PAT_TOKEN}, then to its alias {@code SB_API_TOKEN}; when both
     * are set, {@code SB_PAT_TOKEN} wins.
     */
    public String patToken;
    public String apiUrl;
    public HttpClient httpClient;
    /**
     * The team requests act for, sent as the {@code X-AerolVM-Team} header on
     * every request, WebSocket handshakes included. Null or blank falls back
     * to {@code SB_TEAM}; with neither, no header is sent and the server uses
     * the credential's first matching binding. The header only chooses among
     * teams the credential is already bound to: a team it does not hold is
     * refused (403), and the operator PAT ignores it.
     */
    public String team;
    /**
     * Wire version of the sandbox daemon API to call. Defaults to "v1" when
     * null/empty. The Java SDK package version and the API wire version
     * evolve independently — bumping this SDK does not move the wire
     * version.
     */
    public String apiVersion;
    public ai.aerol.microvm.model.RetryConfig retry;

    public MicroVMConfig setPatToken(String patToken) {
        this.patToken = patToken;
        return this;
    }

    public MicroVMConfig setApiUrl(String apiUrl) {
        this.apiUrl = apiUrl;
        return this;
    }

    public MicroVMConfig setHttpClient(HttpClient httpClient) {
        this.httpClient = httpClient;
        return this;
    }

    public MicroVMConfig setTeam(String team) {
        this.team = team;
        return this;
    }

    public MicroVMConfig setApiVersion(String apiVersion) {
        this.apiVersion = apiVersion;
        return this;
    }

    public MicroVMConfig setRetry(ai.aerol.microvm.model.RetryConfig retry) {
        this.retry = retry;
        return this;
    }
}