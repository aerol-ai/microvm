package ai.aerol.microvm;

import java.net.http.HttpClient;

public class MicroVMConfig {
    public String patToken;
    public String apiUrl;
    public HttpClient httpClient;

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
}