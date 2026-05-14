package ai.aerol.microvm;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import ai.aerol.microvm.internal.Environment;
import ai.aerol.microvm.internal.JavaNetWebSocketConnector;
import ai.aerol.microvm.internal.JsonSupport;
import ai.aerol.microvm.internal.StreamControlMessage;
import ai.aerol.microvm.internal.StreamingWebSocket;
import ai.aerol.microvm.internal.StreamingWebSocketListener;
import ai.aerol.microvm.internal.WebSocketConnector;
import ai.aerol.microvm.internal.api.v1.Paths;
import ai.aerol.microvm.model.CreateOptions;
import ai.aerol.microvm.model.CreateSessionOptions;
import ai.aerol.microvm.model.ExecExitInfo;
import ai.aerol.microvm.model.ExecRequest;
import ai.aerol.microvm.model.ExecResult;
import ai.aerol.microvm.model.ExecStreamOptions;
import ai.aerol.microvm.model.ExposeOptions;
import ai.aerol.microvm.model.ExposeProtocol;
import ai.aerol.microvm.model.ExposeResult;
import ai.aerol.microvm.model.HealthStatus;
import ai.aerol.microvm.model.Lifecycle;
import ai.aerol.microvm.model.MountSpecRedacted;
import ai.aerol.microvm.model.NetworkUsage;
import ai.aerol.microvm.model.ResizeOptions;
import ai.aerol.microvm.model.SandboxData;
import ai.aerol.microvm.model.SandboxSnapshot;
import ai.aerol.microvm.model.Session;
import ai.aerol.microvm.model.SessionAttachOptions;
import ai.aerol.microvm.model.SetNetworkLimitsOptions;

public class MicroVMClient {
    static final String DEFAULT_API_URL = "http://127.0.0.1:21212";
    static final String DEFAULT_API_VERSION = "v1";
    static final String AUTH_REQUIRED_ERROR_MESSAGE = "PAT token is required. Set patToken or SB_PAT_TOKEN.";
    private static final int STREAM_PREFIX_STDOUT = 0x01;
    private static final int STREAM_PREFIX_STDERR = 0x02;

    private static final java.util.Map<String, String> PATH_PREFIXES = java.util.Map.of(
        "v1", Paths.PATH_PREFIX
    );

    private final String apiUrl;
    private final String patToken;
    private final String apiVersion;
    private final String versionPrefix;
    private final HttpClient httpClient;
    private final WebSocketConnector webSocketConnector;

    public MicroVMClient() {
        this(new MicroVMConfig());
    }

    public MicroVMClient(MicroVMConfig config) {
        this(config, config != null ? config.httpClient : null, null, System::getenv);
    }

    MicroVMClient(MicroVMConfig config, HttpClient httpClient, WebSocketConnector webSocketConnector, Environment environment) {
        MicroVMConfig effectiveConfig = config == null ? new MicroVMConfig() : config;
        String configuredPatToken = trimToNull(effectiveConfig.patToken);
        String configuredApiUrl = trimToNull(effectiveConfig.apiUrl);
        String configuredApiVersion = trimToNull(effectiveConfig.apiVersion);
        String envPatToken = trimToNull(environment.get("SB_PAT_TOKEN"));
        String envApiUrl = trimToNull(environment.get("SB_API_URL"));

        this.patToken = configuredPatToken != null ? configuredPatToken : envPatToken != null ? envPatToken : "";
        this.apiUrl = normalizeUrl(configuredApiUrl != null ? configuredApiUrl : envApiUrl != null ? envApiUrl : DEFAULT_API_URL);
        this.apiVersion = configuredApiVersion != null ? configuredApiVersion : DEFAULT_API_VERSION;
        String prefix = PATH_PREFIXES.get(this.apiVersion);
        if (prefix == null) {
            throw new MicroVMException("unsupported apiVersion: " + this.apiVersion);
        }
        this.versionPrefix = prefix;
        this.httpClient = httpClient != null ? httpClient : effectiveConfig.httpClient != null ? effectiveConfig.httpClient : HttpClient.newHttpClient();
        this.webSocketConnector = webSocketConnector != null ? webSocketConnector : new JavaNetWebSocketConnector(this.httpClient);

        if (this.patToken.isEmpty()) {
            throw new MicroVMException(AUTH_REQUIRED_ERROR_MESSAGE);
        }
    }

    /**
     * Build a versioned API path. Pass the suffix beginning with "/" (e.g.
     * {@code "/sandboxes"}); the active version's prefix is prepended. Use
     * this for every versioned call so a future wire version can be selected
     * via {@link MicroVMConfig#apiVersion} without touching call sites.
     */
    private String versioned(String suffix) {
        return versionPrefix + suffix;
    }

    public String getApiUrl() {
        return apiUrl;
    }

    public String getPatToken() {
        return patToken;
    }

    public Sandbox create(CreateOptions options) {
        return wrap(doJson("POST", versioned("/sandboxes"), options, SandboxData.class));
    }

    public List<Sandbox> list() {
        SandboxData[] response = doJson("GET", versioned("/sandboxes"), null, SandboxData[].class);
        if (response == null) {
            return Collections.emptyList();
        }
        return java.util.Arrays.stream(response).map(this::wrap).collect(Collectors.toList());
    }

    public Sandbox get(String sandboxId) {
        return wrap(doJson("GET", sandboxPath(sandboxId), null, SandboxData.class));
    }

    public Sandbox start(String sandboxId) {
        return wrap(doJson("POST", sandboxPath(sandboxId) + "/start", null, SandboxData.class));
    }

    public Sandbox stop(String sandboxId) {
        return wrap(doJson("POST", sandboxPath(sandboxId) + "/stop", null, SandboxData.class));
    }

    public SandboxSnapshot createSnapshot(String sandboxId, String name) {
        return doJson("POST", sandboxPath(sandboxId) + "/snapshot", new CreateSnapshotRequest(name), SandboxSnapshot.class);
    }

    public void destroy(String sandboxId) {
        doNoContent("DELETE", sandboxPath(sandboxId), null);
    }

    public Sandbox resize(String sandboxId, ResizeOptions options) {
        return wrap(doJson("POST", sandboxPath(sandboxId) + "/resize", options, SandboxData.class));
    }

    public Sandbox updateLifecycle(String sandboxId, Lifecycle lifecycle) {
        return wrap(doJson("PUT", sandboxPath(sandboxId) + "/lifecycle", lifecycle, SandboxData.class));
    }

    public List<MountSpecRedacted> mounts(String sandboxId) {
        MountListResponse response = doJson("GET", sandboxPath(sandboxId) + "/mounts", null, MountListResponse.class);
        if (response == null || response.mounts == null) {
            return Collections.emptyList();
        }
        return response.mounts;
    }

    public NetworkUsage getNetworkUsage(String sandboxId) {
        return doJson("GET", sandboxPath(sandboxId) + "/network/usage", null, NetworkUsage.class);
    }

    public NetworkUsage setNetworkLimits(String sandboxId, SetNetworkLimitsOptions options) {
        return doJson("PATCH", sandboxPath(sandboxId) + "/network/limits", options, NetworkUsage.class);
    }

    public ExecResult exec(String sandboxId, ExecRequest request) {
        return doJson("POST", sandboxPath(sandboxId) + "/toolbox/process/execute", request, ExecResult.class);
    }

    public void uploadFile(String sandboxId, String targetPath, byte[] data) {
        String boundary = "----microvm-" + UUID.randomUUID();
        byte[] body = buildMultipartBody(boundary, targetPath, data);
        HttpResponse<byte[]> response = sendRequest(
            "POST",
            sandboxPath(sandboxId) + "/toolbox/files/upload",
            HttpRequest.BodyPublishers.ofByteArray(body),
            "multipart/form-data; boundary=" + boundary
        );
        ensureSuccess(response);
    }

    public byte[] downloadFile(String sandboxId, String targetPath) {
        HttpResponse<byte[]> response = sendRequest(
            "GET",
            sandboxPath(sandboxId) + "/toolbox/files/download?path=" + encodeQueryValue(targetPath),
            HttpRequest.BodyPublishers.noBody(),
            null
        );
        ensureSuccess(response);
        return response.body();
    }

    /**
     * Publish a sandbox container port. {@link ExposeOptions} selects the wire
     * surface — pass {@link ExposeOptions#tcp()} for raw caddy-l4 routing
     * (Postgres / Redis / MySQL / Mongo clients), {@link ExposeOptions#tls()}
     * for the TLS-SNI multiplexer, or {@code null} / {@link ExposeOptions#http()}
     * for the historical HTTP reverse-proxy URL. Result {@code host} and
     * {@code hostPort} are populated only on the TCP path.
     */
    public ExposeResult exposePort(String sandboxId, int port, ExposeOptions options) {
        ExposeProtocol protocol = (options != null && options.protocol != null) ? options.protocol : ExposeProtocol.HTTP;
        Object body = protocol == ExposeProtocol.HTTP ? null : new ExposePortRequest(protocol.getWireValue());
        ExposeResult response = doJson("POST", sandboxPath(sandboxId) + "/ports/" + port, body, ExposeResult.class);
        if (response == null) {
            ExposeResult empty = new ExposeResult();
            empty.protocol = ExposeProtocol.HTTP;
            empty.url = "";
            return empty;
        }
        if (response.protocol == null) {
            response.protocol = ExposeProtocol.HTTP;
        }
        return response;
    }

    public ExposeResult exposePort(String sandboxId, int port) {
        return exposePort(sandboxId, port, null);
    }

    public void unexposePort(String sandboxId, int port) {
        doNoContent("DELETE", sandboxPath(sandboxId) + "/ports/" + port, null);
    }

    static class ExposePortRequest {
        public final String protocol;

        ExposePortRequest(String protocol) {
            this.protocol = protocol;
        }
    }

    static class CreateSnapshotRequest {
        public final String name;

        CreateSnapshotRequest(String name) {
            this.name = name;
        }
    }

    public void reconcile() {
        doNoContent("POST", versioned("/admin/reconcile"), null);
    }

    public HealthStatus health() {
        return doJson("GET", "/health", null, HealthStatus.class);
    }

    public ExecStreamHandle execStream(String sandboxId, ExecStreamOptions options) {
        ExecStreamOptions effective = options == null ? new ExecStreamOptions() : options;
        if (trimToNull(effective.command) == null) {
            throw new MicroVMException("command is required");
        }

        CompletableFuture<ExecExitInfo> completion = new CompletableFuture<>();
        AtomicReference<StreamingWebSocket> socketRef = new AtomicReference<>();
        StreamingWebSocketListener listener = new StreamingWebSocketListener() {
            @Override
            public void onText(String text) {
                StreamServerMessage message = JsonSupport.read(text.getBytes(StandardCharsets.UTF_8), StreamServerMessage.class);
                if ("exit".equals(message.type)) {
                    completion.complete(new ExecExitInfo().setCode(message.code).setSignal(blankToNull(message.signal)));
                    safeClose(socketRef.get(), "done");
                    return;
                }
                if ("error".equals(message.type)) {
                    String errorMessage = message.message == null || message.message.isEmpty() ? "stream error" : message.message;
                    if (effective.onError != null) {
                        effective.onError.accept(errorMessage);
                    }
                    completion.completeExceptionally(new MicroVMException(errorMessage));
                    safeClose(socketRef.get(), "error");
                }
            }

            @Override
            public void onBinary(byte[] data) {
                if (data.length == 0) {
                    return;
                }
                byte[] chunk = java.util.Arrays.copyOfRange(data, 1, data.length);
                if (data[0] == STREAM_PREFIX_STDOUT && effective.onStdout != null) {
                    effective.onStdout.accept(chunk);
                }
                if (data[0] == STREAM_PREFIX_STDERR && effective.onStderr != null) {
                    effective.onStderr.accept(chunk);
                }
            }

            @Override
            public void onClose(int statusCode, String reason) {
                if (!completion.isDone()) {
                    completion.completeExceptionally(new MicroVMException("stream closed before exit: code=" + statusCode + formatReason(reason)));
                }
            }

            @Override
            public void onError(Throwable error) {
                String message = error == null || error.getMessage() == null ? "stream closed before exit" : error.getMessage();
                if (effective.onError != null) {
                    effective.onError.accept(message);
                }
                completion.completeExceptionally(new MicroVMException(message, error));
            }
        };

        StreamingWebSocket socket = webSocketConnector.connect(webSocketUri(sandboxPath(sandboxId) + "/toolbox/process/exec/stream"), authorizationHeaderValue(), listener);
        socketRef.set(socket);
        socket.sendText(JsonSupport.write(effective));
        return new ExecStreamHandle(socket, completion);
    }

    public Session createSession(String sandboxId, CreateSessionOptions options) {
        return doJson("POST", sandboxPath(sandboxId) + "/sessions", options, Session.class);
    }

    public List<Session> listSessions(String sandboxId) {
        SessionListResponse response = doJson("GET", sandboxPath(sandboxId) + "/sessions", null, SessionListResponse.class);
        if (response == null || response.sessions == null) {
            return Collections.emptyList();
        }
        return response.sessions;
    }

    public Session getSession(String sandboxId, String sessionId) {
        return doJson("GET", sandboxPath(sandboxId) + "/sessions/" + encodePathSegment(sessionId), null, Session.class);
    }

    public void deleteSession(String sandboxId, String sessionId) {
        doNoContent("DELETE", sandboxPath(sandboxId) + "/sessions/" + encodePathSegment(sessionId), null);
    }

    public void signalSession(String sandboxId, String sessionId, String signal) {
        doNoContent("POST", sandboxPath(sandboxId) + "/sessions/" + encodePathSegment(sessionId) + "/signal", new SignalRequest(signal));
    }

    public void resizeSession(String sandboxId, String sessionId, int cols, int rows) {
        doNoContent("POST", sandboxPath(sandboxId) + "/sessions/" + encodePathSegment(sessionId) + "/resize", new ResizeSessionRequest(cols, rows));
    }

    public byte[] sessionLog(String sandboxId, String sessionId) {
        HttpResponse<byte[]> response = sendRequest(
            "GET",
            sandboxPath(sandboxId) + "/sessions/" + encodePathSegment(sessionId) + "/log",
            HttpRequest.BodyPublishers.noBody(),
            null
        );
        ensureSuccess(response);
        return response.body();
    }

    public byte[] sessionRecording(String sandboxId, String sessionId) {
        HttpResponse<byte[]> response = sendRequest(
            "GET",
            sandboxPath(sandboxId) + "/sessions/" + encodePathSegment(sessionId) + "/recording",
            HttpRequest.BodyPublishers.noBody(),
            null
        );
        ensureSuccess(response);
        return response.body();
    }

    public SessionAttachHandle attachSession(String sandboxId, String sessionId, SessionAttachOptions options) {
        if (trimToNull(sandboxId) == null || trimToNull(sessionId) == null) {
            throw new MicroVMException("sandbox id and session id are required");
        }

        SessionAttachOptions effective = options == null ? new SessionAttachOptions() : options;
        CompletableFuture<ExecExitInfo> completion = new CompletableFuture<>();
        AtomicReference<StreamingWebSocket> socketRef = new AtomicReference<>();
        StreamingWebSocketListener listener = new StreamingWebSocketListener() {
            @Override
            public void onText(String text) {
                StreamServerMessage message = JsonSupport.read(text.getBytes(StandardCharsets.UTF_8), StreamServerMessage.class);
                if ("exit".equals(message.type)) {
                    ExecExitInfo info = new ExecExitInfo().setCode(message.code).setSignal(blankToNull(message.signal));
                    if (effective.onExit != null) {
                        effective.onExit.accept(info);
                    }
                    completion.complete(info);
                    safeClose(socketRef.get(), "done");
                    return;
                }
                if ("error".equals(message.type)) {
                    String errorMessage = message.message == null || message.message.isEmpty() ? "session error" : message.message;
                    if (effective.onError != null) {
                        effective.onError.accept(errorMessage);
                    }
                    completion.completeExceptionally(new MicroVMException(errorMessage));
                    safeClose(socketRef.get(), "error");
                }
            }

            @Override
            public void onBinary(byte[] data) {
                if (data.length == 0) {
                    return;
                }
                byte[] chunk = java.util.Arrays.copyOfRange(data, 1, data.length);
                if (data[0] == STREAM_PREFIX_STDOUT && effective.onStdout != null) {
                    effective.onStdout.accept(chunk);
                }
                if (data[0] == STREAM_PREFIX_STDERR && effective.onStderr != null) {
                    effective.onStderr.accept(chunk);
                }
            }

            @Override
            public void onClose(int statusCode, String reason) {
                if (!completion.isDone()) {
                    completion.completeExceptionally(new MicroVMException("session stream closed: code=" + statusCode + formatReason(reason)));
                }
            }

            @Override
            public void onError(Throwable error) {
                String message = error == null || error.getMessage() == null ? "session stream closed" : error.getMessage();
                if (effective.onError != null) {
                    effective.onError.accept(message);
                }
                completion.completeExceptionally(new MicroVMException(message, error));
            }
        };

        StreamingWebSocket socket = webSocketConnector.connect(
            webSocketUri(sandboxPath(sandboxId) + "/sessions/" + encodePathSegment(sessionId) + "/attach"),
            authorizationHeaderValue(),
            listener
        );
        socketRef.set(socket);
        if (effective.cols != null && effective.cols > 0 && effective.rows != null && effective.rows > 0) {
            socket.sendText(JsonSupport.write(StreamControlMessage.resize(effective.cols, effective.rows)));
        }
        return new SessionAttachHandle(socket, completion);
    }

    private Sandbox wrap(SandboxData data) {
        return new Sandbox(this, data);
    }

    private <T> T doJson(String method, String path, Object payload, Class<T> responseType) {
        HttpResponse<byte[]> response = sendJsonRequest(method, path, payload);
        ensureSuccess(response);
        if (responseType == null || response.statusCode() == 204 || response.body().length == 0) {
            return null;
        }
        return JsonSupport.read(response.body(), responseType);
    }

    private void doNoContent(String method, String path, Object payload) {
        HttpResponse<byte[]> response = sendJsonRequest(method, path, payload);
        ensureSuccess(response);
    }

    private HttpResponse<byte[]> sendJsonRequest(String method, String path, Object payload) {
        if (payload == null) {
            return sendRequest(method, path, HttpRequest.BodyPublishers.noBody(), null);
        }
        byte[] body = JsonSupport.writeBytes(payload);
        return sendRequest(method, path, HttpRequest.BodyPublishers.ofByteArray(body), "application/json");
    }

    private HttpResponse<byte[]> sendRequest(String method, String path, HttpRequest.BodyPublisher bodyPublisher, String contentType) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(resolve(path)).method(method, bodyPublisher);
        if (contentType != null) {
            builder.header("Content-Type", contentType);
        }
        builder.header("Authorization", authorizationHeaderValue());

        try {
            return httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException | InterruptedException ex) {
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new MicroVMException("request failed", ex);
        }
    }

    private void ensureSuccess(HttpResponse<byte[]> response) {
        if (response.statusCode() >= 400) {
            ErrorResponse error = JsonSupport.tryRead(response.body(), ErrorResponse.class);
            if (error != null && error.error != null && !error.error.isEmpty()) {
                throw new MicroVMException(error.error);
            }
            throw new MicroVMException("request failed with status " + response.statusCode());
        }
    }

    private URI resolve(String path) {
        return URI.create(apiUrl + path);
    }

    private URI webSocketUri(String path) {
        URI uri = resolve(path);
        String scheme = uri.getScheme();
        String websocketScheme;
        if ("http".equalsIgnoreCase(scheme)) {
            websocketScheme = "ws";
        } else if ("https".equalsIgnoreCase(scheme)) {
            websocketScheme = "wss";
        } else if ("ws".equalsIgnoreCase(scheme) || "wss".equalsIgnoreCase(scheme)) {
            websocketScheme = scheme;
        } else {
            throw new MicroVMException("unsupported base URL scheme \"" + scheme + "\"");
        }

        try {
            return new URI(websocketScheme, uri.getUserInfo(), uri.getHost(), uri.getPort(), uri.getPath(), uri.getQuery(), uri.getFragment());
        } catch (URISyntaxException ex) {
            throw new MicroVMException("invalid websocket URL", ex);
        }
    }

    private String authorizationHeaderValue() {
        return "Bearer " + patToken;
    }

    private String sandboxPath(String sandboxId) {
        return versioned("/sandboxes/" + encodePathSegment(sandboxId));
    }

    private static String normalizeUrl(String value) {
        return value.replaceAll("/+$", "");
    }

    private static String encodePathSegment(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String encodeQueryValue(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static String blankToNull(String value) {
        return trimToNull(value);
    }

    private static String baseName(String value) {
        int slash = value.lastIndexOf('/');
        return slash >= 0 ? value.substring(slash + 1) : value;
    }

    private static String formatReason(String reason) {
        return reason == null || reason.isEmpty() ? "" : " reason=" + reason;
    }

    private static void safeClose(StreamingWebSocket socket, String reason) {
        if (socket == null) {
            return;
        }
        try {
            socket.sendClose(1000, reason);
        } catch (RuntimeException ignored) {
        }
    }

    private static byte[] buildMultipartBody(String boundary, String targetPath, byte[] data) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try {
            writePart(output, boundary, "path", null, "text/plain; charset=UTF-8", targetPath.getBytes(StandardCharsets.UTF_8));
            writePart(output, boundary, "file", baseName(targetPath), "application/octet-stream", data);
            output.write(("--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
            return output.toByteArray();
        } catch (IOException ex) {
            throw new MicroVMException("failed to build multipart request", ex);
        }
    }

    private static void writePart(ByteArrayOutputStream output, String boundary, String name, String filename, String contentType, byte[] data) throws IOException {
        output.write(("--" + boundary + "\r\n").getBytes(StandardCharsets.UTF_8));
        StringBuilder disposition = new StringBuilder("Content-Disposition: form-data; name=\"").append(name).append("\"");
        if (filename != null) {
            disposition.append("; filename=\"").append(filename).append("\"");
        }
        disposition.append("\r\n");
        output.write(disposition.toString().getBytes(StandardCharsets.UTF_8));
        if (contentType != null) {
            output.write(("Content-Type: " + contentType + "\r\n").getBytes(StandardCharsets.UTF_8));
        }
        output.write("\r\n".getBytes(StandardCharsets.UTF_8));
        output.write(data);
        output.write("\r\n".getBytes(StandardCharsets.UTF_8));
    }

    private static final class MountListResponse {
        public List<MountSpecRedacted> mounts;
    }

    private static final class SessionListResponse {
        public List<Session> sessions;
    }

    @SuppressWarnings("unused")
    private static final class ErrorResponse {
        public String error;
    }

    @SuppressWarnings("unused")
    private static final class StreamServerMessage {
        public String type;
        public int code;
        public String signal;
        public String message;
    }

    @SuppressWarnings("unused")
    private static final class SignalRequest {
        public final String signal;

        private SignalRequest(String signal) {
            this.signal = signal;
        }
    }

    @SuppressWarnings("unused")
    private static final class ResizeSessionRequest {
        public final int cols;
        public final int rows;

        private ResizeSessionRequest(int cols, int rows) {
            this.cols = cols;
            this.rows = rows;
        }
    }
}