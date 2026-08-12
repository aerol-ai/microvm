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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
import ai.aerol.microvm.model.BuildImageOptions;
import ai.aerol.microvm.model.BuildImagePushOptions;
import ai.aerol.microvm.model.BuildImageResult;
import ai.aerol.microvm.model.CloneGeneration;
import ai.aerol.microvm.model.CreateOptions;
import ai.aerol.microvm.model.CreateSessionOptions;
import ai.aerol.microvm.model.CreateTemplateOptions;
import ai.aerol.microvm.model.CreateWasmModuleOptions;
import ai.aerol.microvm.model.PushWasmModuleOptions;
import ai.aerol.microvm.model.PushWasmModuleResponse;
import ai.aerol.microvm.model.CustomDomain;
import ai.aerol.microvm.model.CustomDomainDnsRecords;
import ai.aerol.microvm.model.DnsRecord;
import ai.aerol.microvm.model.ExecExitInfo;
import ai.aerol.microvm.model.ExecRequest;
import ai.aerol.microvm.model.ExecResult;
import ai.aerol.microvm.model.ExecStreamOptions;
import ai.aerol.microvm.model.ExposeOptions;
import ai.aerol.microvm.model.ExposeProtocol;
import ai.aerol.microvm.model.ExposeResult;
import ai.aerol.microvm.model.HealthStatus;
import ai.aerol.microvm.model.IngressTarget;
import ai.aerol.microvm.model.Lifecycle;
import ai.aerol.microvm.model.MountSpecRedacted;
import ai.aerol.microvm.model.NetworkUsage;
import ai.aerol.microvm.model.RegisterSnapshotOptions;
import ai.aerol.microvm.model.ResizeOptions;
import ai.aerol.microvm.model.SandboxData;
import ai.aerol.microvm.model.SandboxSnapshot;
import ai.aerol.microvm.model.Session;
import ai.aerol.microvm.model.SessionAttachOptions;
import ai.aerol.microvm.model.SetNetworkLimitsOptions;
import ai.aerol.microvm.model.Template;
import ai.aerol.microvm.model.WasmModule;

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
    private final ai.aerol.microvm.model.RetryConfig retryConfig;

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
        this.retryConfig = effectiveConfig.retry != null ? effectiveConfig.retry : new ai.aerol.microvm.model.RetryConfig();

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

    /**
     * Build {@code image} and create a sandbox from the resulting tag with
     * default options. Distinct method name (vs {@code create(...)} overloads)
     * so a {@code null} argument can't pick this path by accident.
     */
    public Sandbox createWithImage(Image image) {
        return createWithImage(image, new CreateOptions());
    }

    public Sandbox createWithImage(Image image, CreateOptions options) {
        CreateOptions resolved = copyCreateOptions(options);
        resolved.setImage(buildImage(image));
        return create(resolved);
    }

    public String buildImage(Image image) {
        return buildImage(image, null).image;
    }

    /**
     * Build an Image and optionally push the result to a remote registry.
     * When {@code options.push} is set, push credentials are forwarded to the
     * daemon as a one-shot {@code X-Registry-Auth} header on the underlying
     * push call and are never persisted server-side.
     */
    public BuildImageResult buildImage(Image image, BuildImageOptions options) {
        if (image == null) {
            throw new MicroVMException("image is required");
        }
        BuildImageRequest body = new BuildImageRequest(image.getDockerfile());
        if (options != null && options.push != null) {
            BuildImagePushOptions push = options.push;
            String registry = push.registry == null ? "" : push.registry.trim();
            if (registry.isEmpty()) {
                throw new MicroVMException("push.registry is required when push is set");
            }
            if (push.username == null || push.username.isEmpty()
                || push.password == null || push.password.isEmpty()) {
                throw new MicroVMException("push.username and push.password are required when push is set");
            }
            BuildImagePushSpec spec = new BuildImagePushSpec();
            spec.registry = registry;
            spec.tag = isNullOrEmpty(push.tag) ? null : push.tag.trim();
            spec.server = isNullOrEmpty(push.server) ? null : push.server.trim();
            spec.username = push.username;
            spec.password = push.password;
            body.push = spec;
        }
        String path = versioned("/images/build");
        HttpResponse<byte[]> response = sendJsonRequest("POST", path, body);
        if (response.statusCode() == 404) {
            throw new MicroVMException(
                "this daemon does not support Image builds (POST " + path
                    + " is not registered) — pass a string image reference (e.g. \"ubuntu:22.04\") instead, or upgrade the daemon"
            );
        }
        ensureSuccess(response);
        BuildImageResponse payload = JsonSupport.read(response.body(), BuildImageResponse.class);
        if (payload == null) {
            return new BuildImageResult("", null);
        }
        String pushed = isNullOrEmpty(payload.pushed) ? null : payload.pushed;
        return new BuildImageResult(payload.image == null ? "" : payload.image, pushed);
    }

    private static boolean isNullOrEmpty(String s) {
        return s == null || s.isEmpty();
    }

    public List<Sandbox> list() {
        return list(Collections.emptyMap(), false);
    }

    /**
     * Lists sandboxes whose {@code tags} map contains every key/value pair in
     * {@code tags} (AND semantics on the server). Wire format is
     * {@code ?tag.<key>=<value>}; both key and value are URL-encoded. An empty
     * or null map is equivalent to {@link #list()} — no query string is added,
     * keeping fixtures and request matchers stable.
     */
    public List<Sandbox> list(java.util.Map<String, String> tags) {
        return list(tags, false);
    }

    /**
     * Lists sandboxes with optional {@code include_env=true}. Env is omitted
     * from get/list by default; opt-in reads are audited server-side.
     */
    public List<Sandbox> list(java.util.Map<String, String> tags, boolean includeEnv) {
        String basePath = versioned("/sandboxes") + buildSandboxQuery(tags, includeEnv);
        java.util.ArrayList<Sandbox> items = new java.util.ArrayList<>();
        String pageToken = "";
        for (int page = 0; page < 1000; page++) {
            String path = appendQueryParam(basePath, "page_token", pageToken);
            HttpResponse<byte[]> httpResponse = sendJsonRequest("GET", path, null);
            ensureSuccess(httpResponse);
            String partial = headerValue(httpResponse, "X-Cluster-List-Partial");
            String ready = headerValue(httpResponse, "X-Cluster-List-Placement-Ready");
            if ("true".equals(partial) || "false".equals(ready)) {
                throw new MicroVMException("incomplete cluster list");
            }
            SandboxData[] response = JsonSupport.read(httpResponse.body(), SandboxData[].class);
            if (response != null) {
                for (SandboxData item : response) {
                    items.add(wrap(item));
                }
            }
            pageToken = headerValue(httpResponse, "X-Cluster-List-Next-Page-Token");
            if (pageToken == null || pageToken.isBlank()) {
                return items;
            }
            pageToken = pageToken.trim();
        }
        throw new MicroVMException("incomplete cluster list: exceeded max pages");
    }

    private static String headerValue(HttpResponse<byte[]> response, String name) {
        return response.headers().firstValue(name).orElse("");
    }

    private static String appendQueryParam(String path, String key, String value) {
        if (value == null || value.isBlank()) {
            return path;
        }
        String sep = path.contains("?") ? "&" : "?";
        return path + sep + encodeQueryValue(key) + "=" + encodeQueryValue(value);
    }

    // Renders the tag filter as the server's ?tag.<key>=<value> wire format.
    // The "tag." prefix is literal — parseTagFilter on the server checks the
    // *decoded* query key — so only the user-supplied key and value get
    // percent-encoded. Returns "" for null/empty so the URL stays
    // byte-identical to the pre-filter call (no stray trailing "?").
    private static String buildTagQuery(java.util.Map<String, String> tags) {
        return buildSandboxQuery(tags, false);
    }

    private static String buildSandboxQuery(java.util.Map<String, String> tags, boolean includeEnv) {
        boolean hasTags = tags != null && !tags.isEmpty();
        if (!hasTags && !includeEnv) {
            return "";
        }
        StringBuilder out = new StringBuilder("?");
        boolean first = true;
        if (hasTags) {
            for (java.util.Map.Entry<String, String> entry : tags.entrySet()) {
                if (!first) {
                    out.append('&');
                }
                first = false;
                out.append("tag.");
                out.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8));
                out.append('=');
                out.append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
            }
        }
        if (includeEnv) {
            if (!first) {
                out.append('&');
            }
            out.append("include_env=true");
        }
        return out.toString();
    }

    public Sandbox get(String sandboxId) {
        return get(sandboxId, false);
    }

    /** Fetches a sandbox; when {@code includeEnv} is true, appends {@code ?include_env=true}. */
    public Sandbox get(String sandboxId, boolean includeEnv) {
        return wrap(doJson("GET", sandboxPath(sandboxId) + buildSandboxQuery(null, includeEnv), null, SandboxData.class));
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

    public SandboxSnapshot registerSnapshot(RegisterSnapshotOptions options) {
        RegisterSnapshotOptions resolved = copyRegisterSnapshotOptions(options);
        String name = trimToNull(resolved.name);
        if (name == null) {
            throw new MicroVMException("name is required");
        }

        String image = trimToNull(resolved.image);
        String dockerfileContent = trimToNull(resolved.dockerfileContent);
        if (image == null && dockerfileContent == null) {
            throw new MicroVMException("image or dockerfile_content is required");
        }
        if (image != null && dockerfileContent != null) {
            throw new MicroVMException("image and dockerfile_content are mutually exclusive");
        }

        resolved.name = name;
        resolved.image = image;
        resolved.dockerfileContent = dockerfileContent;
        resolved.regionId = trimToNull(resolved.regionId);
        return doJson("POST", versioned("/snapshots"), resolved, SandboxSnapshot.class);
    }

    public SandboxSnapshot registerSnapshotFromImage(String name, Image image) {
        return registerSnapshotFromImage(name, image, new RegisterSnapshotOptions());
    }

    public SandboxSnapshot registerSnapshotFromImage(String name, Image image, RegisterSnapshotOptions options) {
        if (image == null) {
            throw new MicroVMException("image is required");
        }
        RegisterSnapshotOptions resolved = copyRegisterSnapshotOptions(options);
        resolved.name = name;
        resolved.image = null;
        resolved.dockerfileContent = image.getDockerfile();
        return registerSnapshot(resolved);
    }

    public void destroy(String sandboxId) {
        doNoContent("DELETE", sandboxPath(sandboxId), null);
    }

    /**
     * Register a Firecracker rootfs template. Returns a row in
     * {@code status="pending"} and kicks the daemon's async build. Poll
     * {@link #getTemplate} until the row reaches
     * {@link ai.aerol.microvm.model.TemplateStatus#READY} (fast-boot
     * available) or
     * {@link ai.aerol.microvm.model.TemplateStatus#READY_NO_SNAPSHOT}
     * (cold boot only).
     *
     * <p>Idempotent when {@link CreateTemplateOptions#id} is supplied: a
     * duplicate id returns 409 so a retried CI step does not register two
     * rows for the same logical template.
     */
    public Template createTemplate(CreateTemplateOptions options) {
        if (options == null || trimToNull(options.image) == null) {
            throw new MicroVMException("image is required");
        }
        return doJson("POST", versioned("/templates"), options, Template.class);
    }

    public List<Template> listTemplates() {
        Template[] response = doJson("GET", versioned("/templates"), null, Template[].class);
        if (response == null) {
            return Collections.emptyList();
        }
        return java.util.Arrays.asList(response);
    }

    public Template getTemplate(String templateId) {
        return doJson("GET", versioned("/templates/" + templateId), null, Template.class);
    }

    public void deleteTemplate(String templateId) {
        doNoContent("DELETE", versioned("/templates/" + templateId), null);
    }

    /**
     * Register a WASM module in the host catalogue. Resolution is synchronous —
     * the returned row is typically already
     * {@link ai.aerol.microvm.model.WasmModuleStatus#READY}.
     */
    public WasmModule createWasmModule(CreateWasmModuleOptions options) {
        if (options == null || trimToNull(options.moduleRef) == null) {
            throw new MicroVMException("module_ref is required");
        }
        return doJson("POST", versioned("/wasm-modules"), options, WasmModule.class);
    }

    public List<WasmModule> listWasmModules() {
        WasmModule[] response = doJson("GET", versioned("/wasm-modules"), null, WasmModule[].class);
        if (response == null) {
            return Collections.emptyList();
        }
        return java.util.Arrays.asList(response);
    }

    public WasmModule getWasmModule(String moduleId) {
        return doJson("GET", versioned("/wasm-modules/" + moduleId), null, WasmModule.class);
    }

    public void deleteWasmModule(String moduleId) {
        doNoContent("DELETE", versioned("/wasm-modules/" + moduleId), null);
    }

    /**
     * Upload a compiled core-wasip1 module to the registry under your own
     * credentials and get back the {@code oci://} ref to use as
     * {@code moduleRef} on a later create. The daemon validates and forwards
     * the bytes; it never stores them.
     */
    public PushWasmModuleResponse pushWasmModule(PushWasmModuleOptions options) {
        if (options == null || options.getName() == null || options.getName().isBlank()) {
            throw new MicroVMException("name is required");
        }
        if (options.getRegistryToken() == null || options.getRegistryToken().isBlank()) {
            throw new MicroVMException("registryToken is required");
        }
        String tag = (options.getTag() == null || options.getTag().isBlank()) ? "latest" : options.getTag();
        String path = versioned("/wasm-modules/push")
            + "?name=" + encodeQueryValue(options.getName())
            + "&tag=" + encodeQueryValue(tag);
        Map<String, String> headers = new HashMap<>();
        headers.put("X-Registry-Token", options.getRegistryToken());
        if (options.getRegistryUsername() != null && !options.getRegistryUsername().isBlank()) {
            headers.put("X-Registry-Username", options.getRegistryUsername());
        }
        byte[] module = options.getModule() != null ? options.getModule() : new byte[0];
        HttpResponse<byte[]> response = sendRequest(
            "POST",
            path,
            HttpRequest.BodyPublishers.ofByteArray(module),
            "application/octet-stream",
            headers
        );
        ensureSuccess(response);
        return JsonSupport.read(response.body(), PushWasmModuleResponse.class);
    }

    /**
     * Re-run the snapshot phase against an existing template. Idempotent
     * under concurrent retry: the daemon's CAS collapses N parallel calls
     * for the same ready template into one rebuild kick. Returns the row
     * in its post-transition state (typically
     * {@link ai.aerol.microvm.model.TemplateStatus#UNHEALTHY}); poll
     * {@link #getTemplate} to observe the transition back to
     * {@link ai.aerol.microvm.model.TemplateStatus#READY}.
     *
     * <p>Throws {@link MicroVMException} wrapping HTTP 412 when the
     * template is in a state where rebuild is unsafe (build in flight) or
     * unsupported ({@code ready_no_snapshot} / {@code failed} — those need
     * delete+recreate today).
     */
    public Template rebuildTemplate(String templateId) {
        return doJson("POST", versioned("/templates/" + templateId + "/rebuild"), null, Template.class);
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

    /**
     * Reads a sandbox's clone-generation token. The token changes whenever the
     * sandbox is resumed from a snapshot, so a change signals "this is a clone."
     * Read-only — the SDK cannot reseed a process inside the guest; see the
     * "Randomness in cloned sandboxes" docs for the in-guest reseed pattern.
     */
    public CloneGeneration cloneGeneration(String sandboxId) {
        return doJson("GET", sandboxPath(sandboxId) + "/toolbox/clone-generation", null, CloneGeneration.class);
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

    /**
     * Attach an operator-supplied hostname to the sandbox's HTTP entrypoint.
     * The server lowercases {@code hostname}, deduplicates against existing
     * entries (so retries are safe), and returns the full attached-domain
     * set. Newly added rows start in {@link ai.aerol.microvm.model.CustomDomainStatus#PENDING_DNS};
     * Caddy advances them to {@code issuing} / {@code ready} once the
     * operator's DNS resolves to the cluster.
     */
    public List<CustomDomain> addCustomDomain(String sandboxId, String hostname) {
        return addCustomDomain(sandboxId, hostname, 0);
    }

    /**
     * Attach with a per-domain target port. {@code targetPort == 0} routes to
     * the sandbox's toolbox port (the same default the single-arg overload
     * uses). Re-adding the same hostname with a different port returns 409 —
     * detach first if you need to change it.
     */
    public List<CustomDomain> addCustomDomain(String sandboxId, String hostname, int targetPort) {
        CustomDomainListResponse response = doJson(
            "POST",
            sandboxPath(sandboxId) + "/custom-domains",
            new AddCustomDomainRequest(hostname, targetPort),
            CustomDomainListResponse.class
        );
        if (response == null || response.customDomains == null) {
            return Collections.emptyList();
        }
        return response.customDomains;
    }

    public List<CustomDomain> listCustomDomains(String sandboxId) {
        CustomDomainListResponse response = doJson(
            "GET",
            sandboxPath(sandboxId) + "/custom-domains",
            null,
            CustomDomainListResponse.class
        );
        if (response == null || response.customDomains == null) {
            return Collections.emptyList();
        }
        return response.customDomains;
    }

    public void removeCustomDomain(String sandboxId, String hostname) {
        doNoContent(
            "DELETE",
            sandboxPath(sandboxId) + "/custom-domains/" + encodePathSegment(hostname),
            null
        );
    }

    /**
     * Resolve the cluster-wide ingress target operators should point custom
     * domain DNS records at. Exactly one of {@link IngressTarget#hostname}
     * (CNAME target) or {@link IngressTarget#ips} (A-record targets) will be
     * populated, depending on the daemon's configured ingress source.
     */
    public IngressTarget dnsTarget() {
        IngressTarget target = doJson("GET", versioned("/ingress/dns"), null, IngressTarget.class);
        return target == null ? new IngressTarget() : target;
    }

    /**
     * Render the DNS records the operator must publish to validate every
     * custom domain attached to this sandbox. The returned
     * {@link CustomDomainDnsRecords#target} mirrors {@link #dnsTarget()} so
     * callers can render setup instructions without a second round trip.
     */
    public CustomDomainDnsRecords customDomainDns(String sandboxId) {
        CustomDomainDnsRecords records = doJson(
            "GET",
            sandboxPath(sandboxId) + "/custom-domains/dns",
            null,
            CustomDomainDnsRecords.class
        );
        if (records == null) {
            return new CustomDomainDnsRecords();
        }
        if (records.records == null) {
            records.records = Collections.<DnsRecord>emptyList();
        }
        return records;
    }

    static class AddCustomDomainRequest {
        public final String hostname;

        @com.fasterxml.jackson.annotation.JsonProperty("target_port")
        @com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_DEFAULT)
        public final int targetPort;

        AddCustomDomainRequest(String hostname, int targetPort) {
            this.hostname = hostname;
            this.targetPort = targetPort;
        }
    }

    private static final class CustomDomainListResponse {
        @com.fasterxml.jackson.annotation.JsonProperty("custom_domains")
        public List<CustomDomain> customDomains;
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

    static class BuildImageRequest {
        public final String dockerfileContent;
        public BuildImagePushSpec push;

        BuildImageRequest(String dockerfileContent) {
            this.dockerfileContent = dockerfileContent;
        }
    }

    static class BuildImagePushSpec {
        public String registry;
        public String tag;
        public String server;
        public String username;
        public String password;
    }

    static class BuildImageResponse {
        public String image;
        public String pushed;
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

    private CreateOptions copyCreateOptions(CreateOptions source) {
        CreateOptions copy = new CreateOptions();
        if (source == null) {
            return copy;
        }
        copy.image = source.image;
        copy.cpu = source.cpu;
        copy.memoryMb = source.memoryMb;
        copy.diskGb = source.diskGb;
        copy.env = source.env;
        copy.osUser = source.osUser;
        copy.networkBlockAll = source.networkBlockAll;
        copy.networkAllowOut = source.networkAllowOut;
        copy.networkDenyOut = source.networkDenyOut;
        copy.allowPublicTraffic = source.allowPublicTraffic;
        copy.maskRequestHost = source.maskRequestHost;
        copy.networkBytesInLimit = source.networkBytesInLimit;
        copy.networkBytesOutLimit = source.networkBytesOutLimit;
        copy.registry = source.registry;
        copy.containerCommand = source.containerCommand;
        copy.mounts = source.mounts;
        copy.lifecycle = source.lifecycle;
        copy.failover = source.failover;
        copy.runtime = source.runtime;
        copy.durability = source.durability;
        copy.moduleRef = source.moduleRef;
        copy.tenantId = source.tenantId;
        copy.gpus = source.gpus;
        copy.customDomains = source.customDomains;
        return copy;
    }

    private RegisterSnapshotOptions copyRegisterSnapshotOptions(RegisterSnapshotOptions source) {
        RegisterSnapshotOptions copy = new RegisterSnapshotOptions();
        if (source == null) {
            return copy;
        }
        copy.name = source.name;
        copy.image = source.image;
        copy.dockerfileContent = source.dockerfileContent;
        copy.contextHashes = source.contextHashes;
        copy.entrypoint = source.entrypoint;
        copy.regionId = source.regionId;
        copy.cpu = source.cpu;
        copy.gpu = source.gpu;
        copy.memoryMb = source.memoryMb;
        copy.diskGb = source.diskGb;
        return copy;
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
        return sendRequest(method, path, bodyPublisher, contentType, null);
    }

    private HttpResponse<byte[]> sendRequest(String method, String path, HttpRequest.BodyPublisher bodyPublisher, String contentType, Map<String, String> extraHeaders) {
        int maxRetries = retryConfig.maxRetries != null ? retryConfig.maxRetries : 3;
        int baseDelay = retryConfig.baseDelayMs != null ? retryConfig.baseDelayMs : 200;
        int maxDelay = retryConfig.maxDelayMs != null ? retryConfig.maxDelayMs : 5000;

        Exception lastException = null;

        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            HttpRequest.Builder builder = HttpRequest.newBuilder(resolve(path)).method(method, bodyPublisher);
            if (contentType != null) {
                builder.header("Content-Type", contentType);
            }
            if (extraHeaders != null) {
                for (Map.Entry<String, String> entry : extraHeaders.entrySet()) {
                    builder.header(entry.getKey(), entry.getValue());
                }
            }
            builder.header("Authorization", authorizationHeaderValue());

            try {
                HttpResponse<byte[]> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
                int status = response.statusCode();
                if ((status == 429 || status == 502 || status == 503 || status == 504) && attempt < maxRetries) {
                    // Fall through to retry logic
                } else {
                    return response;
                }
            } catch (IOException | InterruptedException ex) {
                if (ex instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                    throw new MicroVMException("request interrupted", ex);
                }
                lastException = ex;
                if (attempt >= maxRetries) {
                    break;
                }
            }

            int delayMs = Math.min(baseDelay * (1 << attempt), maxDelay);
            double jitter = 1.0 + (Math.random() - 0.5) * 0.5;
            try {
                Thread.sleep((long) (delayMs * jitter));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new MicroVMException("request interrupted during backoff", e);
            }
        }

        if (lastException != null) {
            throw new MicroVMException("request failed after " + maxRetries + " retries", lastException);
        }
        throw new MicroVMException("request failed after " + maxRetries + " retries");
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
