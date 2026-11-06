package ai.aerol.microvm;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import ai.aerol.microvm.internal.Environment;
import ai.aerol.microvm.internal.JavaNetWebSocketConnector;
import ai.aerol.microvm.internal.JsonSupport;
import ai.aerol.microvm.internal.StreamControlMessage;
import ai.aerol.microvm.internal.StreamingWebSocket;
import ai.aerol.microvm.internal.StreamingWebSocketListener;
import ai.aerol.microvm.internal.WebSocketConnector;
import ai.aerol.microvm.internal.WebSocketHandshakeFailure;
import ai.aerol.microvm.internal.api.v1.Paths;
import ai.aerol.microvm.model.ApiTokenList;
import ai.aerol.microvm.model.CreateApiTokenOptions;
import ai.aerol.microvm.model.CreatedApiToken;
import ai.aerol.microvm.model.CreateSandboxTokenOptions;
import ai.aerol.microvm.model.SandboxToken;
import ai.aerol.microvm.model.WhoAmI;
import ai.aerol.microvm.model.AuditCoverage;
import ai.aerol.microvm.model.EgressProfile;
import ai.aerol.microvm.model.EgressProfileList;
import ai.aerol.microvm.model.EgressProfileOptions;
import ai.aerol.microvm.model.IdentityRole;
import ai.aerol.microvm.model.IdentityRoleList;
import ai.aerol.microvm.model.IdentityRoleOptions;
import ai.aerol.microvm.model.ListIdentityRolesOptions;
import ai.aerol.microvm.model.ListEgressProfilesOptions;
import ai.aerol.microvm.model.TeamQuota;
import ai.aerol.microvm.model.TeamQuotaOptions;
import ai.aerol.microvm.model.WarmPool;
import ai.aerol.microvm.model.WarmPoolList;
import ai.aerol.microvm.model.WarmPoolOptions;
import ai.aerol.microvm.model.ListSnapshotsOptions;
import ai.aerol.microvm.model.NetworkLearned;
import ai.aerol.microvm.model.NetworkLearnedEntry;
import ai.aerol.microvm.model.NetworkPolicy;
import ai.aerol.microvm.model.NetworkPolicyCheckOptions;
import ai.aerol.microvm.model.NetworkPolicyCheckResult;
import ai.aerol.microvm.model.NetworkPolicyOptions;
import ai.aerol.microvm.model.AuditOptions;
import ai.aerol.microvm.model.AuditPage;
import ai.aerol.microvm.model.BuildImageOptions;
import ai.aerol.microvm.model.BuildImagePushOptions;
import ai.aerol.microvm.model.BuildImageResult;
import ai.aerol.microvm.model.CloneGeneration;
import ai.aerol.microvm.model.CreateSnapshotOptions;
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
import ai.aerol.microvm.model.FileEvent;
import ai.aerol.microvm.model.CopyFileOptions;
import ai.aerol.microvm.model.DeleteFileOptions;
import ai.aerol.microvm.model.FileInfo;
import ai.aerol.microvm.model.FileList;
import ai.aerol.microvm.model.FileMatch;
import ai.aerol.microvm.model.ListFilesOptions;
import ai.aerol.microvm.model.MakeDirOptions;
import ai.aerol.microvm.model.MoveFileOptions;
import ai.aerol.microvm.model.UploadFileOptions;
import ai.aerol.microvm.model.DownloadFileOptions;
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
import ai.aerol.microvm.model.SnapshotList;
import ai.aerol.microvm.model.SessionAttachOptions;
import ai.aerol.microvm.model.SetNetworkLimitsOptions;
import ai.aerol.microvm.model.Template;
import ai.aerol.microvm.model.WasmModule;
import ai.aerol.microvm.model.WatchOptions;

public class MicroVMClient {
    static final String DEFAULT_API_URL = "http://127.0.0.1:21212";
    static final String DEFAULT_API_VERSION = "v1";
    static final String AUTH_REQUIRED_ERROR_MESSAGE = "PAT token is required. Set patToken, SB_PAT_TOKEN or SB_API_TOKEN.";
    /**
     * The request header that selects which of a credential's teams a request
     * acts for. Keep in sync with pkg/api.HeaderTeam on the server.
     */
    public static final String TEAM_HEADER = "X-AerolVM-Team";

    /**
     * The header a sandbox create carries so the server can recognise a retry
     * of it. Keep in sync with clustercreate.HeaderIdempotencyKey on the
     * server.
     */
    public static final String IDEMPOTENCY_KEY_HEADER = "Idempotency-Key";

    private static final java.security.SecureRandom IDEMPOTENCY_KEY_RANDOM = new java.security.SecureRandom();
    // How long watchFiles waits for the server's start frame. toolboxd sends
    // it once every folder is watched; a recursive walk of a large tree can
    // take seconds.
    private static final java.time.Duration WATCH_START_TIMEOUT = java.time.Duration.ofSeconds(60);
    private static final int STREAM_PREFIX_STDOUT = 0x01;
    private static final int STREAM_PREFIX_STDERR = 0x02;

    private static final java.util.Map<String, String> PATH_PREFIXES = java.util.Map.of(
        "v1", Paths.PATH_PREFIX
    );

    private final String apiUrl;
    private final String patToken;
    private final String team;
    private final String apiVersion;
    private final String versionPrefix;
    private final HttpClient httpClient;
    private final WebSocketConnector webSocketConnector;
    private final ai.aerol.microvm.model.RetryConfig retryConfig;
    // Each sandbox's agent feature list from /version (requireToolboxFeatures).
    // A miss refreshes it, because a restart can bring a newer agent.
    private final java.util.concurrent.ConcurrentHashMap<String, java.util.Set<String>> toolboxFeatures =
        new java.util.concurrent.ConcurrentHashMap<>();

    /** One bounded fleet-list page plus the opaque token for the next page. */
    public static final class SandboxPage {
        public final List<Sandbox> sandboxes;
        public final String nextPageToken;

        private SandboxPage(List<Sandbox> sandboxes, String nextPageToken) {
            this.sandboxes = List.copyOf(sandboxes);
            this.nextPageToken = nextPageToken;
        }
    }

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
        // SB_API_TOKEN is an alias of SB_PAT_TOKEN for any bearer; SB_PAT_TOKEN
        // wins when both are set, so existing setups keep the token they had.
        String envPatToken = trimToNull(environment.get("SB_PAT_TOKEN"));
        if (envPatToken == null) {
            envPatToken = trimToNull(environment.get("SB_API_TOKEN"));
        }
        String envApiUrl = trimToNull(environment.get("SB_API_URL"));
        String configuredTeam = trimToNull(effectiveConfig.team);

        this.patToken = configuredPatToken != null ? configuredPatToken : envPatToken != null ? envPatToken : "";
        this.team = configuredTeam != null ? configuredTeam : trimToNull(environment.get("SB_TEAM"));
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

    /** The team sent as {@code X-AerolVM-Team}, or null when none is. */
    public String getTeam() {
        return team;
    }

    /**
     * Who the server says the caller is: principal, role, team and when the
     * credential expires. Every valid credential may ask.
     */
    public WhoAmI whoami() {
        WhoAmI who = doJson("GET", versioned("/whoami"), null, WhoAmI.class);
        if (who == null) {
            who = new WhoAmI();
        }
        if (who.principal == null) {
            who.principal = new ai.aerol.microvm.model.WhoAmIPrincipal();
        }
        return who;
    }

    /** Scoped API tokens ({@code avm_…}) for services and CI: {@code client.tokens().create/list/revoke}. */
    public Tokens tokens() {
        return new Tokens();
    }

    /**
     * Scoped API tokens, reached through {@link MicroVMClient#tokens()}.
     * Creating and revoking needs an admin credential; listing needs an
     * auditor or an admin.
     */
    public final class Tokens {
        private Tokens() {
        }

        /**
         * Mints a token. The result's {@code token} is the secret, returned
         * this once and never again. A 409 means the name is taken, possibly
         * by an earlier attempt whose reply was lost; that secret cannot be
         * recovered, so revoke the token and create it again.
         */
        public CreatedApiToken create(CreateApiTokenOptions options) {
            CreateApiTokenOptions body = options == null ? new CreateApiTokenOptions() : options;
            return doJson("POST", versioned("/tokens"), body, CreatedApiToken.class);
        }

        /**
         * Lists every token, expired ones included ({@code expired} is true)
         * until the server removes them 30 days after expiry. Never a secret.
         */
        public ApiTokenList list() {
            ApiTokenList list = doJson("GET", versioned("/tokens"), null, ApiTokenList.class);
            if (list == null) {
                list = new ApiTokenList();
            }
            if (list.tokens == null) {
                list.tokens = new ArrayList<>();
            }
            return list;
        }

        /**
         * Revokes a token by id ({@code tok_…}). Revoking one that is already
         * gone succeeds, so a retried revoke is safe.
         */
        public void revoke(String id) {
            String trimmed = trimToNull(id);
            if (trimmed == null) {
                throw new MicroVMException("token id is required");
            }
            doNoContent("DELETE", versioned("/tokens/" + encodePathSegment(trimmed)), null);
        }
    }

    /**
     * Creates a sandbox. The request carries an {@code Idempotency-Key}: the
     * caller's {@link CreateOptions#idempotencyKey}, or a random one made for
     * this call. Either way it is sent unchanged on each of the call's
     * automatic retries, so a create retried after a timeout gets back the
     * sandbox the first attempt made instead of making a second one.
     */
    public Sandbox create(CreateOptions options) {
        String key = options == null ? null : trimToNull(options.idempotencyKey);
        if (key == null) {
            key = newIdempotencyKey();
        }
        Sandbox sandbox = wrap(doJson("POST", versioned("/sandboxes"), options, SandboxData.class, RetryMode.IDEMPOTENT,
            Map.of(IDEMPOTENCY_KEY_HEADER, key)));
        return sandbox.setDestroyOnClose(options != null && options.destroyOnClose);
    }

    /** A fresh create key: 128 random bits as 32 lowercase hex characters. */
    static String newIdempotencyKey() {
        byte[] bytes = new byte[16];
        IDEMPOTENCY_KEY_RANDOM.nextBytes(bytes);
        StringBuilder key = new StringBuilder(32);
        for (byte b : bytes) {
            key.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
        }
        return key.toString();
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
        java.util.ArrayList<Sandbox> items = new java.util.ArrayList<>();
        String pageToken = "";
        // Safety cap for cluster page drain (enough for 100k @ page size 1).
        for (int page = 0; page < 100_000; page++) {
            SandboxPage result = listPage(tags, includeEnv, pageToken);
            items.addAll(result.sandboxes);
            pageToken = result.nextPageToken;
            if (pageToken.isEmpty()) {
                return items;
            }
        }
        throw new MicroVMException("incomplete cluster list: exceeded max pages");
    }

    /**
     * Fetches exactly one server page. Fleet inventory callers should loop on
     * {@link SandboxPage#nextPageToken} to keep memory bounded.
     */
    public SandboxPage listPage(java.util.Map<String, String> tags, boolean includeEnv, String pageToken) {
        String basePath = versioned("/sandboxes") + buildSandboxQuery(tags, includeEnv);
        String path = appendQueryParam(basePath, "page_token", pageToken);
        HttpResponse<byte[]> httpResponse = sendJsonRequest("GET", path, null);
        ensureSuccess(httpResponse);
        String partial = headerValue(httpResponse, "X-Cluster-List-Partial");
        String ready = headerValue(httpResponse, "X-Cluster-List-Placement-Ready");
        if ("true".equals(partial) || "false".equals(ready)) {
            throw new MicroVMException("incomplete cluster list");
        }
        SandboxData[] response = JsonSupport.read(httpResponse.body(), SandboxData[].class);
        java.util.ArrayList<Sandbox> items = new java.util.ArrayList<>();
        if (response != null) {
            for (SandboxData item : response) {
                items.add(wrap(item));
            }
        }
        return new SandboxPage(items, headerValue(httpResponse, "X-Cluster-List-Next-Page-Token").trim());
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

    // Renders tag filters and optional include_env as the server's wire
    // format. The "tag." prefix is literal — parseTagFilter on the server
    // checks the *decoded* query key — so only the user-supplied key and
    // value get percent-encoded. Returns "" for null/empty so the URL stays
    // byte-identical to the pre-filter call (no stray trailing "?").
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

    /**
     * Returns the caller's sandbox with this name, or empty if there is none.
     * Names are unique per owner. The reply is only trusted when it holds at
     * most one sandbox carrying the requested name: a server that predates
     * {@code ?name=} ignores the filter and returns an ordinary list page, and
     * acting on its first row would target the wrong sandbox.
     */
    public java.util.Optional<Sandbox> getByName(String name) {
        return getByName(name, false);
    }

    /** {@link #getByName(String)} with optional {@code include_env=true}. */
    public java.util.Optional<Sandbox> getByName(String name, boolean includeEnv) {
        String wanted = name == null ? "" : name.trim();
        if (wanted.isEmpty()) {
            throw new IllegalArgumentException("sandbox name is required");
        }
        String path = appendQueryParam(versioned("/sandboxes") + buildSandboxQuery(null, includeEnv), "name", wanted);
        SandboxData[] response = doJson("GET", path, null, SandboxData[].class);
        if (response == null || response.length == 0) {
            return java.util.Optional.empty();
        }
        if (response.length > 1 || !wanted.equals(response[0].name)) {
            throw new MicroVMException(apiUrl + " does not support sandbox name lookup; use the sandbox ID or upgrade the server");
        }
        return java.util.Optional.of(wrap(response[0]));
    }

    /**
     * Returns the caller's sandbox called {@code name}, creating it from
     * {@code options} when there is none. {@link GetOrCreateResult#isCreated()}
     * is true only when this call made the sandbox.
     *
     * <p>Safe to retry and to run at the same time from many processes. Names
     * are unique per owner, so when two callers race to create the same name,
     * one gets a 409 and reads the winner's sandbox instead; a 409 whose name
     * still cannot be found is a conflict on something else and is thrown as
     * is. An existing sandbox is returned as it is: its image and settings
     * are not compared with {@code options}. {@code options.name} may be null
     * or repeat {@code name}; {@code options} is not changed.
     */
    public GetOrCreateResult getOrCreate(String name, CreateOptions options) {
        String wanted = name == null ? "" : name.trim();
        if (wanted.isEmpty()) {
            throw new IllegalArgumentException("sandbox name is required");
        }
        String given = options == null || options.name == null ? "" : options.name.trim();
        if (!given.isEmpty() && !given.equals(wanted)) {
            throw new IllegalArgumentException("options name \"" + given + "\" differs from \"" + wanted + "\"");
        }
        // destroyOnClose applies only to a sandbox this call creates (create()
        // sets it). One it finds may be in use by another program that shares
        // the name, so it is never deleted on close.
        java.util.Optional<Sandbox> existing = getByName(wanted);
        if (existing.isPresent()) {
            return new GetOrCreateResult(existing.get().setDestroyOnClose(false), false);
        }
        CreateOptions named = copyCreateOptions(options);
        named.name = wanted;
        try {
            return new GetOrCreateResult(create(named), true);
        } catch (MicroVMConflictException e) {
            // Another caller created the name after the lookup.
            java.util.Optional<Sandbox> winner = getByName(wanted);
            if (winner.isEmpty()) {
                throw e;
            }
            return new GetOrCreateResult(winner.get().setDestroyOnClose(false), false);
        }
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
        return createSnapshot(sandboxId, name, null);
    }

    /**
     * Saves a sandbox's files as a snapshot. With {@code allowPause} false, a
     * sandbox that is not stopped is refused (HTTP 409) instead of paused.
     */
    public SandboxSnapshot createSnapshot(String sandboxId, String name, CreateSnapshotOptions options) {
        Boolean allowPause = options == null ? null : options.allowPause;
        return doJson("POST", sandboxPath(sandboxId) + "/snapshot", new CreateSnapshotRequest(name, allowPause), SandboxSnapshot.class);
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

    /** Reads one snapshot from the catalogue by name; 404 if there is none. */
    public SandboxSnapshot getSnapshot(String name) {
        return doJson("GET", snapshotPath(name), null, SandboxSnapshot.class);
    }

    /**
     * Reads one name-ordered page of the caller's snapshots. Pass the last
     * name of the previous page as {@link ListSnapshotsOptions#setStartingAfter}
     * to walk the catalogue; an empty page or a false {@code hasMore} ends it.
     */
    public SnapshotList listSnapshots(ListSnapshotsOptions options) {
        StringBuilder query = new StringBuilder();
        if (options != null) {
            appendQuery(query, "limit", options.getLimit() == null ? null : String.valueOf(options.getLimit()));
            appendQuery(query, "starting_after", options.getStartingAfter());
        }
        SnapshotList page = doJson("GET", versioned("/snapshots") + query, null, SnapshotList.class);
        if (page == null) {
            page = new SnapshotList();
        }
        if (page.snapshots == null) {
            page.snapshots = new ArrayList<>();
        }
        return page;
    }

    public SnapshotList listSnapshots() {
        return listSnapshots(null);
    }

    /** Deletes a snapshot by name; deleting a missing snapshot is a 404. */
    public void deleteSnapshot(String name) {
        doNoContent("DELETE", snapshotPath(name), null);
    }

    private String snapshotPath(String name) {
        return versioned("/snapshots/" + encodePathSegment(name));
    }

    /**
     * Deletes every sandbox of yours that carries all of {@code tags} and
     * returns the IDs of the ones now gone. It lists every page first, then
     * deletes them one at a time. A sandbox that is already gone (404) counts
     * as deleted, so a second call, or two calls at once, is safe. Any other
     * failed delete stops the call and is thrown; the sandboxes already
     * deleted stay deleted, and calling it again finishes the job.
     *
     * @throws IllegalArgumentException when {@code tags} is null or empty:
     *     with no filter it would delete every sandbox you own
     */
    public List<String> destroyAll(java.util.Map<String, String> tags) {
        if (tags == null || tags.isEmpty()) {
            throw new IllegalArgumentException("destroyAll needs at least one tag; with none it would delete every sandbox you own");
        }
        List<String> ids = new ArrayList<>();
        for (Sandbox sandbox : list(tags)) {
            ids.add(sandbox.id);
        }
        List<String> gone = new ArrayList<>(ids.size());
        for (String id : ids) {
            try {
                destroy(id);
            } catch (MicroVMNotFoundException e) {
                // Already gone: someone else deleted it, which is the goal.
            }
            gone.add(id);
        }
        return gone;
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
     * Reads one page of a sandbox's audit log: outbound connections and
     * egress denials (kind {@code "egress"}) and secret reads.
     */
    public AuditPage getAudit(String sandboxId, AuditOptions options) {
        StringBuilder query = new StringBuilder();
        if (options != null) {
            appendQuery(query, "kind", options.getKind());
            appendQuery(query, "limit", options.getLimit() == null ? null : String.valueOf(options.getLimit()));
            appendQuery(query, "cursor", options.getCursor());
            appendQuery(query, "incarnation_id", options.getIncarnationId());
            appendQuery(query, "caller", options.getCaller());
        }
        AuditPage page = doJson("GET", sandboxPath(sandboxId) + "/audit" + query, null, AuditPage.class);
        if (page == null) {
            page = new AuditPage();
        }
        if (page.events == null) {
            page.events = new ArrayList<>();
        }
        if (page.coverage == null) {
            page.coverage = new AuditCoverage();
        }
        return page;
    }

    /**
     * Reads what a sandbox reached in learn mode and the allow list that would
     * have allowed it.
     */
    public NetworkLearned getNetworkLearned(String sandboxId) {
        NetworkLearned learned = doJson("GET", sandboxPath(sandboxId) + "/network/learned", null, NetworkLearned.class);
        if (learned == null) {
            learned = new NetworkLearned();
        }
        if (learned.entries == null) {
            learned.entries = new ArrayList<>();
        }
        for (NetworkLearnedEntry e : learned.entries) {
            if (e.ports == null) {
                e.ports = new ArrayList<>();
            }
        }
        if (learned.cidrs == null) {
            learned.cidrs = new ArrayList<>();
        }
        if (learned.suggestedAllowOut == null) {
            learned.suggestedAllowOut = new ArrayList<>();
        }
        return learned;
    }

    /**
     * Creates or replaces a named egress profile (a full replace: the same body
     * twice is a no-op). A change reaches every sandbox that references it.
     */
    public EgressProfile putEgressProfile(String name, EgressProfileOptions options) {
        EgressProfileOptions body = options == null ? new EgressProfileOptions() : options;
        return withProfileDefaults(doJson("PUT", egressProfilePath(name), body, EgressProfile.class));
    }

    public EgressProfile getEgressProfile(String name) {
        return withProfileDefaults(doJson("GET", egressProfilePath(name), null, EgressProfile.class));
    }

    public EgressProfileList listEgressProfiles(ListEgressProfilesOptions options) {
        StringBuilder query = new StringBuilder();
        if (options != null) {
            appendQuery(query, "cursor", options.getCursor());
            appendQuery(query, "limit", options.getLimit() == null ? null : String.valueOf(options.getLimit()));
        }
        EgressProfileList page = doJson("GET", versioned("/egress-profiles") + query, null, EgressProfileList.class);
        if (page == null) {
            page = new EgressProfileList();
        }
        if (page.profiles == null) {
            page.profiles = new ArrayList<>();
        }
        return page;
    }

    public EgressProfileList listEgressProfiles() {
        return listEgressProfiles(null);
    }

    /** Deletes a profile; one that sandboxes still reference is refused (409). */
    public void deleteEgressProfile(String name) {
        doNoContent("DELETE", egressProfilePath(name), null);
    }

    /**
     * Sets a team's quota: the most sandboxes, CPU and memory its sandboxes
     * may hold. Admin only. The same limits twice change nothing. A create,
     * resize or start past the quota fails with a 429 whose code is
     * {@code team_quota_exceeded}.
     */
    public TeamQuota putTeamQuota(String team, TeamQuotaOptions options) {
        TeamQuotaOptions body = options == null ? new TeamQuotaOptions() : options;
        return doJson("PUT", teamQuotaPath(team), body, TeamQuota.class);
    }

    /** Reads a team's quota and what the team holds now (404 if none). */
    public TeamQuota getTeamQuota(String team) {
        return doJson("GET", teamQuotaPath(team), null, TeamQuota.class);
    }

    /** Removes a team's quota. Removing one that is already gone succeeds. */
    public void deleteTeamQuota(String team) {
        doNoContent("DELETE", teamQuotaPath(team), null);
    }

    private String teamQuotaPath(String team) {
        return versioned("/teams/" + URLEncoder.encode(team, StandardCharsets.UTF_8) + "/quota");
    }

    private String egressProfilePath(String name) {
        return versioned("/egress-profiles/" + URLEncoder.encode(name, StandardCharsets.UTF_8));
    }

    /**
     * Puts a role tag on a team's cloud identity allow list, or changes its
     * minimum caller role ({@code "runner"} or {@code "admin"}). Admin only.
     * The same call twice changes nothing, so it is safe to retry.
     */
    public IdentityRole putIdentityRole(String tag, IdentityRoleOptions options) {
        IdentityRoleOptions body = options == null ? new IdentityRoleOptions() : options;
        return doJson("PUT", identityRolePath(tag, body.getTeam()), body, IdentityRole.class);
    }

    /** Lists a team's cloud identity allow list, one page at a time. Admin only. */
    public IdentityRoleList listIdentityRoles(ListIdentityRolesOptions options) {
        StringBuilder query = new StringBuilder();
        if (options != null) {
            appendQuery(query, "team", options.getTeam());
            appendQuery(query, "cursor", options.getCursor());
            appendQuery(query, "limit", options.getLimit() == null ? null : String.valueOf(options.getLimit()));
        }
        IdentityRoleList page = doJson("GET", versioned("/identity/roles") + query, null, IdentityRoleList.class);
        if (page == null) {
            page = new IdentityRoleList();
        }
        if (page.roles == null) {
            page.roles = new ArrayList<>();
        }
        return page;
    }

    public IdentityRoleList listIdentityRoles() {
        return listIdentityRoles(null);
    }

    /**
     * Takes a role tag off a team's allow list (a null team is the operator
     * namespace). Admin only. Sandboxes that use it keep their current token
     * (at most one hour) and get no new one. Deleting a tag that is already
     * gone succeeds.
     */
    public void deleteIdentityRole(String tag, String team) {
        doNoContent("DELETE", identityRolePath(tag, team), null);
    }

    public void deleteIdentityRole(String tag) {
        deleteIdentityRole(tag, null);
    }

    private String identityRolePath(String tag, String team) {
        StringBuilder query = new StringBuilder();
        appendQuery(query, "team", team);
        return versioned("/identity/roles/" + URLEncoder.encode(tag, StandardCharsets.UTF_8)) + query;
    }

    private static EgressProfile withProfileDefaults(EgressProfile profile) {
        if (profile != null && profile.allowOut == null) {
            profile.allowOut = new ArrayList<>();
        }
        return profile;
    }

    // Warm pools are PUT/GET/DELETE of one entry: every call is safe to
    // retry, so they keep the default (idempotent) retry tier.

    /**
     * Sets how many ready sandboxes every server with a warm pool keeps for an
     * image (a full replace: the same call twice is a no-op). A create that
     * names the image then starts from a warm sandbox. Admin only.
     */
    public WarmPool putWarmPool(String image, WarmPoolOptions options) {
        WarmPoolOptions body = options == null ? new WarmPoolOptions() : options;
        return withWarmPoolDefaults(doJson("PUT", warmPoolPath(image), body, WarmPool.class));
    }

    /** Reads an image's warm-pool entry with its status (ready and target, in total and per server). */
    public WarmPool getWarmPool(String image) {
        return withWarmPoolDefaults(doJson("GET", warmPoolPath(image), null, WarmPool.class));
    }

    /** Reads every warm-pool entry, by image, with its status. */
    public List<WarmPool> listWarmPools() {
        WarmPoolList list = doJson("GET", versioned("/warm-pools"), null, WarmPoolList.class);
        List<WarmPool> out = new ArrayList<>();
        if (list != null && list.pools != null) {
            for (WarmPool pool : list.pools) {
                out.add(withWarmPoolDefaults(pool));
            }
        }
        return out;
    }

    /** Deletes an image's warm-pool entry; its warm sandboxes are removed. Deleting a missing entry succeeds. */
    public void deleteWarmPool(String image) {
        doNoContent("DELETE", warmPoolPath(image), null);
    }

    // An image is the rest of the path: each segment is escaped and the
    // slashes kept, so no proxy has an encoded slash to rewrite. URLEncoder is
    // a form encoder, so its '+' for a space becomes %20 for a path.
    private String warmPoolPath(String image) {
        String[] segments = (image == null ? "" : image).split("/", -1);
        StringBuilder path = new StringBuilder("/warm-pools/");
        for (int i = 0; i < segments.length; i++) {
            if (i > 0) {
                path.append('/');
            }
            path.append(URLEncoder.encode(segments[i], StandardCharsets.UTF_8).replace("+", "%20"));
        }
        return versioned(path.toString());
    }

    private static WarmPool withWarmPoolDefaults(WarmPool pool) {
        if (pool != null && pool.status != null && pool.status.servers == null) {
            pool.status.servers = new ArrayList<>();
        }
        if (pool != null && (pool.onImageChange == null || pool.onImageChange.isEmpty())) {
            pool.onImageChange = WarmPoolOptions.REPLACE_NOW;
        }
        return pool;
    }

    public AuditPage getAudit(String sandboxId) {
        return getAudit(sandboxId, null);
    }

    private static void appendQuery(StringBuilder query, String key, String value) {
        if (value == null || value.isBlank()) {
            return;
        }
        query.append(query.length() == 0 ? '?' : '&').append(key).append('=').append(encodeQueryValue(value));
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

    /**
     * Replaces a sandbox's egress policy while it runs and returns once the new
     * policy is enforced. Sending the same policy again is a no-op, so it is
     * safe to retry.
     */
    public NetworkPolicy setNetworkPolicy(String sandboxId, NetworkPolicyOptions options) {
        NetworkPolicyOptions body = options == null ? new NetworkPolicyOptions() : options;
        return doJson("PUT", sandboxPath(sandboxId) + "/network/policy", body, NetworkPolicy.class);
    }

    /**
     * Runs a command and waits for it to finish. Unlike every other call, a
     * transport failure is retried only when the request provably never left
     * the client (refused or timed-out connect, failed name lookup), or on
     * HTTP 429/503: re-sending after the server may have received it would
     * run the command a second time. Any other failure is thrown to the
     * caller, who knows whether the command is safe to repeat.
     */
    public ExecResult exec(String sandboxId, ExecRequest request) {
        // An older agent ignores the caps and returns all output, and refuses
        // argv with a confusing "command is required"; check first.
        List<String> features = new ArrayList<>();
        if (request != null && (isSet(request.maxStdoutBytes) || isSet(request.maxStderrBytes))) {
            features.add("exec.max_output_bytes");
        }
        if (request != null && request.argv != null && !request.argv.isEmpty()) {
            features.add("exec.argv");
        }
        requireToolboxFeatures(sandboxId, features.toArray(new String[0]));
        return doJson("POST", sandboxPath(sandboxId) + "/toolbox/process/execute", request, ExecResult.class, RetryMode.UNSENT_ONLY);
    }

    /** A cap of 0 or null means none, as on the wire. */
    private static boolean isSet(Long cap) {
        return cap != null && cap != 0;
    }

    public void uploadFile(String sandboxId, String targetPath, byte[] data) {
        uploadFile(sandboxId, targetPath, data, null);
    }

    /**
     * Uploads {@code data} with write options: append, create-only, atomic
     * replace and a file mode. A sandbox whose agent predates them fails with
     * {@link MicroVMUnsupportedFeatureException} instead of ignoring them.
     * Plain and atomic uploads retry on 421/429/502/503/504; append and
     * create-only only on 429/503, because a second send would append twice
     * or find the first one's file.
     */
    public void uploadFile(String sandboxId, String targetPath, byte[] data, UploadFileOptions options) {
        UploadFileOptions opts = options == null ? new UploadFileOptions() : options;
        Map<String, String> query = uploadQuery(sandboxId, opts);
        String boundary = "----microvm-" + UUID.randomUUID();
        byte[] body = buildMultipartBody(boundary, targetPath, data);
        HttpResponse<byte[]> response = sendRequest(
            "POST",
            toolboxPath(sandboxId, "/files/upload", query),
            HttpRequest.BodyPublishers.ofByteArray(body),
            "multipart/form-data; boundary=" + boundary,
            null,
            opts.append || opts.createOnly ? RetryMode.UNSENT_ONLY : RetryMode.IDEMPOTENT
        );
        ensureSuccess(response);
    }

    /** The upload's write options as query, after the /version check they need. */
    private Map<String, String> uploadQuery(String sandboxId, UploadFileOptions options) {
        UploadFileOptions opts = options == null ? new UploadFileOptions() : options;
        Map<String, String> query = new java.util.LinkedHashMap<>();
        if (opts.append) {
            query.put("append", "true");
        }
        if (opts.createOnly) {
            query.put("create_only", "true");
        }
        if (opts.atomic) {
            query.put("atomic", "true");
        }
        if (opts.mode != null) {
            query.put("mode", Integer.toOctalString(opts.mode));
        }
        if (!query.isEmpty()) {
            // An older agent ignores these; create_only would replace a file.
            requireToolboxFeatures(sandboxId, FEATURE_WRITE_OPTIONS);
        }
        return query;
    }

    public byte[] downloadFile(String sandboxId, String targetPath) {
        return downloadFile(sandboxId, targetPath, null);
    }

    /** Reads a whole file, refusing one larger than {@code options.maxBytes}. Retries like any safe call. */
    public byte[] downloadFile(String sandboxId, String targetPath, DownloadFileOptions options) {
        try (java.io.InputStream in = downloadFileStream(sandboxId, targetPath, options)) {
            return in.readAllBytes();
        } catch (MicroVMException ex) {
            throw ex;
        } catch (IOException ex) {
            if (ex.getCause() instanceof MicroVMFileTooLargeException) {
                throw (MicroVMFileTooLargeException) ex.getCause();
            }
            throw new MicroVMException("read " + targetPath + ": " + ex.getMessage(), ex);
        }
    }

    /**
     * Opens a file for reading a piece at a time, so a large file never sits
     * in memory; close the stream when done. With {@code maxBytes}, a larger
     * file is refused before reading when the server states the size, and
     * otherwise the read that passes the limit throws an IOException whose
     * cause is a {@link MicroVMFileTooLargeException}. The request retries
     * until the file starts to arrive (plans/agent-sandbox-feature-parity.md,
     * F4).
     */
    public java.io.InputStream downloadFileStream(String sandboxId, String targetPath, DownloadFileOptions options) {
        HttpResponse<java.io.InputStream> response = send(
            "GET",
            toolboxPath(sandboxId, "/files/download", Map.of("path", targetPath)),
            HttpRequest.BodyPublishers.noBody(),
            null,
            null,
            RetryMode.IDEMPOTENT,
            null,
            HttpResponse.BodyHandlers.ofInputStream()
        );
        java.io.InputStream body = response.body();
        if (response.statusCode() >= 400) {
            byte[] error;
            try (java.io.InputStream in = body) {
                error = in.readAllBytes();
            } catch (IOException ex) {
                error = new byte[0];
            }
            throwApiError(response.statusCode(), response.headers().firstValue("Retry-After").orElse(null), error);
        }
        Long max = options == null ? null : options.maxBytes;
        if (max == null) {
            return body;
        }
        long length = response.headers().firstValueAsLong("Content-Length").orElse(-1);
        if (length > max) {
            try {
                body.close();
            } catch (IOException ignored) {
                // The refusal is the error that matters.
            }
            throw new MicroVMFileTooLargeException(targetPath, max);
        }
        return new CappedInputStream(body, targetPath, max);
    }

    /** Fails the read that would pass the limit, instead of quietly cutting the file short. */
    private static final class CappedInputStream extends java.io.FilterInputStream {
        private final String path;
        private final long max;
        private long left;
        private boolean over;

        CappedInputStream(java.io.InputStream in, String path, long max) {
            super(in);
            this.path = path;
            this.max = max;
            this.left = max;
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (over) {
                throw new IOException(new MicroVMFileTooLargeException(path, max));
            }
            if (len == 0) {
                return 0;
            }
            // Read one byte past the limit to tell "exactly the limit" from "more".
            int n = super.read(b, off, (int) Math.min(len, left + 1));
            if (n > left) {
                // Past the limit: hand over the bytes under it first, as the
                // other SDKs do, and fail the next read.
                int under = (int) left;
                left = 0;
                over = true;
                if (under == 0) {
                    throw new IOException(new MicroVMFileTooLargeException(path, max));
                }
                return under;
            }
            if (n > 0) {
                left -= n;
            }
            return n;
        }
    }

    /**
     * Uploads from {@code data} a piece at a time, so a large file never sits
     * in memory. The options are {@link #uploadFile(String, String, byte[],
     * UploadFileOptions)}'s. The data is read as it is sent, so it is sent
     * once and never retried.
     */
    public void uploadFileStream(String sandboxId, String targetPath, java.io.InputStream data, UploadFileOptions options) {
        String path = toolboxPath(sandboxId, "/files/upload", uploadQuery(sandboxId, options));
        String boundary = "----microvm-" + UUID.randomUUID();
        byte[] head = ("--" + boundary + "\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n" + targetPath + "\r\n"
            + "--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + baseName(targetPath) + "\"\r\n"
            + "Content-Type: application/octet-stream\r\n\r\n").getBytes(StandardCharsets.UTF_8);
        byte[] tail = ("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8);
        HttpRequest.BodyPublisher body = HttpRequest.BodyPublishers.ofInputStream(() -> new java.io.SequenceInputStream(
            java.util.Collections.enumeration(List.of(new java.io.ByteArrayInputStream(head), data, new java.io.ByteArrayInputStream(tail)))));
        ensureSuccess(sendRequest("POST", path, body, "multipart/form-data; boundary=" + boundary, null, RetryMode.NEVER));
    }

    // File verbs beyond upload and download (plans/agent-sandbox-feature-
    // parity.md, F1), through the sandbox's toolbox. A sandbox whose agent
    // predates them fails closed with MicroVMUnsupportedFeatureException
    // instead of ignoring a safety option; WASM and V8 isolate sandboxes
    // answer HTTP 501.
    //
    // Retries: listFiles, getFileInfo, fileExists, searchFiles, findInFiles,
    // deleteFile and makeDir are safe to re-send and retry on 421, 429, 502,
    // 503 and 504 (a retried delete or mkdir whose work is already done counts
    // as success). moveFile and copyFile retry only on 429 and 503, because a
    // lost reply may hide a move that happened.

    /**
     * The toolboxd feature (on /version) behind the file verbs' options: list
     * depth and cap, the move and copy overwrite guard, mkdir without parents
     * and the copy route. An older agent ignores those options
     * (overwrite=false would overwrite), so the calls that send them check
     * first.
     */
    static final String FEATURE_FILE_VERBS = "files.verbs";

    /** The toolboxd feature behind upload's write options. */
    static final String FEATURE_WRITE_OPTIONS = "files.write_options";

    /** The toolboxd feature behind upload's extract=true ({@link #uploadDir}). */
    static final String FEATURE_EXTRACT = "files.extract";

    /**
     * Copies the local folder {@code localDir} into {@code remoteDir} in the
     * sandbox (made if missing). The folder is packed as a gzipped tar and the
     * sandbox unpacks it safely: no entry can land outside {@code remoteDir}.
     * Symlinks are sent as links, hard-linked files as separate files;
     * devices, pipes and sockets are skipped. The archive is built in memory
     * and sent once, never retried.
     */
    public void uploadDir(String sandboxId, java.nio.file.Path localDir, String remoteDir) {
        if (!java.nio.file.Files.isDirectory(localDir)) {
            throw new MicroVMException(localDir + " is not a folder");
        }
        // An older agent ignores extract and stores the archive as a file.
        requireToolboxFeatures(sandboxId, FEATURE_EXTRACT);
        byte[] archive;
        try {
            archive = ai.aerol.microvm.internal.TarWriter.gzippedFolder(localDir);
        } catch (IOException ex) {
            throw new MicroVMException("pack " + localDir + ": " + ex.getMessage(), ex);
        }
        String boundary = "----microvm-" + UUID.randomUUID();
        byte[] body = buildMultipartBody(boundary, remoteDir, archive);
        HttpResponse<byte[]> response = sendRequest(
            "POST",
            toolboxPath(sandboxId, "/files/upload", Map.of("extract", "true")),
            HttpRequest.BodyPublishers.ofByteArray(body),
            "multipart/form-data; boundary=" + boundary,
            null,
            RetryMode.NEVER
        );
        ensureSuccess(response);
    }

    private String toolboxPath(String sandboxId, String route, Map<String, String> query) {
        StringBuilder path = new StringBuilder(sandboxPath(sandboxId)).append("/toolbox").append(route);
        char sep = '?';
        for (Map.Entry<String, String> entry : query.entrySet()) {
            path.append(sep).append(encodeQueryValue(entry.getKey())).append('=').append(encodeQueryValue(entry.getValue()));
            sep = '&';
        }
        return path.toString();
    }

    /** Lists a folder. The listing's {@code truncated} says more entries exist. */
    public FileList listFiles(String sandboxId, String path, ListFilesOptions options) {
        ListFilesOptions opts = options == null ? new ListFilesOptions() : options;
        if (opts.depth < 1 || opts.limit < 1) {
            throw new MicroVMException("depth and limit must be at least 1");
        }
        requireToolboxFeatures(sandboxId, FEATURE_FILE_VERBS);
        Map<String, String> query = new java.util.LinkedHashMap<>();
        query.put("path", path);
        query.put("depth", Integer.toString(opts.depth));
        query.put("limit", Integer.toString(opts.limit));
        query.put("extended", "true");
        HttpResponse<byte[]> response = sendRequest("GET", toolboxPath(sandboxId, "/files", query), HttpRequest.BodyPublishers.noBody(), null);
        ensureSuccess(response);
        FileInfoWire[] items = response.body().length == 0 ? null : JsonSupport.read(response.body(), FileInfoWire[].class);
        FileList list = new FileList();
        String base = path.replaceAll("/+$", "");
        if (items != null) {
            for (FileInfoWire item : items) {
                list.entries.add(item.toFileInfo(base + "/" + (item.name == null ? "" : item.name)));
            }
        }
        list.truncated = "true".equals(response.headers().firstValue("X-Toolbox-Truncated").orElse(null));
        return list;
    }

    public FileList listFiles(String sandboxId, String path) {
        return listFiles(sandboxId, path, null);
    }

    /** Describes one path. A symlink is followed. */
    public FileInfo getFileInfo(String sandboxId, String path) {
        // extended=true only adds fields; an older agent that ignores it
        // answers fields this still reads, so no /version check.
        Map<String, String> query = new java.util.LinkedHashMap<>();
        query.put("path", path);
        query.put("extended", "true");
        FileInfoWire wire = doJson("GET", toolboxPath(sandboxId, "/files/info", query), null, FileInfoWire.class);
        return (wire == null ? new FileInfoWire() : wire).toFileInfo(path);
    }

    /** Whether a path exists. A missing sandbox throws; it is not {@code false}. */
    public boolean fileExists(String sandboxId, String path) {
        try {
            getFileInfo(sandboxId, path);
            return true;
        } catch (MicroVMApiException err) {
            if (isMissingFile(err)) {
                return false;
            }
            throw err;
        }
    }

    /**
     * A missing file, not a missing sandbox (also a 404). Current agents say
     * file_not_found; older ones send no code, but their message is the OS
     * error, which ends "no such file or directory".
     */
    private static boolean isMissingFile(MicroVMApiException err) {
        if (err.getStatusCode() != 404) {
            return false;
        }
        return "file_not_found".equals(err.getCode())
            || (err.getCode() == null && err.getMessage() != null && err.getMessage().endsWith("no such file or directory"));
    }

    /** Deletes a file, or a folder and its contents with {@code recursive}. */
    public void deleteFile(String sandboxId, String path, DeleteFileOptions options) {
        Map<String, String> query = new java.util.LinkedHashMap<>();
        query.put("path", path);
        if (options != null && options.recursive) {
            query.put("recursive", "true");
        }
        fileCall("DELETE", toolboxPath(sandboxId, "/files", query), RetryMode.IDEMPOTENT, "file_not_found");
    }

    public void deleteFile(String sandboxId, String path) {
        deleteFile(sandboxId, path, null);
    }

    /** Makes a folder; with {@code parents}, like {@code mkdir -p}. */
    public void makeDir(String sandboxId, String path, MakeDirOptions options) {
        MakeDirOptions opts = options == null ? new MakeDirOptions() : options;
        if (!opts.parents) {
            // An older agent ignores parents=false and makes them anyway.
            requireToolboxFeatures(sandboxId, FEATURE_FILE_VERBS);
        }
        Map<String, String> query = new java.util.LinkedHashMap<>();
        query.put("path", path);
        query.put("parents", Boolean.toString(opts.parents));
        if (opts.mode != null) {
            query.put("mode", Integer.toOctalString(opts.mode));
        }
        fileCall("POST", toolboxPath(sandboxId, "/files/folder", query), RetryMode.IDEMPOTENT, "folder_exists");
    }

    public void makeDir(String sandboxId, String path) {
        makeDir(sandboxId, path, null);
    }

    /** Moves or renames a file or folder. Without {@code overwrite}, an existing destination is refused (HTTP 409). */
    public void moveFile(String sandboxId, String source, String destination, MoveFileOptions options) {
        boolean overwrite = options != null && options.overwrite;
        if (!overwrite) {
            // An older agent ignores overwrite=false and replaces the file.
            requireToolboxFeatures(sandboxId, FEATURE_FILE_VERBS);
        }
        Map<String, String> query = new java.util.LinkedHashMap<>();
        query.put("source", source);
        query.put("destination", destination);
        query.put("overwrite", Boolean.toString(overwrite));
        fileCall("POST", toolboxPath(sandboxId, "/files/move", query), RetryMode.UNSENT_ONLY, null);
    }

    public void moveFile(String sandboxId, String source, String destination) {
        moveFile(sandboxId, source, destination, null);
    }

    /** Copies a file, or a folder with {@code recursive} (keeping modes and symlinks). */
    public void copyFile(String sandboxId, String source, String destination, CopyFileOptions options) {
        CopyFileOptions opts = options == null ? new CopyFileOptions() : options;
        requireToolboxFeatures(sandboxId, FEATURE_FILE_VERBS);
        Map<String, String> query = new java.util.LinkedHashMap<>();
        query.put("source", source);
        query.put("destination", destination);
        query.put("overwrite", Boolean.toString(opts.overwrite));
        query.put("recursive", Boolean.toString(opts.recursive));
        fileCall("POST", toolboxPath(sandboxId, "/files/copy", query), RetryMode.UNSENT_ONLY, null);
    }

    public void copyFile(String sandboxId, String source, String destination) {
        copyFile(sandboxId, source, destination, null);
    }

    /** Paths under {@code path} whose name matches a glob such as {@code *.java}. */
    public List<String> searchFiles(String sandboxId, String path, String pattern) {
        Map<String, String> query = new java.util.LinkedHashMap<>();
        query.put("path", path);
        query.put("pattern", pattern);
        SearchFilesResponse found = doJson("GET", toolboxPath(sandboxId, "/files/search", query), null, SearchFilesResponse.class);
        return found == null || found.files == null ? new ArrayList<>() : found.files;
    }

    /** Each line under {@code path} that contains {@code text} (plain text). */
    public List<FileMatch> findInFiles(String sandboxId, String path, String text) {
        Map<String, String> query = new java.util.LinkedHashMap<>();
        query.put("path", path);
        query.put("pattern", text);
        FileMatch[] matches = doJson("GET", toolboxPath(sandboxId, "/files/find", query), null, FileMatch[].class);
        return matches == null ? new ArrayList<>() : new ArrayList<>(java.util.Arrays.asList(matches));
    }

    /** A body-less file call whose success reply is discarded. */
    private void fileCall(String method, String path, RetryMode retryMode, String doneCode) {
        HttpResponse<byte[]> response = sendRequest(method, path, HttpRequest.BodyPublishers.noBody(), null, null, retryMode, doneCode);
        if (response != null) {
            ensureSuccess(response);
        }
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
        String visibility = options != null && options.visibility != null && !options.visibility.isEmpty() ? options.visibility : null;
        // Only what the caller set: an omitted visibility keeps an exposed
        // port's gate, so a plain retry never opens a token port.
        Object body = protocol == ExposeProtocol.HTTP && visibility == null
            ? null
            : new ExposePortRequest(protocol == ExposeProtocol.HTTP ? null : protocol.getWireValue(), visibility);
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
     * Issue a signed token scoped to one sandbox ({@code POST
     * /v1/sandboxes/{id}/tokens}), to hand to a browser or an end user. Not
     * idempotent by nature: every call makes a new token and the server
     * stores none. It uses the normal retry tier: a retry after a lost
     * answer makes a second token nobody holds, which simply expires.
     */
    public SandboxToken createSandboxToken(String sandboxId, CreateSandboxTokenOptions options) {
        CreateSandboxTokenOptions body = options == null ? new CreateSandboxTokenOptions() : options;
        return doJson("POST", sandboxPath(sandboxId) + "/tokens", body, SandboxToken.class);
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

    @com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL)
    static class ExposePortRequest {
        public final String protocol;
        public final String visibility;

        ExposePortRequest(String protocol, String visibility) {
            this.protocol = protocol;
            this.visibility = visibility;
        }
    }

    @com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL)
    static class CreateSnapshotRequest {
        public final String name;
        @com.fasterxml.jackson.annotation.JsonProperty("allow_pause")
        public final Boolean allowPause;

        CreateSnapshotRequest(String name, Boolean allowPause) {
            this.name = name;
            this.allowPause = allowPause;
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

    /**
     * Asks whether a sandbox created with these egress fields would reach a
     * destination, with the same matcher the filter enforces. No sandbox is
     * needed.
     */
    public NetworkPolicyCheckResult checkNetworkPolicy(NetworkPolicyCheckOptions options) {
        return doJson("POST", versioned("/network/policy/check"), options, NetworkPolicyCheckResult.class);
    }

    public ExecStreamHandle execStream(String sandboxId, ExecStreamOptions options) {
        ExecStreamOptions effective = options == null ? new ExecStreamOptions() : options;
        boolean hasCommand = trimToNull(effective.command) != null;
        boolean hasArgv = effective.argv != null && !effective.argv.isEmpty();
        if (hasCommand && hasArgv) {
            throw new MicroVMException("set command or argv, not both");
        }
        if (!hasCommand && !hasArgv) {
            throw new MicroVMException("command is required");
        }
        if (hasArgv) {
            // Before the socket opens, so an older agent never gets a start
            // message it cannot run.
            requireToolboxFeatures(sandboxId, "exec.argv");
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

        StreamingWebSocket socket = webSocketConnector.connect(webSocketUri(sandboxPath(sandboxId) + "/toolbox/process/exec/stream"), webSocketHeaders(), listener);
        socketRef.set(socket);
        socket.sendText(JsonSupport.write(effective));
        return new ExecStreamHandle(socket, completion);
    }

    /**
     * Watches a folder in the sandbox for changes and calls {@code onEvent}
     * for each one, in order, on the socket's reader thread. Returns once the
     * watch is in place, so a file changed after this returns is seen.
     *
     * <p>Watching works on gVisor and Firecracker sandboxes only; others
     * answer 501 ({@link MicroVMApiException}). A sandbox whose agent predates
     * file watching throws {@link MicroVMUnsupportedFeatureException}. The
     * handshake is a stream, so it is sent once and never retried.
     */
    public FileWatchHandle watchFiles(String sandboxId, String path, WatchOptions options, Consumer<FileEvent> onEvent) {
        if (trimToNull(sandboxId) == null) {
            throw new MicroVMException("sandbox id is required");
        }
        if (trimToNull(path) == null) {
            throw new MicroVMException("path is required");
        }
        if (onEvent == null) {
            throw new MicroVMException("onEvent is required");
        }
        String query = "?path=" + encodeQueryValue(path);
        if (options != null && options.recursive) {
            query += "&recursive=true";
        }
        FileWatchHandle handle = new FileWatchHandle(onEvent);
        StreamingWebSocket socket;
        try {
            socket = webSocketConnector.connect(
                webSocketUri(sandboxPath(sandboxId) + "/toolbox/files/watch" + query),
                webSocketHeaders(),
                handle.listener()
            );
        } catch (WebSocketHandshakeFailure failure) {
            throw watchHandshakeError(sandboxId, failure);
        }
        handle.attach(socket);
        handle.awaitStart(WATCH_START_TIMEOUT);
        return handle;
    }

    /**
     * A 404 that says the route itself is missing (toolboxd marks it with
     * {@code X-Toolbox-Route: none}; one built before that mark says just
     * "not found") means the agent predates file watching. sandboxd's own 404
     * says "sandbox not found", and a missing folder "path not found: ...",
     * so neither is mistaken for it.
     */
    private RuntimeException watchHandshakeError(String sandboxId, WebSocketHandshakeFailure failure) {
        int status = failure.getStatusCode();
        byte[] body = failure.getBody().getBytes(StandardCharsets.UTF_8);
        ErrorResponse error = JsonSupport.tryRead(body, ErrorResponse.class);
        String route = failure.header("X-Toolbox-Route");
        if (status == 404 && (route != null && "none".equals(route.trim()) || error != null && "not found".equals(error.error))) {
            return new MicroVMUnsupportedFeatureException(sandboxId, List.of("files.watch"), "");
        }
        return apiException(status, failure.header("Retry-After"), body);
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
            webSocketHeaders(),
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
        copy.name = source.name;
        copy.tags = source.tags;
        copy.cpu = source.cpu;
        copy.memoryMb = source.memoryMb;
        copy.diskGb = source.diskGb;
        copy.env = source.env;
        copy.osUser = source.osUser;
        copy.networkBlockAll = source.networkBlockAll;
        copy.networkAllowOut = source.networkAllowOut;
        copy.networkDenyOut = source.networkDenyOut;
        copy.egressProfiles = source.egressProfiles;
        copy.networkEgressMode = source.networkEgressMode;
        copy.networkEgressRules = source.networkEgressRules;
        copy.allowPublicTraffic = source.allowPublicTraffic;
        copy.maskRequestHost = source.maskRequestHost;
        copy.networkBytesInLimit = source.networkBytesInLimit;
        copy.networkBytesOutLimit = source.networkBytesOutLimit;
        copy.registry = source.registry;
        copy.containerCommand = source.containerCommand;
        copy.mounts = source.mounts;
        copy.platformVolumes = source.platformVolumes;
        copy.lifecycle = source.lifecycle;
        copy.failover = source.failover;
        copy.placement = source.placement;
        copy.runtime = source.runtime;
        copy.durability = source.durability;
        copy.moduleRef = source.moduleRef;
        copy.tenantId = source.tenantId;
        copy.gpus = source.gpus;
        copy.customDomains = source.customDomains;
        copy.templateId = source.templateId;
        copy.idempotencyKey = source.idempotencyKey;
        copy.destroyOnClose = source.destroyOnClose;
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

    /**
     * Fails closed unless the sandbox's agent lists every feature on
     * /version. toolboxd ignores request options it does not know, so sending
     * a newer option to an older agent would silently skip it.
     */
    void requireToolboxFeatures(String sandboxId, String... features) {
        if (features.length == 0) {
            return;
        }
        java.util.Set<String> have = toolboxFeatures.get(sandboxId);
        String agentVersion = "";
        String runtime = "";
        if (have == null || !have.containsAll(java.util.Arrays.asList(features))) {
            ToolboxVersion info = doJson("GET", sandboxPath(sandboxId) + "/toolbox/version", null, ToolboxVersion.class);
            have = info == null || info.features == null ? java.util.Set.of() : java.util.Set.copyOf(info.features);
            toolboxFeatures.put(sandboxId, have);
            agentVersion = info == null || info.version == null ? "" : info.version;
            runtime = info == null || info.runtime == null ? "" : info.runtime;
        }
        List<String> missing = new ArrayList<>();
        for (String feature : features) {
            if (!have.contains(feature)) {
                missing.add(feature);
            }
        }
        if (!missing.isEmpty()) {
            throw new MicroVMUnsupportedFeatureException(sandboxId, missing, agentVersion, runtime);
        }
    }

    private <T> T doJson(String method, String path, Object payload, Class<T> responseType) {
        return doJson(method, path, payload, responseType, RetryMode.IDEMPOTENT);
    }

    private <T> T doJson(String method, String path, Object payload, Class<T> responseType, RetryMode retryMode) {
        return doJson(method, path, payload, responseType, retryMode, null);
    }

    /** {@code extraHeaders} are set on every attempt, so a retry carries them unchanged. */
    private <T> T doJson(String method, String path, Object payload, Class<T> responseType, RetryMode retryMode, Map<String, String> extraHeaders) {
        HttpResponse<byte[]> response = sendJsonRequest(method, path, payload, retryMode, extraHeaders);
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
        return sendJsonRequest(method, path, payload, RetryMode.IDEMPOTENT);
    }

    private HttpResponse<byte[]> sendJsonRequest(String method, String path, Object payload, RetryMode retryMode) {
        return sendJsonRequest(method, path, payload, retryMode, null);
    }

    private HttpResponse<byte[]> sendJsonRequest(String method, String path, Object payload, RetryMode retryMode, Map<String, String> extraHeaders) {
        if (payload == null) {
            return sendRequest(method, path, HttpRequest.BodyPublishers.noBody(), null, extraHeaders, retryMode);
        }
        byte[] body = JsonSupport.writeBytes(payload);
        return sendRequest(method, path, HttpRequest.BodyPublishers.ofByteArray(body), "application/json", extraHeaders, retryMode);
    }

    private HttpResponse<byte[]> sendRequest(String method, String path, HttpRequest.BodyPublisher bodyPublisher, String contentType) {
        return sendRequest(method, path, bodyPublisher, contentType, null);
    }

    private HttpResponse<byte[]> sendRequest(String method, String path, HttpRequest.BodyPublisher bodyPublisher, String contentType, Map<String, String> extraHeaders) {
        return sendRequest(method, path, bodyPublisher, contentType, extraHeaders, RetryMode.IDEMPOTENT);
    }

    private HttpResponse<byte[]> sendRequest(String method, String path, HttpRequest.BodyPublisher bodyPublisher, String contentType, Map<String, String> extraHeaders, RetryMode retryMode) {
        return sendRequest(method, path, bodyPublisher, contentType, extraHeaders, retryMode, null);
    }

    /**
     * {@code doneCode} is for a call whose retry can find its own work done
     * (a delete finds the path gone, a mkdir its folder): when a re-sent
     * attempt, never the first, gets an error carrying that toolbox error
     * code, the first attempt's reply was lost and this returns {@code null}
     * for success. Without a {@code doneCode} it never returns {@code null}.
     */
    private HttpResponse<byte[]> sendRequest(String method, String path, HttpRequest.BodyPublisher bodyPublisher, String contentType, Map<String, String> extraHeaders, RetryMode retryMode, String doneCode) {
        return send(method, path, bodyPublisher, contentType, extraHeaders, retryMode, doneCode, HttpResponse.BodyHandlers.ofByteArray());
    }

    /**
     * The retry loop itself, for any body handler: a download streams its
     * body ({@code ofInputStream}) and is retried only until the response
     * arrives. {@code doneCode} needs a byte[] body.
     */
    private <T> HttpResponse<T> send(String method, String path, HttpRequest.BodyPublisher bodyPublisher, String contentType, Map<String, String> extraHeaders, RetryMode retryMode, String doneCode, HttpResponse.BodyHandler<T> handler) {
        int maxRetries = retryConfig.maxRetries != null ? retryConfig.maxRetries : 3;
        int baseDelay = retryConfig.baseDelayMs != null ? retryConfig.baseDelayMs : 200;
        int maxDelay = retryConfig.maxDelayMs != null ? retryConfig.maxDelayMs : 5000;
        int maxRetryAfter = retryConfig.maxRetryAfterMs != null ? retryConfig.maxRetryAfterMs : RetryAfter.DEFAULT_MAX_RETRY_AFTER_MS;

        Exception lastException = null;

        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            String retryAfter = null;
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
            if (team != null) {
                builder.header(TEAM_HEADER, team);
            }

            try {
                HttpResponse<T> response = httpClient.send(builder.build(), handler);
                if (doneCode != null && attempt > 0 && response.statusCode() >= 400
                    && response.body() instanceof byte[] && doneCode.equals(errorCode((byte[]) response.body()))) {
                    return null;
                }
                if (attempt < maxRetries && retryMode.retriesStatus(response.statusCode())) {
                    // Fall through to retry logic
                    retryAfter = RetryAfter.hint(response);
                    if (response.body() instanceof java.io.InputStream) {
                        // Free the connection before the wait.
                        ((java.io.InputStream) response.body()).close();
                    }
                } else {
                    return response;
                }
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                throw new MicroVMException("request interrupted", ex);
            } catch (IOException ex) {
                if (!retryMode.retriesTransportFailure(ex)) {
                    throw new MicroVMException("request failed and was not retried because the server may already have received it", ex);
                }
                lastException = ex;
                if (attempt >= maxRetries) {
                    break;
                }
            }

            // A 429 or 503 waits as long as its Retry-After asks, within
            // maxRetryAfterMs. An interrupt (Future.cancel(true), executor
            // shutdown) ends the wait at once.
            long waitMs = RetryAfter.waitMillis(baseDelay, maxDelay, maxRetryAfter, attempt, retryAfter, java.time.Instant.now(), Math.random());
            try {
                Thread.sleep(waitMs);
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

    private static String errorCode(byte[] body) {
        ErrorResponse error = JsonSupport.tryRead(body, ErrorResponse.class);
        return error == null ? null : error.code;
    }

    private void ensureSuccess(HttpResponse<byte[]> response) {
        if (response.statusCode() >= 400) {
            throw apiException(response.statusCode(), response.headers().firstValue("Retry-After").orElse(null), response.body());
        }
    }

    // Throws the API error for a failed response; the streaming download
    // paths call it where a value-returning helper would not read well.
    private static void throwApiError(int status, String retryAfterHeader, byte[] body) {
        throw apiException(status, retryAfterHeader, body);
    }

    private static MicroVMApiException apiException(int status, String retryAfterHeader, byte[] body) {
        java.time.Duration retryAfter = RetryAfter.parse(retryAfterHeader, java.time.Instant.now());
        ErrorResponse error = body == null ? null : JsonSupport.tryRead(body, ErrorResponse.class);
        if (error != null && error.error != null && !error.error.isEmpty()) {
            String code = error.code == null || error.code.isEmpty() ? null : error.code;
            return MicroVMApiException.forStatus(status, code, error.error, retryAfter);
        }
        return MicroVMApiException.forStatus(status, null, "request failed with status " + status, retryAfter);
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

        // Swap the scheme on the raw text: rebuilding from the decoded parts
        // would turn an escaped '&' or '=' in a query value (a watched path)
        // into a real separator.
        return URI.create(websocketScheme + uri.toString().substring(scheme.length()));
    }

    private String authorizationHeaderValue() {
        return "Bearer " + patToken;
    }

    /** The WebSocket handshake headers: the same credential and team as every HTTP request. */
    private Map<String, String> webSocketHeaders() {
        Map<String, String> headers = new java.util.LinkedHashMap<>();
        headers.put("Authorization", authorizationHeaderValue());
        if (team != null) {
            headers.put(TEAM_HEADER, team);
        }
        return headers;
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

    /**
     * What {@code sendRequest} may re-send after a failure. A transport error
     * does not mean the request never reached the server: a read timeout,
     * reset or EOF can arrive after the server received the body and started
     * the work.
     */
    enum RetryMode {
        /**
         * The default. The daemon designs these endpoints so a re-sent request
         * is harmless, so any transport failure is retried, as are 421
         * (misdirected: connection coalescing or a stale route; the server
         * closed the connection, so the retry reconnects), 429, 502, 503 and
         * 504.
         */
        IDEMPOTENT {
            @Override
            boolean retriesStatus(int status) {
                return status == 421 || status == 429 || status == 502 || status == 503 || status == 504;
            }

            @Override
            boolean retriesTransportFailure(IOException error) {
                return true;
            }
        },
        /**
         * For requests whose re-send repeats a side effect (exec runs the
         * command again). 429 and 503 are the daemon refusing before it starts
         * the work. 502 and 504 come from a proxy that may have handed the
         * request upstream before failing, and 421 does not prove the work did
         * not start either, so they surface. Of transport failures, only
         * connect-phase ones are retried.
         */
        /**
         * For a body plan section 10 says is sent once and never re-sent (a
         * folder upload): no status and no transport failure is retried.
         */
        NEVER {
            @Override
            boolean retriesStatus(int status) {
                return false;
            }

            @Override
            boolean retriesTransportFailure(IOException error) {
                return false;
            }
        },
        UNSENT_ONLY {
            @Override
            boolean retriesStatus(int status) {
                return status == 429 || status == 503;
            }

            @Override
            boolean retriesTransportFailure(IOException error) {
                // java.net.http reports every connect-phase failure (refused,
                // unresolvable host, no route) as ConnectException and a connect
                // timeout as HttpConnectTimeoutException; neither is ever thrown
                // once the request is on the wire. The other two cover a
                // caller-supplied HttpClient that surfaces the raw cause. A plain
                // HttpTimeoutException is the response timeout, so it is not here.
                return error instanceof java.net.ConnectException
                    || error instanceof java.net.http.HttpConnectTimeoutException
                    || error instanceof java.net.UnknownHostException
                    || error instanceof java.net.NoRouteToHostException;
            }
        };

        abstract boolean retriesStatus(int status);

        abstract boolean retriesTransportFailure(IOException error);
    }

    private static final class ToolboxVersion {
        public String version;
        public List<String> features;
        public String runtime;
    }

    /**
     * toolboxd's file info with extended=true. An older agent ignores
     * extended and sends only Daytona's fields (a 32-bit size, no path), so
     * each extended field falls back.
     */
    private static final class FileInfoWire {
        public String name;
        @com.fasterxml.jackson.annotation.JsonProperty("isDir")
        public boolean isDir;
        public long size;
        public Long sizeBytes;
        public String path;
        public String mode;
        public String permissions;
        public String owner;
        public String group;
        @com.fasterxml.jackson.annotation.JsonProperty("modTime")
        public String modTime;
        public String symlinkTarget;

        FileInfo toFileInfo(String fallbackPath) {
            FileInfo info = new FileInfo();
            info.name = name == null ? "" : name;
            info.path = path == null || path.isEmpty() ? fallbackPath : path;
            info.isDir = isDir;
            info.size = sizeBytes != null ? sizeBytes : size;
            info.mode = mode == null ? "" : mode;
            info.permissions = permissions == null ? "" : permissions;
            info.owner = owner == null ? "" : owner;
            info.group = group == null ? "" : group;
            info.modTime = modTime == null ? "" : modTime;
            info.symlinkTarget = symlinkTarget;
            return info;
        }
    }

    private static final class SearchFilesResponse {
        public List<String> files;
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
        public String code;
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
