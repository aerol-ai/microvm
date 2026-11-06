package ai.aerol.microvm;

import java.util.List;

import ai.aerol.microvm.model.AuditOptions;
import ai.aerol.microvm.model.AuditPage;
import ai.aerol.microvm.model.CloneGeneration;
import ai.aerol.microvm.model.CopyFileOptions;
import ai.aerol.microvm.model.DeleteFileOptions;
import ai.aerol.microvm.model.FileInfo;
import ai.aerol.microvm.model.FileList;
import ai.aerol.microvm.model.FileMatch;
import ai.aerol.microvm.model.ListFilesOptions;
import ai.aerol.microvm.model.MakeDirOptions;
import ai.aerol.microvm.model.MoveFileOptions;
import ai.aerol.microvm.model.UploadFileOptions;
import ai.aerol.microvm.model.CreateSnapshotOptions;
import ai.aerol.microvm.model.CreateSessionOptions;
import ai.aerol.microvm.model.CustomDomain;
import ai.aerol.microvm.model.CustomDomainDnsRecords;
import ai.aerol.microvm.model.ExecRequest;
import ai.aerol.microvm.model.ExecResult;
import ai.aerol.microvm.model.ExecStreamOptions;
import ai.aerol.microvm.model.ExposeOptions;
import ai.aerol.microvm.model.NetworkLearned;
import ai.aerol.microvm.model.NetworkPolicy;
import ai.aerol.microvm.model.NetworkPolicyOptions;
import ai.aerol.microvm.model.ExposeResult;
import ai.aerol.microvm.model.FileEvent;
import ai.aerol.microvm.model.Lifecycle;
import ai.aerol.microvm.model.NetworkUsage;
import ai.aerol.microvm.model.ResizeOptions;
import ai.aerol.microvm.model.SandboxData;
import ai.aerol.microvm.model.SandboxSnapshot;
import ai.aerol.microvm.model.Session;
import ai.aerol.microvm.model.SessionAttachOptions;
import ai.aerol.microvm.model.SetNetworkLimitsOptions;
import ai.aerol.microvm.model.WatchOptions;

public class Sandbox extends SandboxData {
    private final MicroVMClient client;

    Sandbox(MicroVMClient client, SandboxData data) {
        this.client = client;
        apply(data);
    }

    public SandboxData toData() {
        return copy();
    }

    public Sandbox refresh() {
        apply(client.get(id));
        return this;
    }

    public ExecResult exec(ExecRequest request) {
        return client.exec(id, request);
    }

    public ExecResult exec(String command) {
        return client.exec(id, new ExecRequest().setCommand(command));
    }

    /**
     * Reads this sandbox's clone-generation token (changes on
     * resume-from-snapshot). Read-only; does not reseed in-guest PRNGs.
     */
    public CloneGeneration cloneGeneration() {
        return client.cloneGeneration(id);
    }

    public ExecStreamHandle execStream(ExecStreamOptions options) {
        return client.execStream(id, options);
    }

    public Session createSession(CreateSessionOptions options) {
        return client.createSession(id, options);
    }

    public List<Session> listSessions() {
        return client.listSessions(id);
    }

    public Session getSession(String sessionId) {
        return client.getSession(id, sessionId);
    }

    public void deleteSession(String sessionId) {
        client.deleteSession(id, sessionId);
    }

    public void signalSession(String sessionId, String signal) {
        client.signalSession(id, sessionId, signal);
    }

    public void resizeSession(String sessionId, int cols, int rows) {
        client.resizeSession(id, sessionId, cols, rows);
    }

    public byte[] sessionLog(String sessionId) {
        return client.sessionLog(id, sessionId);
    }

    public byte[] sessionRecording(String sessionId) {
        return client.sessionRecording(id, sessionId);
    }

    /**
     * Watches a folder in this sandbox for changes; see
     * {@link MicroVMClient#watchFiles(String, String, WatchOptions, java.util.function.Consumer)}.
     */
    public FileWatchHandle watchFiles(String path, WatchOptions options, java.util.function.Consumer<FileEvent> onEvent) {
        return client.watchFiles(id, path, options, onEvent);
    }

    public SessionAttachHandle attachSession(String sessionId, SessionAttachOptions options) {
        return client.attachSession(id, sessionId, options);
    }

    public void uploadFile(String targetPath, byte[] data) {
        client.uploadFile(id, targetPath, data);
    }

    /** Uploads with write options: append, create-only, atomic replace and a mode. */
    public void uploadFile(String targetPath, byte[] data, UploadFileOptions options) {
        client.uploadFile(id, targetPath, data, options);
    }

    /** Copies a local folder into the sandbox. See {@link MicroVMClient#uploadDir}. */
    public void uploadDir(java.nio.file.Path localDir, String remoteDir) {
        client.uploadDir(id, localDir, remoteDir);
    }

    public byte[] downloadFile(String targetPath) {
        return client.downloadFile(id, targetPath);
    }

    /** Lists a folder. See {@link ListFilesOptions}; {@code truncated} means more entries exist. */
    public FileList listFiles(String path, ListFilesOptions options) {
        return client.listFiles(id, path, options);
    }

    public FileList listFiles(String path) {
        return client.listFiles(id, path);
    }

    /** Describes one path. A symlink is followed. */
    public FileInfo getFileInfo(String path) {
        return client.getFileInfo(id, path);
    }

    /** Whether a path exists. */
    public boolean fileExists(String path) {
        return client.fileExists(id, path);
    }

    /** Deletes a file, or a folder with {@code recursive}. */
    public void deleteFile(String path, DeleteFileOptions options) {
        client.deleteFile(id, path, options);
    }

    public void deleteFile(String path) {
        client.deleteFile(id, path);
    }

    /** Makes a folder; with {@code parents}, like {@code mkdir -p}. */
    public void makeDir(String path, MakeDirOptions options) {
        client.makeDir(id, path, options);
    }

    public void makeDir(String path) {
        client.makeDir(id, path);
    }

    /** Moves or renames a file or folder. */
    public void moveFile(String source, String destination, MoveFileOptions options) {
        client.moveFile(id, source, destination, options);
    }

    public void moveFile(String source, String destination) {
        client.moveFile(id, source, destination);
    }

    /** Copies a file, or a folder with {@code recursive}. */
    public void copyFile(String source, String destination, CopyFileOptions options) {
        client.copyFile(id, source, destination, options);
    }

    public void copyFile(String source, String destination) {
        client.copyFile(id, source, destination);
    }

    /** Paths under {@code path} whose name matches a glob. */
    public List<String> searchFiles(String path, String pattern) {
        return client.searchFiles(id, path, pattern);
    }

    /** Each line under {@code path} that contains {@code text}. */
    public List<FileMatch> findInFiles(String path, String text) {
        return client.findInFiles(id, path, text);
    }

    public ExposeResult exposePort(int port) {
        return client.exposePort(id, port, null);
    }

    /**
     * Publish a sandbox container port. Pass {@link ExposeOptions#tcp()} for
     * raw caddy-l4 routing (Postgres / Redis / MySQL / Mongo), or
     * {@link ExposeOptions#tls()} for the TLS-SNI multiplexer. The returned
     * {@link ExposeResult} carries {@code host} and {@code hostPort} only on
     * the TCP path.
     */
    public ExposeResult exposePort(int port, ExposeOptions options) {
        return client.exposePort(id, port, options);
    }

    public void unexposePort(int port) {
        client.unexposePort(id, port);
    }

    public List<CustomDomain> addCustomDomain(String hostname) {
        return client.addCustomDomain(id, hostname);
    }

    public List<CustomDomain> addCustomDomain(String hostname, int targetPort) {
        return client.addCustomDomain(id, hostname, targetPort);
    }

    public List<CustomDomain> listCustomDomains() {
        return client.listCustomDomains(id);
    }

    public void removeCustomDomain(String hostname) {
        client.removeCustomDomain(id, hostname);
    }

    public CustomDomainDnsRecords customDomainDns() {
        return client.customDomainDns(id);
    }

    public Sandbox start() {
        apply(client.start(id));
        return this;
    }

    public Sandbox stop() {
        apply(client.stop(id));
        return this;
    }

    public SandboxSnapshot createSnapshot(String name) {
        return client.createSnapshot(id, name);
    }

    /**
     * Saves this sandbox's files as a snapshot. With {@code allowPause} false,
     * a sandbox that is not stopped is refused (HTTP 409) instead of paused.
     */
    public SandboxSnapshot createSnapshot(String name, CreateSnapshotOptions options) {
        return client.createSnapshot(id, name, options);
    }

    public void destroy() {
        client.destroy(id);
    }

    public Sandbox resize(ResizeOptions options) {
        apply(client.resize(id, options));
        return this;
    }

    public Sandbox updateLifecycle(Lifecycle lifecycle) {
        apply(client.updateLifecycle(id, lifecycle));
        return this;
    }

    public NetworkUsage getNetworkUsage() {
        return client.getNetworkUsage(id);
    }

    public NetworkUsage setNetworkLimits(SetNetworkLimitsOptions options) {
        return client.setNetworkLimits(id, options);
    }

    /**
     * Replaces this sandbox's egress policy while it runs (see
     * {@link MicroVMClient#setNetworkPolicy}) and updates its policy fields.
     */
    public NetworkPolicy setNetworkPolicy(NetworkPolicyOptions options) {
        NetworkPolicy policy = client.setNetworkPolicy(id, options);
        networkBlockAll = policy.networkBlockAll;
        egressProfiles = policy.egressProfiles;
        egressStatus = policy.egressStatus;
        networkEgressMode = "learn".equals(policy.networkEgressMode) ? "learn" : null;
        networkEgressRules = policy.networkEgressRules;
        return policy;
    }

    /**
     * Reads what this sandbox reached in learn mode. A recording stays readable
     * after a switch to enforce, until the sandbox is destroyed.
     */
    public NetworkLearned learned() {
        return client.getNetworkLearned(id);
    }

    /**
     * Reads one page of this sandbox's audit log: outbound connections and
     * egress denials (kind {@code "egress"}) and secret reads.
     */
    public AuditPage audit(AuditOptions options) {
        return client.getAudit(id, options);
    }

    public AuditPage audit() {
        return client.getAudit(id, null);
    }

    private void apply(SandboxData data) {
        String existingPrivateKey = sshPrivateKey;
        copyFrom(data);
        if (data == null || data.sshPrivateKey == null) {
            sshPrivateKey = existingPrivateKey;
        }
    }
}