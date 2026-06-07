package ai.aerol.microvm;

import java.util.List;

import ai.aerol.microvm.model.CloneGeneration;
import ai.aerol.microvm.model.CreateSessionOptions;
import ai.aerol.microvm.model.CustomDomain;
import ai.aerol.microvm.model.CustomDomainDnsRecords;
import ai.aerol.microvm.model.ExecRequest;
import ai.aerol.microvm.model.ExecResult;
import ai.aerol.microvm.model.ExecStreamOptions;
import ai.aerol.microvm.model.ExposeOptions;
import ai.aerol.microvm.model.ExposeResult;
import ai.aerol.microvm.model.Lifecycle;
import ai.aerol.microvm.model.NetworkUsage;
import ai.aerol.microvm.model.ResizeOptions;
import ai.aerol.microvm.model.SandboxData;
import ai.aerol.microvm.model.SandboxSnapshot;
import ai.aerol.microvm.model.Session;
import ai.aerol.microvm.model.SessionAttachOptions;
import ai.aerol.microvm.model.SetNetworkLimitsOptions;

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

    public SessionAttachHandle attachSession(String sessionId, SessionAttachOptions options) {
        return client.attachSession(id, sessionId, options);
    }

    public void uploadFile(String targetPath, byte[] data) {
        client.uploadFile(id, targetPath, data);
    }

    public byte[] downloadFile(String targetPath) {
        return client.downloadFile(id, targetPath);
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

    private void apply(SandboxData data) {
        String existingPrivateKey = sshPrivateKey;
        copyFrom(data);
        if (data == null || data.sshPrivateKey == null) {
            sshPrivateKey = existingPrivateKey;
        }
    }
}