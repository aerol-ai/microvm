package ai.aerol.microvm;

import java.util.List;

import ai.aerol.microvm.model.CreateSessionOptions;
import ai.aerol.microvm.model.ExecRequest;
import ai.aerol.microvm.model.ExecResult;
import ai.aerol.microvm.model.ExecStreamOptions;
import ai.aerol.microvm.model.Lifecycle;
import ai.aerol.microvm.model.ResizeOptions;
import ai.aerol.microvm.model.SandboxData;
import ai.aerol.microvm.model.Session;
import ai.aerol.microvm.model.SessionAttachOptions;

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

    public String exposePort(int port) {
        return client.exposePort(id, port);
    }

    public void unexposePort(int port) {
        client.unexposePort(id, port);
    }

    public Sandbox start() {
        apply(client.start(id));
        return this;
    }

    public Sandbox stop() {
        apply(client.stop(id));
        return this;
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

    private void apply(SandboxData data) {
        String existingPrivateKey = sshPrivateKey;
        copyFrom(data);
        if (data == null || data.sshPrivateKey == null) {
            sshPrivateKey = existingPrivateKey;
        }
    }
}