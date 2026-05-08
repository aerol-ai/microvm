package ai.aerol.microvm.model;

import java.time.Instant;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Session {
    public String id;
    public String name;
    public List<String> argv;
    @JsonProperty("workdir")
    public String workDir;
    public boolean pty;
    public String status;
    @JsonProperty("exit_code")
    public int exitCode;
    @JsonProperty("exit_signal")
    public String exitSignal;
    public Instant createdAt;
    public Instant startedAt;
    public Instant exitedAt;
    public boolean recording;
    public long bytes;
    public int attached;
}