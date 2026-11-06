package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class Lifecycle {
    public Long stopIfIdleFor;
    public Long destroyIfIdleFor;
    public Long stopAtAge;
    public Long destroyAtAge;
    // serverless=true opts the sandbox into HTTP wake-on-request: auto-stop
    // when idle, resume on the next inbound HTTP request. Requires
    // stopIfIdleFor to be set; the server rejects serverless=true without
    // an idle window.
    public Boolean serverless;
    // restartOnFailure=true starts the sandbox again when it crashes or runs
    // out of memory, waiting 5 s, then 10 s, 20 s and so on up to 5 minutes;
    // the wait goes back to 5 s after 10 minutes of running. Docker, gVisor
    // and containerd sandboxes only (others answer 400).
    public Boolean restartOnFailure;

    public Lifecycle setStopIfIdleFor(Long stopIfIdleFor) {
        this.stopIfIdleFor = stopIfIdleFor;
        return this;
    }

    public Lifecycle setDestroyIfIdleFor(Long destroyIfIdleFor) {
        this.destroyIfIdleFor = destroyIfIdleFor;
        return this;
    }

    public Lifecycle setStopAtAge(Long stopAtAge) {
        this.stopAtAge = stopAtAge;
        return this;
    }

    public Lifecycle setDestroyAtAge(Long destroyAtAge) {
        this.destroyAtAge = destroyAtAge;
        return this;
    }

    public Lifecycle setServerless(Boolean serverless) {
        this.serverless = serverless;
        return this;
    }

    public Lifecycle setRestartOnFailure(Boolean restartOnFailure) {
        this.restartOnFailure = restartOnFailure;
        return this;
    }

    public Lifecycle copy() {
        return new Lifecycle()
            .setStopIfIdleFor(stopIfIdleFor)
            .setDestroyIfIdleFor(destroyIfIdleFor)
            .setStopAtAge(stopAtAge)
            .setDestroyAtAge(destroyAtAge)
            .setServerless(serverless)
            .setRestartOnFailure(restartOnFailure);
    }
}
