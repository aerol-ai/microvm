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

    public Lifecycle copy() {
        return new Lifecycle()
            .setStopIfIdleFor(stopIfIdleFor)
            .setDestroyIfIdleFor(destroyIfIdleFor)
            .setStopAtAge(stopAtAge)
            .setDestroyAtAge(destroyAtAge)
            .setServerless(serverless);
    }
}
