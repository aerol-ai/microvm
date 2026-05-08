package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class Lifecycle {
    public Long stopIfIdleFor;
    public Long destroyIfIdleFor;
    public Long stopAtAge;
    public Long destroyAtAge;

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

    public Lifecycle copy() {
        return new Lifecycle()
            .setStopIfIdleFor(stopIfIdleFor)
            .setDestroyIfIdleFor(destroyIfIdleFor)
            .setStopAtAge(stopAtAge)
            .setDestroyAtAge(destroyAtAge);
    }
}