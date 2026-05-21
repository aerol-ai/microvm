package ai.aerol.microvm.model;

public class Failover {
    public String policy;

    public Failover setPolicy(String policy) {
        this.policy = policy;
        return this;
    }

    public Failover copy() {
        return new Failover().setPolicy(policy);
    }
}
