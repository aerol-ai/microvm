package ai.aerol.microvm.model;

/** The answer to a policy check. */
public class NetworkPolicyCheckResult {
    public boolean allowed;
    /** The entry that decided; empty when the default verdict did. */
    public String matchedRule;
    /** "allow" or "deny": what happens to a destination no entry matches. */
    public String defaultVerdict;
    /** The first allow entry outside this deployment's ceiling, or null. */
    public String outsideCeiling;
}
