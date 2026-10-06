package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.ArrayList;
import java.util.List;

/**
 * One method, path or program rule. Rules refine a host the allow list already
 * admits: a request to a ruled host passes when some rule for that host admits
 * its program, method and path, and gets a 403 otherwise. A host no rule names
 * keeps its allow-list decision.
 */
// NON_DEFAULT leaves out empty lists and inspect=false, so a rule goes on the
// wire as written and the server applies its own port default.
@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class EgressRule {
    /** An exact name or {@code *.} wildcard, without a port. */
    public String host;
    /**
     * {@code [80]} by default, or {@code [443]} with inspect; only 80 and 443,
     * except that a rule with only binaries may name any port the allow list
     * opens.
     */
    public List<Integer> ports = new ArrayList<>();
    /** Exact, upper case ({@code GET}, {@code POST}); empty allows any. */
    public List<String> methods = new ArrayList<>();
    /**
     * Path globs: {@code *} within one segment, {@code **} as a whole segment
     * for any number of them. Empty allows any path.
     */
    public List<String> paths = new ArrayList<>();
    /**
     * Terminate TLS on 443 with the node's CA so the rule can see requests. The
     * request's Host must then equal the TLS server name.
     */
    public boolean inspect;
    /**
     * Replace a header on the requests this rule allows with a secret from the
     * sandbox's own env, which the sandbox itself only sees as a placeholder.
     * Needs inspect.
     */
    public EgressInject inject;
    /**
     * Limit the rule to connections opened by these executables: clean absolute
     * paths inside the sandbox, at most 16. For an interpreter (python, node, a
     * shell) the script it runs counts too, so {@code /usr/local/bin/pip}
     * works. A rule with only binaries decides whole connections, on any port
     * the allow list opens. Runc sandboxes only (docker and containerd); least
     * privilege for trusted tooling, not a security boundary.
     */
    public List<String> binaries = new ArrayList<>();

    public EgressRule setHost(String host) {
        this.host = host;
        return this;
    }

    public EgressRule setPorts(List<Integer> ports) {
        this.ports = ports == null ? new ArrayList<>() : ports;
        return this;
    }

    public EgressRule setMethods(List<String> methods) {
        this.methods = methods == null ? new ArrayList<>() : methods;
        return this;
    }

    public EgressRule setPaths(List<String> paths) {
        this.paths = paths == null ? new ArrayList<>() : paths;
        return this;
    }

    public EgressRule setInspect(boolean inspect) {
        this.inspect = inspect;
        return this;
    }

    public EgressRule setInject(EgressInject inject) {
        this.inject = inject;
        return this;
    }

    public EgressRule setBinaries(List<String> binaries) {
        this.binaries = binaries == null ? new ArrayList<>() : binaries;
        return this;
    }
}
