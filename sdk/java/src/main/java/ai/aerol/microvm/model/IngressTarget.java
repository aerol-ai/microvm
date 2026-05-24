package ai.aerol.microvm.model;

import java.util.List;

/**
 * DNS target operators point custom domains at. Exactly one of {@link #hostname}
 * or {@link #ips} is populated depending on the daemon's configured ingress
 * {@link #source} (CNAME-style hostname vs A-record IPs). Treat both fields as
 * optional in client code; missing fields decode to {@code null}.
 */
public class IngressTarget {
    public String hostname;
    public List<String> ips;
    public String source;
}
