package ai.aerol.microvm.model;

import java.util.List;

/**
 * Per-sandbox DNS instructions for the custom domains attached to it. Each
 * {@link DnsRecord} in {@link #records} is the exact record an operator must
 * publish; {@link #target} echoes the cluster-wide ingress endpoint the
 * records point at, so callers don't need a second round trip to
 * {@code dnsTarget()} to render setup instructions.
 */
public class CustomDomainDnsRecords {
    public List<DnsRecord> records;
    public IngressTarget target;
}
