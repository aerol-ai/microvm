package models

// IngressTarget is the cluster-published address(es) that DNS for a custom
// domain must point at. The shape depends on how the operator deployed
// AerolVM:
//
//   - Source="hostname" — the cluster advertises a stable hostname (e.g.
//     ingress.example.com that itself resolves to a load balancer). DNS for
//     custom domains is a CNAME to this hostname.
//   - Source="ips" — the cluster advertises one or more raw IPs. DNS for
//     custom domains is one A (and AAAA for IPv6) record per IP.
//   - Source="mixed" — some ingress nodes gossip a hostname, others gossip
//     raw IPs. Callers should prefer the hostname (smaller record set,
//     survives IP changes) but render both so apex domains without
//     CNAME-flattening can still be configured.
//   - Source="unknown" — no ingress node has gossiped a public address yet.
//     This is the boot-time / mis-configured case; callers should treat the
//     target as unusable rather than guessing.
//
// The struct mirrors what GET /v1/ingress/dns returns. SDK helpers wrap it
// in language-idiomatic types but the JSON shape is shared.
type IngressTarget struct {
	Hostname string   `json:"hostname,omitempty"`
	IPs      []string `json:"ips,omitempty"`
	Source   string   `json:"source"`
}

// IngressTarget Source values. Constants exported so cluster and service
// layers can build targets without stringly-typed errors.
const (
	IngressTargetSourceHostname = "hostname"
	IngressTargetSourceIPs      = "ips"
	IngressTargetSourceMixed    = "mixed"
	IngressTargetSourceUnknown  = "unknown"
)

// DNSRecord is one DNS row a user must add at their provider to make a
// custom domain reach the cluster. Hostname is the full custom hostname
// (api.acme.com); Name is the leftmost label (or "@" for apex) the way DNS
// UIs accept it; Value is the right-hand side (target hostname or IP).
//
// Notes carries provider-specific gotchas the SDK pre-renders so callers
// don't have to embed the documentation themselves. Currently only used to
// surface the Cloudflare "DNS only, gray cloud" warning — without it the
// proxy terminates TLS and on-demand ACME never fires.
type DNSRecord struct {
	Hostname string `json:"hostname"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Notes    string `json:"notes,omitempty"`
}

// DNS record types we emit. Limited to the three that on-demand ACME +
// HTTP-01 actually require — TXT / SRV / etc. are not in scope.
const (
	DNSRecordTypeCNAME = "CNAME"
	DNSRecordTypeA     = "A"
	DNSRecordTypeAAAA  = "AAAA"
)

// CustomDomainDNSRecords is the response body for
// GET /v1/sandboxes/{id}/custom-domains/dns. Records is the flat
// ready-to-paste list (one row per custom domain × per ingress address);
// Target is the raw aggregation the records were composed from, included
// so callers can render their own UI without re-fetching.
type CustomDomainDNSRecords struct {
	Records []DNSRecord   `json:"records"`
	Target  IngressTarget `json:"target"`
}
