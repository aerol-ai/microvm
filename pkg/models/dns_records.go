package models

import (
	"net"
	"strings"
)

// cloudflareNote is the surfaced warning every record carries. With the
// Cloudflare proxy on (orange cloud), Cloudflare terminates TLS itself and
// the cluster never sees the SNI — Caddy's on-demand `ask` handler is never
// invoked, ACME never runs, and the custom domain stays pending_dns
// forever. Same trap for any CDN that intercepts TLS in front of ingress,
// so we phrase the note generically and call Cloudflare out explicitly.
const cloudflareNote = "Cloudflare/CDN: set the record to DNS only (gray cloud). A proxied record terminates TLS at the CDN and blocks on-demand ACME issuance."

// ComposeDNSRecords expands every hostname against an IngressTarget into
// the set of DNS records the user must create at their provider. Shape
// rules:
//
//   - target.Hostname set (Source=hostname or mixed) → one CNAME per
//     hostname. Apex hostnames (foo.com) get Name="@"; subdomains
//     (api.foo.com) get Name="api". Apex CNAME assumes the provider
//     supports flattening (Cloudflare, Route 53 alias, DNSimple ALIAS,
//     DNSMadeEasy ANAME, etc.) — the doc page covers the fallback.
//   - target.IPs populated (Source=ips or mixed) → one A or AAAA per IP per
//     hostname, partitioned by net.ParseIP.To4().
//   - target empty / Source=unknown → returns nil. Callers render an
//     operator-must-configure-ingress error rather than fake records.
//
// Mixed sources emit BOTH the CNAME and the A/AAAA records so apex
// hostnames that can't flatten still have a workable option.
func ComposeDNSRecords(hostnames []string, target IngressTarget) []DNSRecord {
	if len(hostnames) == 0 {
		return nil
	}
	if target.Hostname == "" && len(target.IPs) == 0 {
		return nil
	}
	out := make([]DNSRecord, 0, len(hostnames))
	for _, host := range hostnames {
		host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
		if host == "" {
			continue
		}
		name := dnsRecordName(host)
		if target.Hostname != "" {
			out = append(out, DNSRecord{
				Hostname: host,
				Type:     DNSRecordTypeCNAME,
				Name:     name,
				Value:    target.Hostname,
				Notes:    cloudflareNote,
			})
		}
		for _, ip := range target.IPs {
			recType := DNSRecordTypeA
			if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
				recType = DNSRecordTypeAAAA
			}
			out = append(out, DNSRecord{
				Hostname: host,
				Type:     recType,
				Name:     name,
				Value:    ip,
				Notes:    cloudflareNote,
			})
		}
	}
	return out
}

// dnsRecordName returns "@" for apex (two-label) hostnames and the
// leftmost label for subdomains. The split matches what DNS provider UIs
// accept in their "Name" field — Cloudflare, Route 53, etc. all use "@"
// for apex and the bare leftmost label for subdomain rows.
func dnsRecordName(host string) string {
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return "@"
	}
	return labels[0]
}
