package models

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// cloudflareNote is the surfaced warning every record carries. With the
// Cloudflare proxy on (orange cloud), Cloudflare terminates TLS itself and
// the cluster never sees the SNI — Caddy's on-demand `ask` handler is never
// invoked, ACME never runs, and the custom domain stays pending_dns
// forever. Same trap for any CDN that intercepts TLS in front of ingress,
// so we phrase the note generically and call Cloudflare out explicitly.
const cloudflareNote = "Cloudflare/CDN: set the record to DNS only (gray cloud). A proxied record terminates TLS at the CDN and blocks on-demand ACME issuance."

// apexFlatteningNote is attached to every apex routing candidate. A bare CNAME
// is illegal at a zone root (RFC 1034 §3.6.2); providers expose flattening
// under different record types, so we emit CNAME/ANAME/ALIAS together and tell
// the caller to add exactly one — the type their provider accepts.
const apexFlatteningNote = "Apex domain: add only ONE of these, whichever your DNS provider supports — CNAME (Cloudflare flattening), ANAME (dnsmadeeasy/EasyDNS), or ALIAS (Route 53/DNSimple)."

// ComposeDNSRecords expands every hostname against an IngressTarget into
// the set of DNS records the user must create at their provider. Shape
// rules:
//
//   - Subdomains with target.Hostname available → one CNAME (smallest,
//     survives IP changes, works at every provider).
//   - Apex hostnames with target.IPs available → one A (and AAAA for IPv6)
//     per IP. Apex prefers IPs over CNAME because CNAME-at-apex requires
//     provider-specific flattening (Cloudflare, Route 53 alias, DNSimple
//     ALIAS, etc.) and many providers reject it.
//   - Apex hostnames with only target.Hostname (no IPs) → three mutually-
//     exclusive flattening candidates (CNAME, ANAME, ALIAS), all at "@" with
//     the same value. A bare CNAME is illegal at a zone root, and providers
//     name their flattening record differently, so we emit all three and the
//     note tells the caller to add the one their provider supports.
//   - Subdomains with only target.IPs → one A/AAAA per IP.
//   - target empty / Source=unknown → returns nil. Callers render an
//     operator-must-configure-ingress error rather than fake records.
//
// One strategy per hostname is required: a CNAME owner name cannot coexist
// with A/AAAA records at the same name (RFC 1034 §3.6.2). DNS providers
// reject the second row, so emitting both as "ready-to-paste" would just
// trip the user up.
//
// The TXT verification record proves zone control, not sandbox binding:
// value is `<txtValuePrefix><hostname>`, so the same record stays valid
// across sandbox recreates and can be provisioned BEFORE a sandbox exists.
// Cross-sandbox hijack is still blocked by the cluster-wide uniqueness gate
// on hostname insert.
// `txtNamePrefix` and `txtValuePrefix` allow customizing the verification TXT records.
func ComposeDNSRecords(hostnames []string, target IngressTarget, txtNamePrefix, txtValuePrefix string) []DNSRecord {
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
		isApex := name == "@"
		useCNAME := target.Hostname != "" && (!isApex || len(target.IPs) == 0)
		if useCNAME && isApex {
			// Apex on a hostname ingress: a bare CNAME is illegal at the zone
			// root, so emit the three flattening candidates and let the caller
			// pick the one their provider supports. Fixed order keeps the
			// output deterministic. The CNAME row also carries the Cloudflare
			// gray-cloud warning since Cloudflare users add exactly that row.
			out = append(out,
				DNSRecord{
					Hostname: host,
					Type:     DNSRecordTypeCNAME,
					Name:     name,
					Value:    target.Hostname,
					Notes:    cloudflareNote + " " + apexFlatteningNote,
				},
				DNSRecord{
					Hostname: host,
					Type:     DNSRecordTypeANAME,
					Name:     name,
					Value:    target.Hostname,
					Notes:    apexFlatteningNote,
				},
				DNSRecord{
					Hostname: host,
					Type:     DNSRecordTypeALIAS,
					Name:     name,
					Value:    target.Hostname,
					Notes:    apexFlatteningNote,
				},
			)
		} else if useCNAME {
			out = append(out, DNSRecord{
				Hostname: host,
				Type:     DNSRecordTypeCNAME,
				Name:     name,
				Value:    target.Hostname,
				Notes:    cloudflareNote,
			})
		} else {
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

		// Add TXT verification record. Value is the hostname itself so the
		// record proves zone control (one-time setup per hostname) instead
		// of binding to a specific sandbox ID — that lets the TXT be added
		// BEFORE any sandbox exists and survive sandbox recreates.
		out = append(out, DNSRecord{
			Hostname: host,
			Type:     "TXT",
			Name:     fmt.Sprintf("%s.%s", txtNamePrefix, name),
			Value:    fmt.Sprintf("%s%s", txtValuePrefix, host),
			Notes:    "Required for domain ownership verification.",
		})
	}
	return out
}

// dnsRecordName returns "@" for apex hostnames and the leftmost label for
// subdomains. Apex detection uses the Mozilla public suffix list so
// `example.co.uk` and `example.com.au` are correctly recognized as zone
// roots — a naive label-count check would label `example` as the
// subdomain. Falls back to the label-count heuristic only when the host
// has no public suffix (intranet TLDs, single-label hosts).
func dnsRecordName(host string) string {
	if etldPlus1, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		if host == etldPlus1 {
			return "@"
		}
		return strings.TrimSuffix(host, "."+etldPlus1)
	}
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return "@"
	}
	return labels[0]
}
