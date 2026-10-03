# Security assessment

Assessed for the 0.6.3 release (2026-10-02) and kept as the standing model of the problems that matter most. The guest is untrusted code. The highest-impact problems are the ones that let that guest, or a caller who is not the operator, reach the host or another tenant. Reporting and response times are in [SECURITY.md](SECURITY.md). Actors are in [DESIGN.md](DESIGN.md).

## Most likely and most severe

| Problem | Why it is likely | Impact if it happens | Where the 0.6.3 review left it |
| :--- | :--- | :--- | :--- |
| Host command execution | Mount tools and the WASM toolhost run on the host and take caller input. A value that the tool reads as an option becomes a host command. | Critical. Code runs as the daemon user, outside every sandbox. | Fixed for mount sources (GHSA-5pqm-4fh4-585q) and for the WASM `/process/exec/stream` and `/process/code-run` routes, which now fail closed. Any new host helper that takes a caller string has to treat it as data. |
| Host path traversal | Sandbox ids, content digests, and module refs are caller input used as path components. | High. A `..` component reads or writes outside the sandbox's directory. | Sandbox ids, bundle digests, and relative module refs are validated before use. New host paths need the same check. |
| Cross-tenant access | One API token, or a cluster-forwarded create, names another tenant's id. | High. One customer reads or changes another customer's sandbox, secrets, or mounts. | Ids are validated. Cluster create ids that arrive from a peer are checked at the entry and at the point of use. |
| API or SSH authentication bypass | The API is bearer-token. SSH is a per-sandbox key. A missing check on a new route skips both. | High. Full control of the sandboxes that credential was meant to protect. | v1, Daytona, and E2B routes are wrapped in the shared auth middleware. The SSH gateway accepts only the key issued for that sandbox. |
| Egress or network-isolation bypass | Each sandbox has its own network namespace and an egress policy. A runtime that does not install that policy shares the host network. | High for a multi-tenant host. The guest reaches addresses the operator meant to deny. | containerd, gVisor, and Firecracker install per-sandbox network rules. WASM and the V8 isolate are host-mediated and have no per-guest network namespace; their outbound path is the host policy, which the assessment treats as a weaker boundary than a microVM. |
| Tampered release or installer | Users run `install.sh` and the release binaries. | High. A swapped binary is a host compromise before any sandbox starts. | Releases publish `checksums.txt` and a signed SLSA provenance bundle (`<version>.intoto.jsonl`). |

## Accepted on purpose

Running code inside a sandbox the caller owns is the product, not a vulnerability. A denial of service against a deployment the operator themselves controls is out of scope. A finding that starts from an already-stolen operator token is out of scope: that token is the host operator.

## How this is re-checked

Each release's security notes are in [CHANGELOG.md](CHANGELOG.md). A confirmed vulnerability is published as a GitHub Security Advisory. The Go CI job runs `govulncheck` on daemon changes, and Dependabot opens weekly dependency updates.
