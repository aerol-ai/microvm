# Threat model and attack surface

This is the threat model and attack surface analysis for a released AerolVM node. It was reviewed on 2026-10-03 against the 0.6.3 security assessment in [SECURITY-ASSESSMENT.md](SECURITY-ASSESSMENT.md). The guest is untrusted code. The failures that matter are the ones that let that guest, or a caller who is not the operator, reach the host or another tenant.

## Trust boundaries

| Boundary | Who is on the outside | What they must not get |
| :--- | :--- | :--- |
| Operator credential | Anyone who does not hold the PAT | The host, every sandbox, and release operations. In the open-source build the PAT holder is the host operator. |
| Tenant API token | Another tenant | Sandboxes, secrets, and mounts that belong to someone else. |
| Sandbox guest | Code inside a sandbox | The host filesystem, the host network, and other guests. |
| Cluster peer | A node that is not in the membership | Placement changes and forwarded API calls. |
| Release consumer | A person running `install.sh` or a release binary | A binary that was not built by the release workflow for that tag. |

## Attack surface

The paths an attacker can actually touch:

- The HTTP API (v1, and the Daytona and E2B facades), including create, exec, files, snapshots, and mounts.
- The SSH gateway, which accepts the key issued for one sandbox.
- Preview URLs and TCP or TLS port routes published through Caddy.
- Host-side mount inputs (S3, NFS, SSHFS, rclone). The mount tool runs on the host as the daemon user. A value the tool reads as an option is a host command.
- The WASM toolhost routes that run a process for a module.
- Per-sandbox network policy. containerd, gVisor, and Firecracker install it. WASM and the V8 isolate are host-mediated and do not have a per-guest network namespace.
- Cluster forwarding, when cluster mode is on. It is a no-op when cluster mode is off.
- The release and the installer. A swapped `sandboxd` is a host compromise before any sandbox starts.

## Critical paths

| Path | Attack | What holds |
| :--- | :--- | :--- |
| Mount and toolhost input | Host command execution | Mount sources are validated. The WASM exec and code-run routes fail closed. A new host helper must treat caller strings as data. |
| Sandbox id, digest, module ref used as a path | Host path traversal | Those values are checked before they are joined onto a host path. |
| API id and cluster-forwarded create | Cross-tenant access | Ids are validated at the entry and again where they are used. |
| New route or SSH handshake | Authentication bypass | v1, Daytona, and E2B routes use the shared auth middleware. SSH accepts only the key for that sandbox. |
| Runtime without an egress policy | Network-isolation bypass | containerd, gVisor, and Firecracker install per-sandbox rules. WASM and the isolate use the host policy, which is a weaker boundary than a microVM. |
| Release asset or `install.sh` | Tampered binary | The release carries `checksums.txt`, `sbom.cdx.json`, and a SLSA provenance bundle. Verification steps are in [RELEASE-VERIFICATION.md](RELEASE-VERIFICATION.md). |

## Accepted on purpose

Running code inside a sandbox the caller owns is the product. A denial of service against a deployment the operator controls is out of scope. A finding that starts from an already-stolen operator token is out of scope, because that token is the host operator.

## How this stays current

Re-read this file when a release adds a host-side helper, a new runtime, or a new authentication path. The security assessment records the same problems and the state of the 0.6.3 review. A confirmed vulnerability is published as a GitHub Security Advisory.
