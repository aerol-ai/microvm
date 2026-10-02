# Security Policy

AerolVM runs untrusted code on your infrastructure, so we take isolation and
host-integrity issues seriously. Thank you for helping keep it safe.

## Supported versions

Security fixes land on the most recent minor release line. Older lines do not
receive backports — upgrade to the latest release.

| Version          | Supported          |
| ---------------- | ------------------ |
| Latest `0.6.x`   | :white_check_mark: |
| Older `0.6.x`    | upgrade to latest  |
| `< 0.6`          | :x:                |

Which releases still receive security fixes, and when a line stops, is stated in [SUPPORT.md](SUPPORT.md).

## Reporting a vulnerability

Please report privately — do **not** open a public issue, pull request, or
Discord message for a suspected vulnerability.

Use whichever is easiest:

1. **GitHub private advisory (preferred):** open a report at
   <https://github.com/aerol-ai/microvm/security/advisories/new>. This keeps the
   discussion and any fix private until a coordinated release.
2. **Email:** <security@aerol.ai>. PGP is available on request if you need it.
3. **Discord (first contact only):** join <https://discord.gg/QWQpymQgYJ> and
   ask a maintainer to open a private channel. Never post vulnerability details
   in a public Discord channel — use it only to reach us, then move to a private
   advisory or email.

Please include: the version or commit, the runtime involved (docker, containerd,
gVisor, Firecracker, WASM, or V8-isolate), a description of the impact, and the
steps or proof-of-concept to reproduce.

## What to expect

| Stage                     | Target                                   |
| ------------------------- | ---------------------------------------- |
| Acknowledgement           | within 3 business days                   |
| Initial assessment        | within 7 business days                   |
| Fix for a confirmed issue | critical: ~14 days · high: ~30 days · other: next release |

We coordinate disclosure with you: we publish a GitHub Security Advisory (and
request a CVE) alongside the fixed release, and we credit you unless you prefer
to stay anonymous.

## Scope

In scope — these are the issues we most want to hear about:

- Sandbox escape: executing code or reaching the filesystem/network on the host
  from inside a sandbox.
- Cross-tenant access: one sandbox or API token reaching another tenant's
  sandboxes, data, or secrets.
- Authentication or authorization bypass on the API or SSH gateway.
- Egress-policy or network-isolation bypass.
- Release or installer integrity (tampered artifacts, checksum/attestation
  bypass).
- `toolboxd` (the in-sandbox agent) behaviour that crosses the sandbox, tenant,
  or host boundary — for example path traversal into host mounts, reaching
  another sandbox, or SSRF to the host or control plane.

Out of scope:

- Running arbitrary code or commands **inside a sandbox you own**. That is
  toolboxd's intended function, not a vulnerability.
- Denial of service against a self-hosted deployment you control.
- Findings that require an already-compromised operator credential (the PAT) —
  in the open-source build the PAT holder is trusted as a host operator.
- Reports from automated scanners with no demonstrated impact.

## Secrets and credentials

Operator tokens, registry credentials, and CI secrets are stored in GitHub Actions secrets or in a root-owned file on the host. They are not committed to the repository. Access is limited to repository administrators and to the workflow job that needs that credential. Rotation is required after a suspected exposure and when a person who could read the credential leaves the project. GitHub secret scanning and push protection reject a push that contains a credential.

## Safe harbor

We will not pursue or support legal action against anyone who makes a good-faith
effort to follow this policy: who reports privately, avoids privacy violations
and data destruction, does not degrade others' service, and gives us reasonable
time to fix the issue before any public disclosure. If in doubt, ask first at
<security@aerol.ai>.
