# Changelog

All notable changes to AerolVM are documented here. This project follows
[Semantic Versioning](https://semver.org). Releases prior to 0.6.3 are
described in the [GitHub Releases](https://github.com/aerol-ai/microvm/releases)
auto-generated notes.

## [0.6.3] - 2026-10-02

Security release. All issues below were found and fixed in a security review of
the sandbox control plane; none require a configuration change to benefit from.

### Security

- **Host command execution via a mount source (critical, GHSA-5pqm-4fh4-585q).**
  A sandbox create request could pass an option-shaped external-storage mount
  `source` (e.g. an `sshfs` `-oProxyCommand=…` value) that the host mount tool
  parsed as a flag, running an attacker-controlled command on the host as the
  daemon user. Mount sources are now rejected if they are option-shaped or carry
  control characters, and every mount adapter terminates options with `--`
  before the source/target.
- **Sandbox ID path traversal (high).** A caller-influenced sandbox ID (via the
  `X-Cluster-Create-ID` forward header) was used as a host path component in the
  mount manager without validation, so a `..` id could escape the mount root.
  Sandbox IDs are now validated (`[A-Za-z0-9_-]{1,128}`) at the create entry and
  at the point of use.
- **WASM toolhost host command execution (critical).** On the WASM runtime the
  in-daemon toolhost served `/process/exec/stream` and `/process/code-run` by
  spawning a host shell / host interpreter on caller input — code execution on
  the host rather than inside the sandbox. Both endpoints now fail closed with
  501; the confined `POST /process/execute` (runs inside the wasm engine) is
  unchanged. Restoring a confined streaming/code-run path is tracked for a
  future release.
- **jsbundle content-store path traversal (high).** `GetByDigest` used a
  caller-supplied digest as a path component without validation, so a `..`
  digest could read a file outside the bundle store. Digests are now validated
  as 64-char hex before any filesystem access.
- **WASM module ref traversal (high).** A relative module ref containing `..`
  could resolve outside the modules directory. Relative refs are now confined to
  the modules directory; absolute paths remain the explicit operator option.

### Fixed

- **SSHFS mounts on modern hosts.** The `sshfs` adapter passed `-o foreground`,
  which sshfs 3.x (the Ubuntu 22.04+ package) rejects, so SSHFS mounts never
  mounted. It now uses the `-f` flag.

### Added

- Supply-chain and project-security hardening: a real `SECURITY.md` disclosure
  policy, an OpenSSF Scorecard workflow and badge, SLSA build provenance
  published as a release asset, Go native fuzz targets on the untrusted-input
  validators, a protected `v*` tag ruleset, CodeQL and Dependabot security
  updates, and required org two-factor authentication.

[0.6.3]: https://github.com/aerol-ai/microvm/releases/tag/v0.6.3
