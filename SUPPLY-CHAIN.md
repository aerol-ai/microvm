# Supply chain

Dependency updates are opened by Dependabot (`.github/dependabot.yml`). The Go CI job runs `govulncheck` on daemon changes. Every pull request also runs the `dependency-review` and `gosec` jobs in [`.github/workflows/supply-chain.yml`](.github/workflows/supply-chain.yml). Those job names are required status checks on the default branch, so a violation blocks the merge.

## Software composition analysis

Software composition analysis (SCA), including dependency scanning, must evaluate every pull request for known vulnerabilities and for malicious dependencies. A high or critical vulnerability finding must be remediated. A dependency license that is not approved must be removed. Software composition analysis violations must be remediated before any release. A software composition analysis violation must block merging. A finding that is not exploitable may be suppressed when the exception is declared with a justification in the pull request.

Approved licenses are MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, and MPL-2.0. Any other license is prohibited unless a maintainer records why it is acceptable for that dependency.

## Static analysis

Static analysis findings at high or critical severity must be remediated before merging. A static analysis finding that is not exploitable may be suppressed when the exception is declared with a justification. gosec is the Go gate. CodeQL analyzes Go, JavaScript, TypeScript, Python, Java, Rust, and Actions on the default setup and uploads results to code scanning.
