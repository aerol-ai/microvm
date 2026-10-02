# Contributing to AerolVM

AerolVM is open source under the [MIT License](LICENSE). Contributions are accepted under that same license. Open an issue before a non-trivial change so the approach can be agreed before implementation.

Report suspected vulnerabilities through [SECURITY.md](SECURITY.md). Use a private advisory or security@aerol.ai. A public issue or pull request is the wrong channel for a vulnerability.

## Acceptable contributions

A change is acceptable when all of the following are true:

1. It arrives as a pull request. The default branch rejects direct pushes. A [code owner](.github/CODEOWNERS) other than the pull request author approves it.
2. The pull request description fills every section of the [pull request template](.github/pull_request_template.md). A section that does not apply contains `N/A` and a one-line reason.
3. A change to `internal/service`, `internal/store`, `pkg/caddy`, `pkg/api`, or an SDK addresses each rule in [pr-review.md](pr-review.md) that the change touches. The description states the idempotency, boot-path, failure-path, and host-port behavior when those rules apply.
4. Go changes are formatted with `go fmt`. `make test` passes. New Go code includes tests in a `_test.go` file next to the change and keeps that package's line coverage at or above 85%.
5. A user-facing API change updates each SDK that exposes the API (TypeScript, Python, Go, Rust, and Java).
6. The diff contains no secrets, credentials, private keys, or tokens. Those belong in GitHub Actions secrets or a local file that git ignores.

```bash
make fmt      # format Go code
make test     # run tests
make build    # build sandboxd + toolboxd into bin/
```
