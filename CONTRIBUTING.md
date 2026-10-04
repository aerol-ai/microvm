# Contributing to AerolVM

AerolVM is open source under the [MIT License](LICENSE). Contributions are accepted under that same license. Open an issue before a non-trivial change so the approach can be agreed before implementation.

Report suspected vulnerabilities through [SECURITY.md](SECURITY.md). Use a private advisory or security@aerol.ai. A public issue or pull request is the wrong channel for a vulnerability.

Expected behavior in issues, pull requests, and other project spaces is in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Acceptable contributions

A change is acceptable when all of the following are true:

1. It arrives as a pull request. The default branch rejects direct pushes. A [code owner](.github/CODEOWNERS) other than the pull request author approves it.
2. The pull request description fills every section of the [pull request template](.github/pull_request_template.md). A section that does not apply contains `N/A` and a one-line reason.
3. A change to `internal/service`, `internal/store`, `pkg/caddy`, `pkg/api`, or an SDK addresses each rule in [pr-review.md](pr-review.md) that the change touches. The description states the idempotency, boot-path, failure-path, and host-port behavior when those rules apply.
4. Go changes are formatted with `go fmt`. `make test` passes. New Go code includes tests in a `_test.go` file next to the change and keeps that package's line coverage at or above 85%.
5. A user-facing API change updates each SDK that exposes the API (TypeScript, Python, Go, Rust, and Java).
6. The diff contains no secrets, credentials, private keys, or tokens. Those belong in GitHub Actions secrets or a local file that git ignores.
7. Every commit carries a `Signed-off-by` trailer. That trailer is the contributor's assertion that they are legally allowed to submit the change. The required `changes` status check rejects a pull request that omits it. `git commit -s` adds the trailer.

## Developer Certificate of Origin

By adding `Signed-off-by`, you certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/):

(a) The contribution was created in whole or in part by me and I have the right to submit it under the open source license indicated in the file; or

(b) The contribution is based upon previous work that, to the best of my knowledge, is covered under an appropriate open source license and I have the right under that license to submit that work with modifications, whether created in whole or in part by me, under the same open source license (unless I am permitted to submit under a different license), as indicated in the file; or

(c) The contribution was provided directly to me by some other person who certified (a), (b) or (c) and I have not modified it.

(d) I understand and agree that this project and the contribution are public and that a record of the contribution (including all personal information I submit with it, including my sign-off) is maintained indefinitely and may be redistributed consistent with this project or the open source license(s) involved.

```bash
make fmt      # format Go code
make test     # run tests
make build    # build sandboxd + toolboxd into bin/
```

## When tests run

`make test` runs the Go unit tests on the machine you are using. It does not call the network. The same suites run in GitHub Actions on every pull request into the default branch and on every push to it. A stacked pull request whose base is another branch runs nothing until it is retargeted to the default branch. The workflow is [`.github/workflows/test.yml`](.github/workflows/test.yml). Path filters select the SDK suites. The Go SDK suite runs on every such pull request, including a docs-only change. The required `changes` check passes once the DCO sign-off check and the Go SDK suite pass. The other suites report their own result but do not block the merge, so look at them before you merge and fix a red one on the default branch right away.

## Tests for major changes

A major change to the software must add or update tests of that functionality in the automated test suite before it merges. A change that alters behavior and does not update a test is not ready to merge. The coverage bar for new Go code is the one named in the acceptable-contributions list above.
