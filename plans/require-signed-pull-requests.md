# Proposal: require a signature on every pull request

Status: suggestion. This change does not turn the rule on.

## Suggestion

Every commit a pull request brings onto `main` should be cryptographically signed, so GitHub shows the commit as Verified. Add the `required_signatures` rule to ruleset `rule-1` (id `16186085`, target `~DEFAULT_BRANCH`) once the maintainer's signing key is registered and one signed pull request has merged.

The `Signed-off-by` trailer stays. It is the [Developer Certificate of Origin](https://developercertificate.org/) assertion, and the `changes` check already rejects a pull request that omits it. A signature is a separate check: the commit was made with a key the author registered on GitHub.

## Why this is not already enforced

Ruleset `rule-1` requires a pull request, the merge queue, and the `changes` status check. It has no `required_signatures` rule. Non-merge commits on `main` carry a `Signed-off-by` trailer and no cryptographic signature. Turning the rule on in this pull request would block every open pull request.

## What a contributor does

Register an SSH key as a signing key on the GitHub account, then sign every commit in addition to the DCO trailer:

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git commit -s -S
```

`git commit -s` adds `Signed-off-by`. `git commit -S` adds the signature. Both belong on each commit.

## Follow-up that applies the rule

After the signing key is on the account and a pull request of only signed commits has merged:

1. Add `required_signatures` to ruleset `rule-1`.
2. Leave the DCO check in `.github/workflows/test.yml` in place.
3. Rewrite any still-open pull request so each of its commits is signed, then update the branch.

GitHub-created merge commits are already signed by GitHub. The rule binds the commits the author pushes.
