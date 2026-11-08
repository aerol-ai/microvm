# Releasing

The maintainer publishes releases, as [GOVERNANCE.md](GOVERNANCE.md) describes. A release takes four steps.

## 1. Write the release notes

Write only the features section. The release workflow adds GitHub's list of merged pull requests after it.

```markdown
## Features in vX.Y.Z

An optional lead paragraph, or a `>` note for something every user must act on.

### Highlights

- **The change, in a few words.** What it does for the user.

---

### A detail section

- More detail, for readers who open the full notes.

### Upgrade notes

- Anything a user must check or change before upgrading.
```

- **Keep the `### Highlights` and `### Upgrade notes` headings exactly.** The docs Changelog page and `CHANGELOG.md` show the lead, the highlights and the upgrade notes. They leave the detail sections on GitHub.
- **Make every claim match the code.** The changelog repeats the notes word for word.
- **Leave out `## What's Changed`.** The workflow appends it.

## 2. Publish the release

```bash
gh release create vX.Y.Z --target <main commit> --title "vX.Y.Z: <short summary>" --notes-file notes.md --latest=false
```

- **The tag must look like `vX.Y.Z`,** with an optional `-suffix`. The release workflow rejects other tags.
- **Do not pass `--generate-notes`.** The workflow already appends GitHub's generated list, so the flag makes it appear twice.
- **Publish with `--latest=false`.** The installer downloads from the latest release, so a release with no files yet would break every new install. The workflow marks the release as latest once it has attached the files. If you publish with `--latest` by mistake, the workflow points latest back at the previous release first.
- **The workflow runs the tests, builds every binary and attaches the files.** Until it finishes, the release has no downloads and the previous release stays latest. If the workflow fails, the previous release stays latest until a rerun succeeds. If a test fails for a timing reason, rerun the failed jobs with `gh run rerun <run id> --failed`.
- **Re-running the workflow for an older release does not make it latest.** Only the newest stable release becomes latest. A prerelease never does.
- **The workflow also copies the files to the download mirror,** in its `mirror` job: see "The download mirror" below.

## 3. Sync the changelog

After the release workflow finishes, and again whenever you edit a release's notes on GitHub:

```bash
cd docs
npm run releases:sync
```

- **It rewrites `CHANGELOG.md`** and the docs' saved copy of the releases (`docs/src/data/releases.json`) from the notes on GitHub. Open a pull request with both files.
- **The docs Changelog page updates itself** at the next docs build. This step keeps `CHANGELOG.md` current, and keeps the copy the page uses when GitHub cannot be reached during a build.
- **Set `GITHUB_TOKEN`** if GitHub rate-limits the script.

## 4. Publish SDKs, if they changed

SDK packages are published separately, with the **Publish SDKs** workflow, run by hand. A server release does not need an SDK release.

## The download mirror

Every release's files are also kept in a public S3 bucket, so installs keep working when github.com release downloads fail (on 2026-11-08 they returned 504 for hours, from laptops and from AWS alike). Each file is at:

```
https://aerolvm-downloads.s3.us-east-1.amazonaws.com/aerolvm/<tag>/<file>
```

- **The release workflow fills it.** After the GitHub release is published, its `mirror` job downloads the release's files, checks each one against the release's `checksums.txt`, copies them to `s3://aerolvm-downloads/aerolvm/<tag>/`, and checks that the mirror then serves the same `checksums.txt`. If the release is GitHub's latest, it then points `aerolvm/latest.txt` at the tag; `install.sh` reads that file to find the latest release on the mirror. A failure there does not hold back the GitHub release; rerun just that job with `gh run rerun <run id> --failed`.
- **No keys are stored.** The job gets short-lived AWS credentials through GitHub OIDC by assuming the role named in the repository variable `AEROLVM_MIRROR_ROLE_ARN`. With the variable unset (a fork, say) the job is skipped.
- **The role can only write and list under `aerolvm/`.** It cannot delete, and cannot touch any other prefix or bucket. Only a workflow run of `aerol-ai/microvm` for a `v*` tag can assume it (GitHub's token names the repository and the ref, not the workflow file); only people who can push tags or start workflows here can start such a run, and only the release workflow uses the role. Its policies are `setup/release-mirror/trust-policy.json` and `permissions-policy.json`.
- **One-time setup** (already done for this repo): run `setup/release-mirror/create-role.sh` with AWS credentials that can manage IAM, then set the variable to the ARN it prints: `gh variable set AEROLVM_MIRROR_ROLE_ARN -R aerol-ai/microvm --body <arn>`. Running the script again updates the role in place.
- **Third-party files** (CNI plugins, the Caddy package, BuildKit) live under `deps/<project>/<version>/` in the same bucket. They change only when `install.sh` pins a new version, so they are copied by hand then, not by the release workflow.

