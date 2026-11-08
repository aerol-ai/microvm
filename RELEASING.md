# Releasing

The maintainer publishes releases, as [GOVERNANCE.md](GOVERNANCE.md) describes. A release takes five steps.

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

## 3. Check the download mirror

`install.sh` falls back to a public download mirror, `s3://aerolvm-downloads` (`https://aerolvm-downloads.s3.us-east-1.amazonaws.com`), when GitHub fails. It holds each release at `aerolvm/<tag>/<file>`, under the same names as on GitHub, and pinned third-party files at `deps/<project>/<version>/<file>`. `scripts/mirror-sync.sh` fills it.

- **The release workflow copies the release to the mirror** once its files are attached, with `scripts/mirror-sync.sh --release <tag>`. That checks every file against the release's `checksums.txt` before it uploads anything. If the tag is GitHub's latest release, it then points `aerolvm/latest.txt` at it, which is how `install.sh` finds "latest" on the mirror.
- **If that step failed or was skipped,** run it yourself with AWS credentials that can write to the bucket and `gh` logged in:

  ```bash
  scripts/mirror-sync.sh --release vX.Y.Z --dry-run   # prints the plan
  scripts/mirror-sync.sh --release vX.Y.Z
  ```

- **Re-sync third-party files only when a pin changes.** The pins are the `DOWNLOAD PINS` block in `scripts/install.sh`. After you bump a version and its hashes there, and before the release that ships the new `install.sh`, run `scripts/mirror-sync.sh --deps`. It reads the pins from `install.sh`, checks every file against its pin, and uploads nothing unless all of them match.

## 4. Sync the changelog

After the release workflow finishes, and again whenever you edit a release's notes on GitHub:

```bash
cd docs
npm run releases:sync
```

- **It rewrites `CHANGELOG.md`** and the docs' saved copy of the releases (`docs/src/data/releases.json`) from the notes on GitHub. Open a pull request with both files.
- **The docs Changelog page updates itself** at the next docs build. This step keeps `CHANGELOG.md` current, and keeps the copy the page uses when GitHub cannot be reached during a build.
- **Set `GITHUB_TOKEN`** if GitHub rate-limits the script.

## 5. Publish SDKs, if they changed

SDK packages are published separately, with the **Publish SDKs** workflow, run by hand. A server release does not need an SDK release.
