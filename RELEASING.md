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
gh release create vX.Y.Z --target <main commit> --title "vX.Y.Z: <short summary>" --notes-file notes.md --latest
```

- **The tag must look like `vX.Y.Z`,** with an optional `-suffix`. The release workflow rejects other tags.
- **Do not pass `--generate-notes`.** The workflow already appends GitHub's generated list, so the flag makes it appear twice.
- **The workflow runs the tests, builds every binary and attaches the files.** Until it finishes, the release has no downloads. If a test fails for a timing reason, rerun the failed jobs with `gh run rerun <run id> --failed`.

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
