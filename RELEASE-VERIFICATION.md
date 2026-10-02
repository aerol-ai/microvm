# Verifying a release

Official builds are GitHub Releases. Each asset is attached to the release whose tag is the version, so the download URL contains that tag (`/releases/download/vX.Y.Z/<asset>`). The release workflow also publishes a second copy of each binary and script whose file name starts with that tag (`vX.Y.Z_sandboxd_linux_amd64`). The unversioned name remains so existing download URLs keep working. `checksums.txt` lists a SHA-256 for every file in the release. `sbom.cdx.json` is the CycloneDX bill of materials for the Go module at that tag. `<version>.intoto.jsonl` is the SLSA build provenance.

## Integrity of the assets

1. Download the asset and `checksums.txt` from the same release.
2. Check the digest:

```bash
sha256sum -c checksums.txt --ignore-missing
```

3. Check the provenance. This confirms the file was built by this repository's release workflow and was not swapped after the build:

```bash
gh attestation verify sandboxd_linux_amd64 \
  --repo aerol-ai/microvm \
  --signer-workflow aerol-ai/microvm/.github/workflows/release.yml
```

Repeat for each binary you install. `install.sh` checks `checksums.txt` before it installs. A mismatch means do not install the file.

## Identity of the publisher

The provenance certificate names the builder. Expect all of the following:

- Source repository URI `https://github.com/aerol-ai/microvm`
- Signer workflow `aerol-ai/microvm/.github/workflows/release.yml`
- Source ref equal to the release tag, for example `refs/tags/v0.6.3`

A bundle that names a different repository, a different workflow, or a branch ref instead of the tag is not an official release. The person or process that published it is the GitHub Actions workflow above, running with this repository's OIDC token. There is no separate maintainer signing key.
