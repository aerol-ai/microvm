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

## Kubernetes images

From the release that ships them, each release also publishes these images to `ghcr.io/aerol-ai`, for amd64 and arm64: `aerolvm` (`sandboxd`), `aerolvm-runtime` (the runtime supervisor, containerd, runc and gVisor), `aerolvm-edge` (Caddy) and, from the release that adds cluster mode, `aerolvm-operator` (the Kubernetes operator). They are built from that release's own binaries. Each carries an SBOM and SLSA provenance from the build, a keyless cosign signature and GitHub's build provenance. Use the image's digest, not the tag: a digest cannot be moved.

1. Check the signature with cosign v3 or later. The release signs with cosign v3, in its newer bundle format; cosign v2 reports "no signatures found" for a signed image. The certificate must name this repository's release workflow at the release tag:

```bash
cosign verify ghcr.io/aerol-ai/aerolvm@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/aerol-ai/microvm/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

2. Check the provenance:

```bash
gh attestation verify oci://ghcr.io/aerol-ai/aerolvm@sha256:<digest> \
  --repo aerol-ai/microvm \
  --signer-workflow aerol-ai/microvm/.github/workflows/release.yml
```

`gh` reads the image from ghcr.io with its own token, which needs the `read:packages` scope (`gh auth refresh -s read:packages`). Without it, check the image's manifest as a file instead: fetch it anonymously by its digest, check its SHA-256 equals the digest, and run `gh attestation verify <manifest file> --repo aerol-ai/microvm`.

Repeat for `aerolvm-runtime`, `aerolvm-edge` and `aerolvm-operator`. To have Kubernetes refuse any AerolVM pod whose image fails this check, apply the example admission policy in `charts/aerolvm/examples/kyverno-signed-images.yaml`. The third-party programs in the images (containerd, runc, gVisor, the CNI plugins) are downloaded at build time and checked against hashes pinned in `packaging/images/versions.env`.

## Helm chart

From the first release after v0.7.3, each release also publishes the Helm chart as an OCI artifact, `ghcr.io/aerol-ai/charts/aerolvm`. Its version is the release number without the `v` (release `v1.2.3` is chart `1.2.3`), and it runs that release's images by default. It is published only after the images, with a keyless cosign signature and GitHub's build provenance, like the images.

1. Download the chart. `helm pull` saves `aerolvm-1.2.3.tgz` and prints its digest:

```bash
helm pull oci://ghcr.io/aerol-ai/charts/aerolvm --version 1.2.3
```

2. Check the signature, with the same identity as the images:

```bash
cosign verify ghcr.io/aerol-ai/charts/aerolvm@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/aerol-ai/microvm/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

3. Check the provenance:

```bash
gh attestation verify oci://ghcr.io/aerol-ai/charts/aerolvm@sha256:<digest> \
  --repo aerol-ai/microvm \
  --signer-workflow aerol-ai/microvm/.github/workflows/release.yml
```

Then install the file you checked, not the registry tag, so nothing can change in between: `helm install aerolvm ./aerolvm-1.2.3.tgz`.
