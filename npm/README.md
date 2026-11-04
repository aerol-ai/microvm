# npm packages for aerolvm

`npx -y @aerol-ai/aerolvm mcp` is the install-free way to run the aerolvm MCP
server, and how the MCP Registry entry (`server.json` at the repo root) points
clients at it.

- `aerolvm/` is the launcher package `@aerol-ai/aerolvm`: a small Node script
  that runs the right prebuilt binary.
- `stage.mjs` builds the seven publishable packages from a release's
  `aerolvm_<goos>_<goarch>` binaries: one per platform
  (`@aerol-ai/aerolvm-{darwin,linux,win32}-{x64,arm64}`) and the launcher.
- `cmd/aerolvm/distribution_test.go` keeps the package, the release build
  matrix, `server.json` and the launcher in agreement, and runs the launcher
  end to end under node.

Versions in this directory and in `server.json` stay at the `0.0.0`
placeholder. The release workflow stamps the tag in.

## Release flow

`.github/workflows/release.yml` runs when a GitHub release is published:

1. The `cli` job cross-compiles aerolvm for every platform, and the binaries
   go on the GitHub release with the server binaries.
2. The `npm` job stages the packages and publishes them with GitHub OIDC
   trusted publishing, platform packages first. A prerelease tag publishes
   under the `next` dist-tag, so `npx` keeps running the last stable version.
3. The `mcp-registry` job stamps the version into `server.json`, runs
   `mcp-publisher validate`, waits until npm serves the new version, and
   publishes `io.github.aerol-ai/aerolvm` with `mcp-publisher login
   github-oidc`. Prereleases skip this job.

Both publishing jobs are off until the repository variable
`AEROLVM_NPM_PUBLISH` is `true`, and both skip work that is already done, so
re-running them is safe.

## One-time setup before turning on `AEROLVM_NPM_PUBLISH`

1. npm can only attach a trusted publisher to a package that exists. For each
   of the seven packages, an `@aerol-ai` maintainer publishes the first
   version by hand: run `node npm/stage.mjs <version> <dir with the release
   binaries> out`, then `npm publish --access public` in each `out/<package>`
   directory, platform packages first.
2. On npmjs.com, open each package's settings and add a trusted publisher:
   GitHub Actions, repository `aerol-ai/microvm`, workflow `release.yml`.
3. Nothing is needed for the MCP Registry. GitHub OIDC from this repository
   proves ownership of the `io.github.aerol-ai/*` namespace.
