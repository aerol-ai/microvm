#!/usr/bin/env bash
# build-images.sh: build the Kubernetes images (plans/kubernetes-v2-
# architecture.md P1) from release binaries, without compiling anything in
# the image.
#
#   scripts/build-images.sh --dist <dir> --version <tag> [--registry <repo>]
#                           [--platforms linux/amd64,linux/arm64] [--push]
#                           [--metadata-dir <dir>] [--images aerolvm,aerolvm-runtime]
#
# --dist holds the release build's files, named as release.yml names them:
# sandboxd_linux_<arch>, toolboxd_linux_<arch>, aerolvm-supervisor_linux_<arch>
# and caddy_linux_<arch>, for each platform. Third-party pins and base images
# come from packaging/images/versions.env.
#
# With --push the images go to the registry with an SBOM and SLSA provenance
# attached, and each image's digest is written to <metadata-dir>/<image>.json
# for signing. Without it, one platform is built and loaded into the local
# Docker (a kind cluster, `make k8s-dev`). --images builds only those named
# (single mode needs no aerolvm-edge, so `make k8s-dev` skips the Caddy build).
set -euo pipefail

dist="" version="" registry="ghcr.io/aerol-ai" platforms="" push=0 meta="" images="aerolvm,aerolvm-runtime,aerolvm-edge"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dist) dist="$2"; shift 2 ;;
    --version) version="$2"; shift 2 ;;
    --registry) registry="$2"; shift 2 ;;
    --platforms) platforms="$2"; shift 2 ;;
    --push) push=1; shift ;;
    --metadata-dir) meta="$2"; shift 2 ;;
    --images) images="$2"; shift 2 ;;
    *) echo "build-images: unknown flag $1" >&2; exit 2 ;;
  esac
done
[[ -n "$dist" && -n "$version" ]] || { echo "usage: build-images.sh --dist <dir> --version <tag> [--push]" >&2; exit 2; }
root="$(git rev-parse --show-toplevel)"
if [[ -z "$platforms" ]]; then
  if [[ "$push" == 1 ]]; then
    platforms="linux/amd64,linux/arm64"
  else
    case "$(uname -m)" in arm64|aarch64) platforms="linux/arm64" ;; *) platforms="linux/amd64" ;; esac
  fi
fi
if [[ "$push" != 1 && "$platforms" == *,* ]]; then
  echo "build-images: a local build (no --push) loads one platform; got $platforms" >&2
  exit 2
fi

ctx="$(mktemp -d)"
trap 'rm -rf "$ctx"' EXIT
for platform in ${platforms//,/ }; do
  arch="${platform#linux/}"
  mkdir -p "$ctx/$arch"
  bins="sandboxd toolboxd aerolvm-supervisor"
  [[ ",$images," == *,aerolvm-edge,* ]] && bins="$bins caddy"
  for bin in $bins; do
    src="$dist/${bin}_linux_${arch}"
    [[ -f "$src" ]] || { echo "build-images: missing $src" >&2; exit 1; }
    install -m 0755 "$src" "$ctx/$arch/$bin"
  done
done

args=(--build-arg "VERSION=$version" --build-arg "REVISION=$(git -C "$root" rev-parse HEAD)")
while IFS='=' read -r key value; do
  [[ -z "$key" || "$key" == \#* ]] && continue
  args+=(--build-arg "$key=$value")
done < "$root/packaging/images/versions.env"

for image in ${images//,/ }; do
  case "$image" in aerolvm|aerolvm-runtime|aerolvm-edge) ;; *) echo "build-images: unknown image $image" >&2; exit 2 ;; esac
  file="$root/packaging/images/${image#aerolvm-}.Dockerfile"
  [[ "$image" == aerolvm ]] && file="$root/packaging/images/aerolvm.Dockerfile"
  out=(--load)
  if [[ "$push" == 1 ]]; then
    [[ -n "$meta" ]] || { echo "build-images: --push needs --metadata-dir" >&2; exit 2; }
    mkdir -p "$meta"
    out=(--push --sbom=true --provenance=mode=max --metadata-file "$meta/$image.json")
  fi
  echo "build-images: $registry/$image:$version for $platforms" >&2
  docker buildx build --platform "$platforms" "${args[@]}" -f "$file" \
    -t "$registry/$image:$version" "${out[@]}" "$ctx"
done
