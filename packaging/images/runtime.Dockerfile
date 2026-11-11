# syntax=docker/dockerfile:1
# aerolvm-runtime: the worker pod's runtime container (plans/kubernetes-v2-
# architecture.md §8.2, P1). The supervisor, containerd, runc and gVisor.
# It changes only when one of those does, so an AerolVM upgrade restarts the
# agent container and never this one, which holds every sandbox.
#
# Built by scripts/build-images.sh: the context holds <arch>/aerolvm-supervisor
# from the release build, and versions.env's pins arrive as build args.
# The base is pinned by its multi-arch index digest right here, where
# Scorecard and Dependabot read it (a FROM ${ARG} hides the pin from both).

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS fetch
ARG TARGETARCH
ARG CONTAINERD_VERSION
ARG CONTAINERD_SHA256_AMD64
ARG CONTAINERD_SHA256_ARM64
ARG RUNC_VERSION
ARG RUNC_SHA256_AMD64
ARG RUNC_SHA256_ARM64
ARG GVISOR_RELEASE
ARG GVISOR_SHA512_AMD64
ARG GVISOR_SHA512_ARM64
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl bzip2 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /fetch
# Each download is checked against the hash pinned in versions.env, never
# against a checksum file fetched next to it.
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) g=x86_64; ctd="$CONTAINERD_SHA256_AMD64"; rc="$RUNC_SHA256_AMD64"; gv="$GVISOR_SHA512_AMD64" ;; \
      arm64) g=aarch64; ctd="$CONTAINERD_SHA256_ARM64"; rc="$RUNC_SHA256_ARM64"; gv="$GVISOR_SHA512_ARM64" ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    get() { curl -fsSL --retry 5 --retry-all-errors --connect-timeout 10 -o "$1" "$2"; }; \
    get containerd.tgz "https://github.com/containerd/containerd/releases/download/v${CONTAINERD_VERSION}/containerd-static-${CONTAINERD_VERSION}-linux-${TARGETARCH}.tar.gz"; \
    echo "$ctd  containerd.tgz" | sha256sum -c --quiet -; \
    get runc "https://github.com/opencontainers/runc/releases/download/${RUNC_VERSION}/runc.${TARGETARCH}"; \
    echo "$rc  runc" | sha256sum -c --quiet -; \
    get gvisor.tar.bz2 "https://storage.googleapis.com/gvisor/releases/release/${GVISOR_RELEASE}/${g}/gvisor.tar.bz2"; \
    echo "$gv  gvisor.tar.bz2" | sha512sum -c --quiet -; \
    mkdir -p /out/gvisor-bin ctd gvisor; \
    tar -xzf containerd.tgz -C ctd; \
    install -m 0755 ctd/bin/* /out/; \
    install -m 0755 runc /out/runc; \
    tar -xjf gvisor.tar.bz2 -C gvisor; \
    runsc="$(find gvisor -type f -name runsc | head -1)"; \
    install -m 0755 "$runsc" /out/runsc; \
    install -m 0755 "$(find gvisor -type f -name containerd-shim-runsc-v1 | head -1)" /out/containerd-shim-runsc-v1; \
    if [ -d "$(dirname "$runsc")/gvisor-bin" ]; then \
      find "$(dirname "$runsc")/gvisor-bin" -maxdepth 1 -type f -exec install -m 0755 {} /out/gvisor-bin/ \; ; \
    fi

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="aerolvm-runtime" \
      org.opencontainers.image.description="AerolVM worker runtime: supervisor, containerd, runc, gVisor" \
      org.opencontainers.image.source="https://github.com/aerol-ai/microvm" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
# mount (util-linux, in the base) remounts a read-only cgroup mount; nothing
# else is added.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=fetch /out/ /usr/local/bin/
COPY ${TARGETARCH}/aerolvm-supervisor /usr/local/bin/aerolvm-supervisor
ENTRYPOINT ["/usr/local/bin/aerolvm-supervisor"]
