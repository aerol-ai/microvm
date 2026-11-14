# syntax=docker/dockerfile:1
# aerolvm: sandboxd (plans/kubernetes-v2-architecture.md P1). The agent,
# server and gateway pods all run it; SB_NODE_ROLE picks the role. It ships
# toolboxd (bind-mounted into every sandbox) and the CNI plugins the agent
# runs to build each sandbox's network, plus the tools those plugins and
# sandboxd's firewall need, and workerd for V8-isolate sandboxes (Phase 5;
# used only with SB_ENABLE_ISOLATE), and for Firecracker pools (used only
# with SB_ENABLE_FIRECRACKER) firecracker, its jailer, a guest kernel and
# the tools that turn an image into a VM's disk (skopeo, umoci, mkfs.ext4).
#
# Built by scripts/build-images.sh: the context holds <arch>/sandboxd and
# <arch>/toolboxd from the release build, and versions.env's pins arrive as
# build args. sandboxd links glibc, so the base is a Debian with a newer one
# than the release build machine's.
# The base is pinned by its multi-arch index digest right here, where
# Scorecard and Dependabot read it (a FROM ${ARG} hides the pin from both).

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS fetch
ARG TARGETARCH
ARG CNI_PLUGINS_VERSION
ARG CNI_PLUGINS_SHA256_AMD64
ARG CNI_PLUGINS_SHA256_ARM64
ARG WORKERD_VERSION
ARG WORKERD_SHA256_AMD64
ARG WORKERD_SHA256_ARM64
ARG FIRECRACKER_VERSION
ARG FIRECRACKER_SHA256_AMD64
ARG FIRECRACKER_SHA256_ARM64
ARG FIRECRACKER_KERNEL_CI_VERSION
ARG FIRECRACKER_KERNEL_VERSION
ARG FIRECRACKER_KERNEL_SHA256_AMD64
ARG FIRECRACKER_KERNEL_SHA256_ARM64
ARG FIRECRACKER_KERNEL_CONFIG_SHA256_AMD64
ARG FIRECRACKER_KERNEL_CONFIG_SHA256_ARM64
ARG GVISOR_RELEASE
ARG GVISOR_SHA512_AMD64
ARG GVISOR_SHA512_ARM64
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl bzip2 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /fetch
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) sum="$CNI_PLUGINS_SHA256_AMD64" ;; \
      arm64) sum="$CNI_PLUGINS_SHA256_ARM64" ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --retry 5 --retry-all-errors --connect-timeout 10 -o cni.tgz \
      "https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/cni-plugins-linux-${TARGETARCH}-${CNI_PLUGINS_VERSION}.tgz"; \
    echo "$sum  cni.tgz" | sha256sum -c --quiet -; \
    mkdir -p /out/cni; \
    tar -xzf cni.tgz -C /out/cni
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) file=workerd-linux-64.gz; sum="$WORKERD_SHA256_AMD64" ;; \
      arm64) file=workerd-linux-arm64.gz; sum="$WORKERD_SHA256_ARM64" ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --retry 5 --retry-all-errors --connect-timeout 10 -o workerd.gz \
      "https://github.com/cloudflare/workerd/releases/download/${WORKERD_VERSION}/${file}"; \
    echo "$sum  workerd.gz" | sha256sum -c --quiet -; \
    gunzip -c workerd.gz > /out/workerd; \
    chmod 0755 /out/workerd
# Firecracker names CPU types its own way (x86_64, aarch64).
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) arch=x86_64; fc="$FIRECRACKER_SHA256_AMD64"; k="$FIRECRACKER_KERNEL_SHA256_AMD64"; kc="$FIRECRACKER_KERNEL_CONFIG_SHA256_AMD64" ;; \
      arm64) arch=aarch64; fc="$FIRECRACKER_SHA256_ARM64"; k="$FIRECRACKER_KERNEL_SHA256_ARM64"; kc="$FIRECRACKER_KERNEL_CONFIG_SHA256_ARM64" ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    get() { curl -fsSL --retry 5 --retry-all-errors --connect-timeout 10 -o "$1" "$2"; echo "$3  $1" | sha256sum -c --quiet -; }; \
    get fc.tgz "https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-${arch}.tgz" "$fc"; \
    tar -xzf fc.tgz; \
    mkdir -p /out/fc; \
    install -m 0755 "release-${FIRECRACKER_VERSION}-${arch}/firecracker-${FIRECRACKER_VERSION}-${arch}" /out/fc/firecracker; \
    install -m 0755 "release-${FIRECRACKER_VERSION}-${arch}/jailer-${FIRECRACKER_VERSION}-${arch}" /out/fc/jailer; \
    kernel="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/${FIRECRACKER_KERNEL_CI_VERSION}/${arch}/vmlinux-${FIRECRACKER_KERNEL_VERSION}"; \
    get /out/fc/vmlinux "$kernel" "$k"; \
    get /out/fc/vmlinux.config "$kernel.config" "$kc"
# runsc, the runtime image's release: sandboxd saves a gVisor sandbox with
# `runsc checkpoint` when a decommission moves it (C21), as the shim has no
# checkpoint of its own.
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) g=x86_64; gv="$GVISOR_SHA512_AMD64" ;; \
      arm64) g=aarch64; gv="$GVISOR_SHA512_ARM64" ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --retry 5 --retry-all-errors --connect-timeout 10 -o gvisor.tar.bz2 \
      "https://storage.googleapis.com/gvisor/releases/release/${GVISOR_RELEASE}/${g}/gvisor.tar.bz2"; \
    echo "$gv  gvisor.tar.bz2" | sha512sum -c --quiet -; \
    mkdir -p gvisor; \
    tar -xjf gvisor.tar.bz2 -C gvisor; \
    install -m 0755 "$(find gvisor -type f -name runsc | head -1)" /out/runsc

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="aerolvm" \
      org.opencontainers.image.description="AerolVM sandboxd: agent, server and gateway roles" \
      org.opencontainers.image.source="https://github.com/aerol-ai/microvm" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
# iproute2, iptables and nftables: the CNI bridge plugin's NAT and sandboxd's
# per-sandbox rules (the Phase 0 agent installed the same, agent.sh).
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates iproute2 iptables nftables procps \
      skopeo umoci e2fsprogs \
    && rm -rf /var/lib/apt/lists/*
COPY --from=fetch /out/cni /opt/aerolvm/cni
COPY --from=fetch /out/workerd /usr/local/bin/workerd
COPY --from=fetch /out/fc/firecracker /out/fc/jailer /out/runsc /usr/local/bin/
# Not under /var/lib/sandboxd, the worker pod's state volume, which would
# hide it: the chart points SB_FIRECRACKER_KERNEL here.
COPY --from=fetch /out/fc/vmlinux /out/fc/vmlinux.config /opt/aerolvm/firecracker/
COPY ${TARGETARCH}/sandboxd ${TARGETARCH}/toolboxd /usr/local/bin/
ENV SB_TOOLBOX_BINARY_PATH=/usr/local/bin/toolboxd \
    SB_CONTAINERD_CNI_PLUGIN_DIR=/opt/aerolvm/cni
ENTRYPOINT ["/usr/local/bin/sandboxd"]
