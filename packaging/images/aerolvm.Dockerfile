# syntax=docker/dockerfile:1
# aerolvm: sandboxd (plans/kubernetes-v2-architecture.md P1). The agent,
# server and gateway pods all run it; SB_NODE_ROLE picks the role. It ships
# toolboxd (bind-mounted into every sandbox) and the CNI plugins the agent
# runs to build each sandbox's network, plus the tools those plugins and
# sandboxd's firewall need, and workerd for V8-isolate sandboxes (Phase 5;
# used only with SB_ENABLE_ISOLATE).
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
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
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
    && rm -rf /var/lib/apt/lists/*
COPY --from=fetch /out/cni /opt/aerolvm/cni
COPY --from=fetch /out/workerd /usr/local/bin/workerd
COPY ${TARGETARCH}/sandboxd ${TARGETARCH}/toolboxd /usr/local/bin/
ENV SB_TOOLBOX_BINARY_PATH=/usr/local/bin/toolboxd \
    SB_CONTAINERD_CNI_PLUGIN_DIR=/opt/aerolvm/cni
ENTRYPOINT ["/usr/local/bin/sandboxd"]
