# syntax=docker/dockerfile:1
# aerolvm-edge: AerolVM's Caddy build (layer-4, the Cloudflare DNS module,
# S3 storage and the aerolvm_route plugin from caddymod/), for the worker
# pod's edge container and the gateways (plans/kubernetes-v2-architecture.md
# §8.2, P1). Its own container, so a sandboxd restart never cuts an open
# connection. Static, so it runs on distroless as a non-root user.
#
# Built by scripts/build-images.sh from the release build's <arch>/caddy.
ARG DISTROLESS_IMAGE

FROM ${DISTROLESS_IMAGE}
ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="aerolvm-edge" \
      org.opencontainers.image.description="AerolVM's Caddy build for sandbox links and custom domains" \
      org.opencontainers.image.source="https://github.com/aerol-ai/microvm" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY ${TARGETARCH}/caddy /usr/bin/caddy
# Certificates and Caddy's own state go on mounted volumes, so the root disk
# can stay read-only.
ENV XDG_CONFIG_HOME=/config XDG_DATA_HOME=/data
USER 65532:65532
ENTRYPOINT ["/usr/bin/caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
