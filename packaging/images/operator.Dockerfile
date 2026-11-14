# syntax=docker/dockerfile:1
# aerolvm-operator: the AerolVM operator (plans/kubernetes-v2-architecture.md
# P2, §7.4). Its own image (eng review D1), so a flaw in the Kubernetes
# client libraries it links is reported against this image only, never
# against sandboxd's. Static, so it runs on distroless as a non-root user.
#
# Built by scripts/build-images.sh from the release build's
# <arch>/aerolvm-operator (operator/, its own Go module).
# The base is pinned in the FROM line, by its multi-arch digest, the same
# as aerolvm-edge's: Scorecard and Dependabot read FROM lines.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="aerolvm-operator" \
      org.opencontainers.image.description="The AerolVM operator for Kubernetes" \
      org.opencontainers.image.source="https://github.com/aerol-ai/microvm" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY ${TARGETARCH}/aerolvm-operator /usr/bin/aerolvm-operator
USER 65532:65532
ENTRYPOINT ["/usr/bin/aerolvm-operator"]
