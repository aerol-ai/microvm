#!/usr/bin/env bash
# minio-store.sh: a MinIO the live external-mount checks use as the remote
# store. Sourced by s2m.sh and fckind/mount.sh. Those checks used rclone's
# local backend to stand in for a remote store; sandboxd now refuses it
# (it serves a folder of the host, plans/security-gaps-m1-m4.md Q2), so
# they mount an rclone s3 remote against this MinIO instead.
#
#   minio_store_up kubectl [args...]  starts a MinIO pod and an mc pod in
#                                     that kubectl's namespace, makes the
#                                     bucket, and sets:
#     MINIO_IP           the MinIO pod's address, the remote's endpoint (a
#                        NetworkPolicy may need it opened: it is private)
#     MINIO_BUCKET       the bucket the sandbox mounts
#     MINIO_RCLONE_CONF  an rclone.conf with one remote, [store], for it
#   minio_mc args...                  runs mc against it, as alias "store"
#   minio_store_down                  deletes both pods
#
# minio/minio is gone from Docker Hub and quay, so the images are
# Chainguard's: cgr.dev/chainguard/minio (entrypoint /usr/bin/minio) and
# cgr.dev/chainguard/minio-client:latest-dev (it has a shell to idle in).
# Both run as uid 65532, and the pods pass the restricted Pod Security
# profile. The credentials are random per run; they reach sandboxd only
# inside credentials.rclone_conf, which it seals.

MINIO_POD=aerolvm-test-minio
MC_POD=aerolvm-test-mc
MINIO_BUCKET=sandbox-store
MINIO_KUBECTL=()

minio_store_up() {
  MINIO_KUBECTL=("$@")
  MINIO_USER="u$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
  MINIO_PASS="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  "${MINIO_KUBECTL[@]}" delete pod "$MINIO_POD" "$MC_POD" --ignore-not-found --wait=true >/dev/null 2>&1 || true
  "${MINIO_KUBECTL[@]}" apply -f - >/dev/null <<EOF || return 1
apiVersion: v1
kind: Pod
metadata:
  name: $MINIO_POD
  labels: { app: $MINIO_POD }
spec:
  securityContext:
    runAsUser: 65532
    runAsGroup: 65532
    fsGroup: 65532
    runAsNonRoot: true
    seccompProfile: { type: RuntimeDefault }
  containers:
    - name: minio
      image: cgr.dev/chainguard/minio:latest
      command: ["/usr/bin/minio"]
      args: ["server", "/data", "--address", ":9000"]
      env:
        - { name: MINIO_ROOT_USER, value: "$MINIO_USER" }
        - { name: MINIO_ROOT_PASSWORD, value: "$MINIO_PASS" }
      ports: [{ containerPort: 9000 }]
      readinessProbe:
        httpGet: { path: /minio/health/ready, port: 9000 }
        periodSeconds: 2
      securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }
      volumeMounts: [{ name: data, mountPath: /data }]
  volumes: [{ name: data, emptyDir: {} }]
---
apiVersion: v1
kind: Pod
metadata:
  name: $MC_POD
  labels: { app: $MC_POD }
spec:
  securityContext:
    runAsUser: 65532
    runAsGroup: 65532
    runAsNonRoot: true
    seccompProfile: { type: RuntimeDefault }
  containers:
    - name: mc
      image: cgr.dev/chainguard/minio-client:latest-dev
      command: ["sh", "-c", "sleep 86400"]
      env: [{ name: MC_CONFIG_DIR, value: /tmp/.mc }]
      securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }
EOF
  "${MINIO_KUBECTL[@]}" wait --for=condition=Ready "pod/$MINIO_POD" "pod/$MC_POD" --timeout=300s >/dev/null || return 1
  MINIO_IP="$("${MINIO_KUBECTL[@]}" get pod "$MINIO_POD" -o jsonpath='{.status.podIP}')"
  [ -n "$MINIO_IP" ] || return 1
  minio_mc mb --ignore-existing "store/$MINIO_BUCKET" >/dev/null || return 1
  # shellcheck disable=SC2034 # read by the scripts that source this one
  MINIO_RCLONE_CONF="$(printf '[store]\ntype = s3\nprovider = Minio\nendpoint = http://%s:9000\naccess_key_id = %s\nsecret_access_key = %s\n' \
    "$MINIO_IP" "$MINIO_USER" "$MINIO_PASS")"
}

minio_mc() {
  "${MINIO_KUBECTL[@]}" exec -i "$MC_POD" -- \
    env "MC_HOST_store=http://$MINIO_USER:$MINIO_PASS@$MINIO_IP:9000" mc --quiet "$@"
}

minio_store_down() {
  [ "${#MINIO_KUBECTL[@]}" -gt 0 ] || return 0
  "${MINIO_KUBECTL[@]}" delete pod "$MINIO_POD" "$MC_POD" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
