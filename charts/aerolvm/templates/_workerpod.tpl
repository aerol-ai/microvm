{{- /*
The worker pod (plans/kubernetes-v2-architecture.md §8.2): runtime holds
containerd and every sandbox and changes only with containerd or gVisor;
agent is sandboxd; egress is the hostname-filtering gateway (C6); edge is
Caddy when sandbox links are on. The containers hand each other folders at
the same path. One definition for both modes: single mode's StatefulSet,
and cluster mode's pod template, which the operator stamps per worker
(P2): its name, zone, size, identity and setup container.
*/ -}}
{{- define "aerolvm.workerPodSpec" -}}
{{- $root := .root -}}
{{- $cluster := .cluster -}}
# No Kubernetes API rights (plan §8.7, wall 4).
automountServiceAccountToken: false
enableServiceLinks: false
{{- if or $root.Values.worker.wasm.enabled $root.Values.worker.isolate.enabled $root.Values.worker.firecracker.enabled }}
# WASM, V8-isolate and Firecracker sandboxes are processes sandboxd starts:
# with one process namespace for the pod they outlive an agent restart, and
# the next agent takes them over (C14). sandboxd refuses to start them
# without it.
shareProcessNamespace: true
{{- end }}
{{- if $root.Values.edge.enabled }}
# The edge container is not root, and Kubernetes gives a non-root
# container no ambient capabilities, so ports 80 and 443 are opened
# to every user in the pod's network instead (a namespaced sysctl
# Kubernetes counts as safe).
securityContext:
  sysctls:
    - { name: net.ipv4.ip_unprivileged_port_start, value: "0" }
{{- end }}
terminationGracePeriodSeconds: 30
{{- if $cluster }}
# The worker is the last pod the kubelet removes (§8.1). Its machine,
# zone and size come from its pool, which the operator stamps.
priorityClassName: {{ include "aerolvm.name" $root }}-worker
{{- else }}
{{- with $root.Values.worker.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $root.Values.worker.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $root.Values.worker.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
initContainers:
  # Checks the machine this pod landed on before anything starts (P10):
  # cgroup v2, the kernel version and br_netfilter. Every machine is
  # checked, a machine added later included. A failure stops the pod
  # here, its last log line naming each problem and its fix; the
  # kubelet keeps that line as the termination message, and the
  # operator shows it on the worker's AerolNode. Needs no rights.
  - name: preflight
    image: {{ include "aerolvm.image" (dict "root" $root "name" "aerolvm") }}
    imagePullPolicy: {{ $root.Values.image.pullPolicy }}
    command: ["sandboxd", "preflight", "--pod"{{ if $root.Values.worker.firecracker.enabled }}, "--kvm"{{ end }}]
    terminationMessagePolicy: FallbackToLogsOnError
    securityContext:
      runAsUser: 65532
      runAsGroup: 65532
      runAsNonRoot: true
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    # Requests equal limits, as in every container here: the pod stays
    # Guaranteed (S3).
    resources:
      requests: { cpu: 100m, memory: 64Mi }
      limits: { cpu: 100m, memory: 64Mi }
containers:
  - name: runtime
    image: {{ include "aerolvm.image" (dict "root" $root "name" "aerolvm-runtime") }}
    imagePullPolicy: {{ $root.Values.image.pullPolicy }}
    # Privileged: it builds sandboxes (cgroups, namespaces, gVisor).
    # No liveness probe: restarting this container ends every sandbox.
    securityContext:
      privileged: true
    resources:
      {{- toYaml $root.Values.worker.runtime.resources | nindent 6 }}
    {{- if or $cluster $root.Values.worker.isolate.enabled }}
    env:
      {{- if $cluster }}
      # sandboxd's ownership lease (C7). When it runs out the supervisor
      # freezes the sandboxes it fences, even with sandboxd down; that is
      # what lets a machine the operator says is gone fail over at its
      # lease limit instead of after the grace (C19).
      - { name: SB_OWNERSHIP_LEASE_FILE, value: /run/aerolvm/ownership-lease }
      {{- end }}
      {{- if $root.Values.worker.isolate.enabled }}
      # The V8 jail's mounts, unmounted when the pod ends (as netns, F8).
      - { name: SB_ISOLATE_JAIL_DIR, value: /var/lib/sandboxd/isolate-jail }
      {{- end }}
    {{- end }}
    volumeMounts:
      - { name: containerd, mountPath: /var/lib/containerd }
      - { name: state, mountPath: /var/lib/sandboxd }
      - { name: run-containerd, mountPath: /run/containerd }
      - { name: run-aerolvm, mountPath: /run/aerolvm }
      - { name: run-sandboxd, mountPath: /run/sandboxd }
      - { name: toolbox, mountPath: /opt/aerolvm/toolbox }
      # The network namespaces the agent makes, where containerd starts
      # sandboxes in them. Bidirectional, so the supervisor's unmount
      # when the pod ends reaches the machine; left mounted there, they
      # keep the pod in Terminating (finding F8).
      - { name: netns, mountPath: /run/netns, mountPropagation: Bidirectional }
      {{- if $root.Values.worker.isolate.enabled }}
      # The V8 jail's chroots, here only to unmount their tmpfs mounts
      # when the pod ends.
      - { name: isolate-jail, mountPath: /var/lib/sandboxd/isolate-jail, mountPropagation: Bidirectional }
      {{- end }}
  - name: agent
    image: {{ include "aerolvm.image" (dict "root" $root "name" "aerolvm") }}
    imagePullPolicy: {{ $root.Values.image.pullPolicy }}
    securityContext:
      privileged: true
    command: ["/bin/bash", "-c"]
    args:
      - |
        set -eu
        # The runtime container's containerd socket and the cgroup it
        # set up for sandboxes, both on shared folders.
        for _ in $(seq 1 120); do
          [ -S /run/containerd/containerd.sock ] && [ -s /run/aerolvm/cgroup-parent ] && break
          sleep 1
        done
        [ -s /run/aerolvm/cgroup-parent ] || { echo "agent: the runtime container did not start" >&2; exit 1; }
        SB_CONTAINERD_CGROUP_PARENT="$(cat /run/aerolvm/cgroup-parent)"
        export SB_CONTAINERD_CGROUP_PARENT
        # containerd bind-mounts toolboxd into each sandbox from the
        # runtime container, so it must be on a shared folder. Replaced
        # by rename: running sandboxes keep the copy they started with.
        cp /usr/local/bin/toolboxd /opt/aerolvm/toolbox/.toolboxd.new
        mv -f /opt/aerolvm/toolbox/.toolboxd.new /opt/aerolvm/toolbox/toolboxd
        mkdir -p /var/lib/sandboxd/mounts /run/sandboxd
        chmod 0700 /var/lib/sandboxd/mounts /run/sandboxd
        {{- if $root.Values.edge.enabled }}
        # Caddy's admin API first, as systemd orders the two on a VM:
        # sandboxd sets caddy-l4 up on :443 when it starts, and after a
        # failure tries again only on the first TCP exposure, so an
        # install that exposes only HTTP ports would never serve :443
        # (finding F15).
        for _ in $(seq 1 60); do
          (exec 3<>/dev/tcp/127.0.0.1/2019) 2>/dev/null && break
          sleep 1
        done
        {{- end }}
        {{- if $cluster }}
        # This node's settings and the cluster files its setup container
        # wrote (join --files-only, F14), loaded as systemd loads them on
        # a VM.
        # The pod's own settings beat both files, as sandboxd's own loader
        # has it: the operator sets some per start (a server's gossip
        # address is its pod IP now, where cluster.env keeps its DNS name).
        pod_env="$(export -p)"
        set -a
        . /etc/sandboxd/sandboxd.env
        [ -s /etc/sandboxd/cluster.env ] && . /etc/sandboxd/cluster.env
        set +a
        eval "$pod_env"
        {{- end }}
        exec sandboxd
    env:
      {{- /* In cluster mode a worker holds no admin token: its join gives
      it only the token's fingerprint, to check callers with. */}}
      {{- if not $cluster }}
      - name: SB_PAT_TOKEN
        valueFrom:
          secretKeyRef:
            name: {{ include "aerolvm.tokenSecret" $root }}
            key: SB_PAT_TOKEN
      {{- end }}
      - name: SB_NODE_NAME
        valueFrom:
          fieldRef:
            fieldPath: metadata.name
      {{- if $cluster }}
      # Written after each ownership answer from the leader, for the
      # runtime container's supervisor (C7, C19).
      - { name: SB_OWNERSHIP_LEASE_FILE, value: /run/aerolvm/ownership-lease }
      {{- end }}
      - { name: SB_API_HOST, value: "0.0.0.0" }
      - { name: SB_API_PORT, value: "21212" }
      - { name: SB_DB_PATH, value: /var/lib/sandboxd/state.db }
      - { name: SB_TOOLBOX_BINARY_PATH, value: /opt/aerolvm/toolbox/toolboxd }
      - { name: SB_TOOLBOX_MOUNT_PATH, value: /usr/local/bin/toolboxd }
      - { name: SB_TOOLBOX_PORT, value: "2280" }
      - { name: SB_ENABLE_NETWORK_RULES, value: "true" }
      - { name: SB_MOUNTS_ROOT, value: /var/lib/sandboxd/mounts }
      - { name: SB_MOUNTS_CRED_DIR, value: /run/sandboxd }
      {{- $runtimes := list "docker" "gvisor" }}
      {{- if $root.Values.worker.wasm.enabled }}{{ $runtimes = append $runtimes "wasm" }}{{ end }}
      {{- if $root.Values.worker.isolate.enabled }}{{ $runtimes = append $runtimes "isolate" }}{{ end }}
      {{- if $root.Values.worker.firecracker.enabled }}{{ $runtimes = append $runtimes "firecracker" }}{{ end }}
      - { name: SB_HOST_RUNTIMES, value: {{ join "," $runtimes | quote }} }
      {{- if $root.Values.worker.wasm.enabled }}
      # WASM workers start under the runtime container's sandboxes group
      # (SB_HOST_PROCESS_CGROUP_PARENT defaults to the containerd parent).
      - { name: SB_ENABLE_WASM, value: "true" }
      {{- end }}
      {{- if $root.Values.worker.isolate.enabled }}
      # workerd ships in this image; its group hosts and their jail's
      # cgroups go under the sandboxes group too. The jail's chroots are on
      # their own volume (isolate-jail, below), which outlives an agent
      # restart, so a host the next agent takes over still has its root.
      - { name: SB_ENABLE_ISOLATE, value: "true" }
      - { name: SB_ISOLATE_JAIL_CHROOT_BASE, value: /var/lib/sandboxd/isolate-jail }
      {{- end }}
      {{- if $root.Values.worker.firecracker.enabled }}
      # The image's guest kernel; the templates, the jailer's chroots and
      # the run dir sit on the pod's volumes, so a VM the next agent takes
      # over keeps its files. Each VM runs as jailerUID.
      - { name: SB_ENABLE_FIRECRACKER, value: "true" }
      - { name: SB_FIRECRACKER_KERNEL, value: /opt/aerolvm/firecracker/vmlinux }
      - { name: SB_JAILER_CHROOT_BASE, value: /var/lib/sandboxd/jailer }
      - { name: SB_JAILER_UID, value: {{ $root.Values.worker.firecracker.jailerUID | quote }} }
      - { name: SB_JAILER_GID, value: {{ $root.Values.worker.firecracker.jailerUID | quote }} }
      {{- end }}
      # The runtime image's aerolvm-runsc restores a moved gVisor sandbox.
      - { name: SB_GVISOR_CHECKPOINT_MOVES, value: {{ $root.Values.worker.gvisor.checkpointMoves | quote }} }
      - { name: SB_CONTAINER_ENGINE, value: containerd }
      - { name: SB_CONTAINERD_SOCKET, value: /run/containerd/containerd.sock }
      - { name: SB_CONTAINERD_NAMESPACE, value: aerolvm }
      - { name: SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED, value: "true" }
      # No Docker in the pod (C2).
      - { name: SB_DOCKER_ENABLED, value: "false" }
      - { name: SB_DISK_FLOOR_RATIO, value: {{ $root.Values.worker.diskFloorRatio | quote }} }
      - { name: SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT, value: {{ $root.Values.worker.blockPrivateByDefault | quote }} }
      # Per-owner usage counters on /v1/metrics (C20), read from each
      # sandbox's cgroup under SB_CONTAINERD_CGROUP_PARENT.
      - { name: SB_USAGE_METRICS_ENABLED, value: {{ $root.Values.worker.usageMetrics.enabled | quote }} }
      {{- include "aerolvm.egressRangeEnv" $root | nindent 6 }}
      # The egress container's user, by number (C6).
      - { name: SB_EGRESS_GATEWAY_USER, value: "65532" }
      {{- with $root.Values.worker.defaultRuntime }}
      - { name: SB_CONTAINER_RUNTIME, value: {{ . | quote }} }
      {{- end }}
      {{- if $root.Values.edge.enabled }}
      # A domain install's settings (scripts/install.sh), with the
      # certificate from a file Caddy loads and sandboxd watches (C25).
      - { name: SB_ENABLE_CADDY, value: "true" }
      - { name: SB_DOMAIN, value: {{ $root.Values.edge.domain | quote }} }
      - { name: SB_PUBLIC_HOST, value: {{ $root.Values.edge.domain | quote }} }
      - { name: SB_CADDY_ADMIN_URL, value: "http://127.0.0.1:2019" }
      - { name: SB_CADDY_SERVER_ID, value: srv0 }
      - { name: SB_L4_TLS_LISTEN, value: ":443" }
      - { name: SB_L4_TLS_FALLBACK, value: "127.0.0.1:8443" }
      - { name: SB_TLS_CERT_WATCH_FILE, value: /etc/aerolvm/tls/tls.crt }
      # The internet reaches 80 and 443 through the edge Service, and
      # so does a sandbox's traffic to the public name; the pod's own
      # ports stay closed to sandboxes (C24).
      - { name: SB_SANDBOX_NODE_INGRESS, value: "false" }
      {{- else }}
      - { name: SB_ENABLE_CADDY, value: "false" }
      {{- end }}
      {{- range $k, $v := $root.Values.worker.extraEnv }}
      - { name: {{ $k }}, value: {{ $v | quote }} }
      {{- end }}
    ports:
      - { name: api, containerPort: 21212 }
    # Ready while sandboxd can serve (C1). No liveness probe: a
    # restart of this container is safe but never needed for health.
    readinessProbe:
      httpGet: { path: /ready, port: api }
      periodSeconds: 5
    resources:
      {{- toYaml $root.Values.worker.agent.resources | nindent 6 }}
    volumeMounts:
      # containerd's root too: containerd's client library, inside
      # sandboxd, mounts an image's snapshot to read its users (S2).
      - { name: containerd, mountPath: /var/lib/containerd }
      - { name: state, mountPath: /var/lib/sandboxd }
      - { name: run-containerd, mountPath: /run/containerd }
      - { name: run-aerolvm, mountPath: /run/aerolvm }
      - { name: run-sandboxd, mountPath: /run/sandboxd }
      - { name: toolbox, mountPath: /opt/aerolvm/toolbox }
      {{- if $cluster }}
      - { name: etc, mountPath: /etc/sandboxd }
      {{- end }}
      # The CNI host-local plugin's record of the addresses it gave
      # out. In the container's own filesystem it was lost on an agent
      # restart, and the next warm slot got a running sandbox's
      # address again, cutting that sandbox off (found on kind).
      - { name: cni-state, mountPath: /var/lib/cni }
      # Kubernetes allows Bidirectional only in privileged containers.
      - { name: netns, mountPath: /run/netns, mountPropagation: Bidirectional }
      {{- if $root.Values.worker.isolate.enabled }}
      # The V8 jail's chroots. Each group's run and tmp folders get a
      # tmpfs; Bidirectional, so a restarted agent finds them and takes
      # the group over (C14) as it would on a VM.
      - { name: isolate-jail, mountPath: /var/lib/sandboxd/isolate-jail, mountPropagation: Bidirectional }
      {{- end }}
      {{- if $root.Values.edge.enabled }}
      # The certificate alone, to see it change: sandboxd never
      # needs the key.
      - { name: edge-cert, mountPath: /etc/aerolvm/tls, readOnly: true }
      {{- end }}
  {{- if $root.Values.edge.enabled }}
  - name: edge
    image: {{ include "aerolvm.image" (dict "root" $root "name" "aerolvm-edge") }}
    imagePullPolicy: {{ $root.Values.image.pullPolicy }}
    # AerolVM's Caddy for sandbox links and the API over HTTPS. Its
    # own container, so a sandboxd restart never cuts an open
    # connection. Non-root, no rights, read-only root disk.
    args: ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
    securityContext:
      runAsUser: 65532
      runAsGroup: 65532
      runAsNonRoot: true
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    ports:
      - { name: https, containerPort: 443 }
      - { name: http, containerPort: 80 }
    resources:
      {{- toYaml $root.Values.edge.resources | nindent 6 }}
    volumeMounts:
      - { name: edge-config, mountPath: /etc/caddy, readOnly: true }
      - { name: edge-tls, mountPath: /etc/aerolvm/tls, readOnly: true }
      - { name: edge-data, mountPath: /data }
      - { name: edge-state, mountPath: /config }
  {{- end }}
  - name: egress
    image: {{ include "aerolvm.image" (dict "root" $root "name" "aerolvm") }}
    imagePullPolicy: {{ $root.Values.image.pullPolicy }}
    # The hostname-filtering gateway without systemd (C6): its own
    # process in the pod's network, as uid 65532 with two rights. A
    # container that starts as that user would get neither: Kubernetes
    # puts added capabilities in the bounding set only, never ambient.
    # So it starts as root with just enough to hand itself over, and
    # setpriv drops to 65532 keeping exactly NET_ADMIN and
    # NET_BIND_SERVICE, as the systemd unit's AmbientCapabilities does.
    command:
      - setpriv
      - --reuid=65532
      - --regid=65532
      - --clear-groups
      - --inh-caps=-all,+net_admin,+net_bind_service
      - --ambient-caps=-all,+net_admin,+net_bind_service
      - --bounding-set=-all,+net_admin,+net_bind_service
      - /usr/local/bin/sandboxd
      - egress-gateway
    env:
      - { name: SB_EGRESS_PEER_CGROUP, value: none }
      - { name: SB_EGRESS_STATE_DIR, value: /var/lib/aerolvm-egress }
      # The gateway dials for sandboxes itself, so it must refuse the
      # same addresses sandboxd's firewall does (C24).
      {{- include "aerolvm.egressRangeEnv" $root | nindent 6 }}
    securityContext:
      runAsUser: 0
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
        add: ["NET_ADMIN", "NET_BIND_SERVICE", "SETUID", "SETGID", "SETPCAP"]
    resources:
      {{- toYaml $root.Values.worker.egress.resources | nindent 6 }}
    volumeMounts:
      - { name: run-aerolvm, mountPath: /run/aerolvm }
      - { name: egress-state, mountPath: /var/lib/aerolvm-egress }
volumes:
  - name: containerd
    {{- toYaml $root.Values.worker.containerdVolume | nindent 4 }}
  - name: state
    {{- toYaml $root.Values.worker.stateVolume | nindent 4 }}
  - { name: run-containerd, emptyDir: {} }
  - { name: run-aerolvm, emptyDir: {} }
  - { name: run-sandboxd, emptyDir: {} }
  - { name: toolbox, emptyDir: {} }
  - { name: cni-state, emptyDir: {} }
  - { name: netns, emptyDir: {} }
  {{- if $root.Values.worker.isolate.enabled }}
  - { name: isolate-jail, emptyDir: {} }
  {{- end }}
  - { name: egress-state, emptyDir: {} }
  {{- if $cluster }}
  # /etc/sandboxd: the node's settings and cluster files, written by the
  # setup container the operator adds.
  - { name: etc, emptyDir: {} }
  {{- end }}
  {{- if $root.Values.edge.enabled }}
  - name: edge-config
    configMap:
      name: {{ include "aerolvm.name" $root }}-edge
  # Mounted by key, so a Secret that gains other keys (a DNS token)
  # never reaches a pod; aerolvm k8s verify checks this (C25).
  - name: edge-tls
    secret:
      secretName: {{ include "aerolvm.edgeTLSSecret" $root }}
      items:
        - { key: tls.crt, path: tls.crt }
        - { key: tls.key, path: tls.key }
  - name: edge-cert
    secret:
      secretName: {{ include "aerolvm.edgeTLSSecret" $root }}
      items:
        - { key: tls.crt, path: tls.crt }
  - { name: edge-data, emptyDir: {} }
  - { name: edge-state, emptyDir: {} }
  {{- end }}
{{- end -}}
