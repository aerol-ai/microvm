{{- /*
Server and gateway pods (plans/kubernetes-v2-architecture.md §7.1, §7.2):
sandboxd alone (and, on a gateway, the edge), under `restricted` pod
security: uid 65532, no capabilities, no privilege escalation, a read-only
root disk (C5, measured on kind with integration-tests/k8s/c5.sh). They hold
no Kubernetes API rights. The operator stamps each pod: its name, zone,
volume (a server's disk), settings and the setup container that writes its
cluster files (init or join --files-only, F14).
*/ -}}
{{- define "aerolvm.controlPodSpec" -}}
{{- $root := .root -}}
{{- $role := .role -}}
{{- $gateway := eq $role "gateway" -}}
{{- $edge := and $gateway $root.Values.edge.enabled -}}
{{- $kubeAPI := $root.Values.cluster.agentSandboxAPI.enabled -}}
{{- if and $gateway $kubeAPI }}
# The agent-sandbox API (C17) asks Kubernetes who may do what
# (SubjectAccessReview) and reads the front-proxy CA: the one Kubernetes
# right a gateway holds, through its own service account.
serviceAccountName: {{ $root.Values.cluster.name }}-gateway
automountServiceAccountToken: true
{{- else }}
automountServiceAccountToken: false
{{- end }}
enableServiceLinks: false
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  fsGroup: 65532
  seccompProfile: { type: RuntimeDefault }
  {{- if $edge }}
  # The edge binds 80 and 443 as a non-root user: a namespaced sysctl
  # Kubernetes counts as safe, allowed under `restricted`.
  sysctls:
    - { name: net.ipv4.ip_unprivileged_port_start, value: "0" }
  {{- end }}
# A server hands off Raft leadership and a gateway drains on SIGTERM (C8).
terminationGracePeriodSeconds: 45
containers:
  - name: agent
    image: {{ include "aerolvm.image" (dict "root" $root "name" "aerolvm") }}
    imagePullPolicy: {{ $root.Values.image.pullPolicy }}
    command: ["/bin/bash", "-c"]
    args:
      - |
        set -eu
        # This node's settings and the cluster files its setup container
        # wrote, loaded as systemd loads them on a VM.
        # The pod's own settings beat both files, as sandboxd's own loader
        # has it: the operator sets some per start (a server's gossip
        # address is its pod IP now, where cluster.env keeps its DNS name).
        pod_env="$(export -p)"
        set -a
        . /etc/sandboxd/sandboxd.env
        [ -s /etc/sandboxd/cluster.env ] && . /etc/sandboxd/cluster.env
        set +a
        eval "$pod_env"
        # sandboxd cannot change the mode of a volume's own root (C5), so
        # its database lives one folder down.
        mkdir -p /var/lib/sandboxd/db
        {{- if $edge }}
        # Caddy's admin API first, as on the worker (finding F15).
        for _ in $(seq 1 60); do
          (exec 3<>/dev/tcp/127.0.0.1/2019) 2>/dev/null && break
          sleep 1
        done
        {{- end }}
        exec sandboxd
    env:
      {{- if eq $role "server" }}
      # A server holds the admin token: `sandboxd init` writes the admin
      # login from it, and peers check it. The operator made it.
      - name: SB_PAT_TOKEN
        valueFrom:
          secretKeyRef:
            name: {{ $root.Values.cluster.name }}-admin
            key: token
      {{- end }}
      - { name: SB_API_HOST, value: "0.0.0.0" }
      - { name: SB_API_PORT, value: "21212" }
      - { name: SB_DB_PATH, value: /var/lib/sandboxd/db/state.db }
      - { name: SB_CREDENTIAL_ENCRYPTION_KEY_PATH, value: /var/lib/sandboxd/credential_encryption.key }
      - { name: SB_TOOLBOX_BINARY_PATH, value: /usr/local/bin/toolboxd }
      - { name: SB_MOUNTS_ROOT, value: /var/lib/sandboxd/mounts }
      - { name: SB_MOUNTS_CRED_DIR, value: /run/sandboxd }
      # It runs no sandbox: no engine to reach, no firewall to write (C2).
      - { name: SB_CONTAINER_ENGINE, value: containerd }
      - { name: SB_DOCKER_ENABLED, value: "false" }
      - { name: SB_ENABLE_NETWORK_RULES, value: "false" }
      # Asking a server for the owner on every routed request costs the
      # servers by traffic; the cache costs them by sandbox (E3).
      - { name: SB_CLUSTER_OWNER_CACHE, value: "true" }
      {{- if $gateway }}
      # The gateway serves sandbox links by SNI with no per-sandbox Caddy
      # writes (C11, plans/ingress-proxy-routing.md), and SSH.
      - { name: SB_INGRESS_PROXY_ROUTING, value: "true" }
      - { name: SB_ENABLE_SSH_GATEWAY, value: "true" }
      {{- end }}
      {{- if $edge }}
      - { name: SB_ENABLE_CADDY, value: "true" }
      - { name: SB_DOMAIN, value: {{ $root.Values.edge.domain | quote }} }
      - { name: SB_PUBLIC_HOST, value: {{ $root.Values.edge.domain | quote }} }
      - { name: SB_INGRESS_ADVERTISE_HOST, value: {{ $root.Values.edge.domain | quote }} }
      - { name: SB_CADDY_ADMIN_URL, value: "http://127.0.0.1:2019" }
      - { name: SB_CADDY_SERVER_ID, value: srv0 }
      - { name: SB_L4_TLS_LISTEN, value: ":443" }
      - { name: SB_L4_TLS_FALLBACK, value: "127.0.0.1:8443" }
      - { name: SB_TLS_CERT_WATCH_FILE, value: /etc/aerolvm/tls/tls.crt }
      {{- else }}
      - { name: SB_ENABLE_CADDY, value: "false" }
      {{- end }}
      {{- if $kubeAPI }}
      {{- include "aerolvm.agentSandboxEnv" $root | nindent 6 }}
      {{- end }}
      {{- range $k, $v := $root.Values.worker.extraEnv }}
      {{- if or (hasPrefix "SB_CLUSTER_" $k) (eq $k "SB_DEAD_OWNER_GRACE") }}
      - { name: {{ $k }}, value: {{ $v | quote }} }
      {{- end }}
      {{- end }}
    ports:
      - { name: api, containerPort: 21212 }
      - { name: raft, containerPort: 7000 }
      - { name: gossip, containerPort: 7001 }
      - { name: gossip-udp, containerPort: 7001, protocol: UDP }
      - { name: internal, containerPort: 7002 }
      - { name: join, containerPort: 7003 }
      {{- if $gateway }}
      - { name: ssh, containerPort: 2220 }
      {{- end }}
      {{- if and $gateway $kubeAPI }}
      - { name: agent-sandbox, containerPort: 9443 }
      {{- end }}
    readinessProbe:
      httpGet: { path: /ready, port: api }
      periodSeconds: 5
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities: { drop: ["ALL"] }
    volumeMounts:
      - { name: etc, mountPath: /etc/sandboxd }
      - { name: state, mountPath: /var/lib/sandboxd }
      - { name: run, mountPath: /run/sandboxd }
      - { name: tmp, mountPath: /tmp }
      {{- if $edge }}
      - { name: edge-cert, mountPath: /etc/aerolvm/tls, readOnly: true }
      {{- end }}
      {{- if and $gateway $kubeAPI }}
      - { name: agent-sandbox-tls, mountPath: /etc/aerolvm/agent-sandbox-api, readOnly: true }
      {{- end }}
  {{- if $edge }}
  - name: edge
    image: {{ include "aerolvm.image" (dict "root" $root "name" "aerolvm-edge") }}
    imagePullPolicy: {{ $root.Values.image.pullPolicy }}
    args: ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities: { drop: ["ALL"] }
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
volumes:
  - { name: etc, emptyDir: {} }
  - { name: state, emptyDir: {} }
  - { name: run, emptyDir: {} }
  - { name: tmp, emptyDir: {} }
  {{- if and $gateway $kubeAPI }}
  - name: agent-sandbox-tls
    secret:
      secretName: {{ $root.Values.cluster.name }}-agent-sandbox-api-tls
      items:
        - { key: tls.crt, path: tls.crt }
        - { key: tls.key, path: tls.key }
  {{- end }}
  {{- if $edge }}
  - name: edge-config
    configMap:
      name: {{ include "aerolvm.name" $root }}-edge
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
