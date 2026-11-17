{{- define "aerolvm.name" -}}
{{- .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- end -}}

{{- define "aerolvm.labels" -}}
app.kubernetes.io/name: aerolvm
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "aerolvm.selector" -}}
app.kubernetes.io/name: aerolvm
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: worker
{{- end -}}

{{- /* An image by name. The Azure Marketplace package names each image
under global.azure.images (packaging/marketplace/azure): registry, image and
digest, which it rewrites to its own registry; without it, the chart's
registry and tag. */ -}}
{{- define "aerolvm.image" -}}
{{- $az := dig "azure" "images" .name dict (.root.Values.global | default dict) -}}
{{- if and $az.registry $az.image $az.digest -}}
{{- printf "%s/%s@%s" $az.registry $az.image $az.digest -}}
{{- else -}}
{{- $tag := .root.Values.image.tag | default .root.Chart.AppVersion -}}
{{- printf "%s/%s:%s" .root.Values.image.registry .name $tag -}}
{{- end -}}
{{- end -}}

{{- define "aerolvm.edgeTLSSecret" -}}
{{- .Values.edge.existingTLSSecret | default (printf "%s-edge-tls" (include "aerolvm.name" .)) -}}
{{- end -}}

{{- /* An address or a CIDR as a CIDR: a bare address is one host. */ -}}
{{- define "aerolvm.cidr" -}}
{{- if contains "/" . -}}
{{- . -}}
{{- else if contains ":" . -}}
{{- printf "%s/128" . -}}
{{- else -}}
{{- printf "%s/32" . -}}
{{- end -}}
{{- end -}}

{{- /* The cluster's own addresses (C24), for every container that guards
sandbox traffic: sandboxd and the egress gateway read the same lists. */ -}}
{{- define "aerolvm.egressRangeEnv" -}}
{{- with .Values.worker.egressDenyFloor }}
- { name: SB_EGRESS_DENY_FLOOR_CIDRS, value: {{ join "," . | quote }} }
{{- end }}
{{- with .Values.worker.egressPrivateRanges }}
- { name: SB_EGRESS_PRIVATE_DEFAULT_CIDRS, value: {{ join "," . | quote }} }
{{- end }}
{{- end -}}

{{- define "aerolvm.tokenSecret" -}}
{{- .Values.apiToken.existingSecret | default (printf "%s-api-token" (include "aerolvm.name" .)) -}}
{{- end -}}

{{- /* NetworkPolicy peers: every pod of this install, the release
namespace's (servers, gateways, the operator) and the workers. */ -}}
{{- define "aerolvm.installPeers" -}}
- namespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: {{ .Release.Namespace }}
  podSelector:
    matchLabels:
      app.kubernetes.io/name: aerolvm
      app.kubernetes.io/instance: {{ .Release.Name }}
- namespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: {{ .Values.cluster.workerNamespace }}
  podSelector:
    matchLabels:
      {{- include "aerolvm.selector" . | nindent 6 }}
{{- end -}}

{{/*
API tokens and the settings that go with them, on every node of the install
alike: identity.enabled, identity.tokenMaxTTL, identity.file and
enterprise.enabled. A node with tokens off refuses every token, so a cluster
that had them on its workers alone (worker.extraEnv, the only way before)
answered a scrape token 401 on its servers and gateways (issue #1343), and a
cap or an identity file there bound workers only, which take no token write.
worker.extraEnv may not set any of them in cluster mode (a false value of a
switch turns nothing on and passes), nor beside its chart value.
*/}}
{{- define "aerolvm.identityEnv" -}}
{{- $identity := .Values.identity | default dict }}
{{- $enterprise := .Values.enterprise | default dict }}
{{- $file := $identity.file | default dict }}
{{- $fileOn := or $file.content $file.existingConfigMap }}
{{- $env := .Values.worker.extraEnv | default dict }}
{{- $values := dict "SB_IDENTITY_ENABLED" "identity.enabled" "SB_TOKEN_MAX_TTL" "identity.tokenMaxTTL" "SB_IDENTITY_FILE" "identity.file" "SB_ENTERPRISE_MODE" "enterprise.enabled" }}
{{- $set := dict "SB_IDENTITY_ENABLED" $identity.enabled "SB_TOKEN_MAX_TTL" $identity.tokenMaxTTL "SB_IDENTITY_FILE" $fileOn "SB_ENTERPRISE_MODE" $enterprise.enabled }}
{{- range $key, $value := $values }}
{{- if hasKey $env $key }}
{{- $given := index $env $key | toString | trim }}
{{- /* A false value (strconv.ParseBool's, which sandboxd reads with) of a
switch turns nothing on, so cluster mode lets it be. */}}
{{- $off := and (has $key (list "SB_IDENTITY_ENABLED" "SB_ENTERPRISE_MODE")) (has $given (list "false" "False" "FALSE" "0" "f" "F")) }}
{{- if and (not $off) (ne $.Values.mode "single") }}
{{- fail (printf "worker.extraEnv.%s (%s) reaches workers only, so servers and gateways would not match it: in cluster mode it is set for every node with %s. Remove it, and set %s." $key $given $value $value) }}
{{- end }}
{{- if index $set $key }}
{{- fail (printf "%s is set twice: keep %s and remove worker.extraEnv.%s." $key $value $key) }}
{{- end }}
{{- end }}
{{- end }}
{{- if and $fileOn (not $identity.enabled) }}
{{- fail "identity.file needs identity.enabled=true: with API tokens off, sandboxd never reads the identity file." }}
{{- end }}
{{- if and $enterprise.enabled (not $identity.enabled) }}
{{- fail "enterprise.enabled needs identity.enabled=true: enterprise mode refuses to start without named credentials." }}
{{- end }}
{{- /* Enterprise mode refuses SB_TOKEN_MAX_TTL over 90 days at boot, so
refuse it here: every pod would crash. The duration in seconds, summed from
its Go units. */}}
{{- if and $enterprise.enabled $identity.tokenMaxTTL }}
{{- $secs := 0.0 }}
{{- $units := dict "ns" 0.000000001 "us" 0.000001 "ms" 0.001 "s" 1.0 "m" 60.0 "h" 3600.0 }}
{{- range regexFindAll "[0-9]+(\\.[0-9]+)?(ns|us|ms|s|m|h)" (toString $identity.tokenMaxTTL) -1 }}
{{- $num := regexFind "^[0-9]+(\\.[0-9]+)?" . | float64 }}
{{- $secs = addf $secs (mulf $num (get $units (regexReplaceAll "^[0-9]+(\\.[0-9]+)?" . ""))) }}
{{- end }}
{{- if gt $secs 7776000.0 }}
{{- fail (printf "identity.tokenMaxTTL %s is longer than enterprise mode allows (2160h, 90 days): every node would refuse to start. Lower it, or leave it empty for enterprise mode's 90 days." (toString $identity.tokenMaxTTL)) }}
{{- end }}
{{- end }}
{{- with $identity.tokenMaxTTL }}
{{- if not (regexMatch "^([0-9]+(\\.[0-9]+)?(ns|us|ms|s|m|h))+$" (toString .)) }}
{{- fail (printf "identity.tokenMaxTTL %q is not a duration sandboxd reads: write hours, such as 2160h for 90 days" (toString .)) }}
{{- end }}
{{- end }}
{{- if $identity.enabled }}
- { name: SB_IDENTITY_ENABLED, value: "true" }
{{- end }}
{{- with $identity.tokenMaxTTL }}
- { name: SB_TOKEN_MAX_TTL, value: {{ toString . | quote }} }
{{- end }}
{{- if $fileOn }}
- { name: SB_IDENTITY_FILE, value: {{ printf "/etc/aerolvm/identity/%s" ($file.key | default "identity.yaml") | quote }} }
{{- end }}
{{- if $enterprise.enabled }}
- { name: SB_ENTERPRISE_MODE, value: "true" }
{{- end }}
{{- end -}}

{{/*
The lifetime of the scrape token the notes and the scrape-token refusal tell
you to make: identity.tokenMaxTTL when set (every node allows it), else 90d,
which every default cap allows. Every token needs one (expires_in is
required).
*/}}
{{- define "aerolvm.scrapeTokenExpiresIn" -}}
{{- (.Values.identity | default dict).tokenMaxTTL | default "90d" -}}
{{- end -}}

{{/*
The identity file's ConfigMap: the chart's own (identity.file.content) or
the one named in identity.file.existingConfigMap. A whole folder, so an
edit reaches the running node and jwks_file can name another key.
*/}}
{{- define "aerolvm.identityFileConfigMap" -}}
{{- $file := (.Values.identity | default dict).file | default dict }}
{{- $file.existingConfigMap | default (printf "%s-identity" (include "aerolvm.name" .)) -}}
{{- end -}}

{{- define "aerolvm.identityFileMount" -}}
{{- $file := (.Values.identity | default dict).file | default dict }}
{{- if or $file.content $file.existingConfigMap }}
- { name: identity-file, mountPath: /etc/aerolvm/identity, readOnly: true }
{{- end }}
{{- end -}}

{{- define "aerolvm.identityFileVolume" -}}
{{- $file := (.Values.identity | default dict).file | default dict }}
{{- if or $file.content $file.existingConfigMap }}
- name: identity-file
  configMap:
    name: {{ include "aerolvm.identityFileConfigMap" . }}
{{- end }}
{{- end -}}

{{/*
The agent-sandbox API's settings (C17), on every node: gateways serve it,
nodes with sandboxes report their run state.
*/}}
{{- define "aerolvm.agentSandboxEnv" -}}
- { name: SB_AGENT_SANDBOX_API, value: "true" }
{{- with .Values.cluster.agentSandboxAPI.namespaces }}
{{- $pairs := list }}
{{- range $ns, $owner := . }}
{{- $pairs = append $pairs (printf "%s=%s" $ns $owner) }}
{{- end }}
- { name: SB_AGENT_SANDBOX_API_NAMESPACES, value: {{ join "," $pairs | quote }} }
{{- end }}
{{- end -}}

{{/*
Enterprise mode's admin-token rule and the audit evidence settings, on every
node of a cluster alike (issue #1349). Each check fails the render where
sandboxd would refuse to start, so a mistake shows at `helm install`, not as
crash-looping pods.
*/}}
{{- define "aerolvm.publicSocketDir" -}}/run/sandboxd-public{{- end -}}
{{- /* One folder down: the volume's own root belongs to root, and sandboxd,
not root on a server or gateway, sets its socket folder's owner and mode. */ -}}
{{- define "aerolvm.publicSocket" -}}{{ include "aerolvm.publicSocketDir" . }}/api/api.sock{{- end -}}

{{- define "aerolvm.nodeServiceAccount" -}}
{{- printf "%s-node" (include "aerolvm.name" .) -}}
{{- end -}}

{{- define "aerolvm.auditEnv" -}}
{{- $enterprise := (.Values.enterprise | default dict).enabled }}
{{- $audit := .Values.audit | default dict }}
{{- $w := $audit.witness | default dict }}
{{- $x := $audit.export | default dict }}
{{- $xs3 := $x.s3 | default dict }}
{{- $hook := $x.webhook | default dict }}
{{- $creds := $audit.credentials | default dict }}
{{- $ca := $creds.caBundle | default dict }}
{{- $backend := $x.backend | default "" | lower | trim }}
{{- if $enterprise }}
{{- if ne .Values.mode "cluster" }}
{{- fail "enterprise.enabled needs mode=cluster: on Kubernetes enterprise mode runs in cluster mode only." }}
{{- end }}
{{- if not $w.bucket }}
{{- fail "enterprise.enabled needs audit.witness.bucket: enterprise mode refuses to start without an S3 Object Lock audit witness." }}
{{- end }}
{{- if not (has $backend (list "s3" "webhook")) }}
{{- fail "enterprise.enabled needs audit.export.backend s3 or webhook: enterprise mode refuses to start while audit records stay on the node." }}
{{- end }}
{{- /* Enterprise mode refuses to start past 10 live gateways unless the
traffic in front of them is shard-aware (SB_CLUSTER_SHARD_AWARE_INGRESS,
which worker.extraEnv gives every node). The operator keeps minReplicas
gateways, or one per zone if that is more. */}}
{{- $gateways := max (int .Values.cluster.gateways.minReplicas) (len .Values.cluster.zones) }}
{{- /* sandboxd reads it with strconv.ParseBool. */}}
{{- $shardAware := has (toString (index (.Values.worker.extraEnv | default dict) "SB_CLUSTER_SHARD_AWARE_INGRESS" | default "") | trim) (list "1" "t" "T" "true" "TRUE" "True") }}
{{- if and (gt (int $gateways) 10) (not $shardAware) }}
{{- fail (printf "enterprise.enabled with %d gateways: enterprise mode refuses to start past 10 unless the traffic in front of them is shard-aware. Keep cluster.gateways.minReplicas at 10 or fewer, or, if your router uses /v1/cluster/ingress-route/{id}, set worker.extraEnv.SB_CLUSTER_SHARD_AWARE_INGRESS=\"true\" (it reaches every node)." (int $gateways)) }}
{{- end }}
{{- $endpoints := dict "audit.witness.endpoint" $w.endpoint }}
{{- if eq $backend "s3" }}{{ $_ := set $endpoints "audit.export.s3.endpoint" $xs3.endpoint }}{{ end }}
{{- if eq $backend "webhook" }}{{ $_ := set $endpoints "audit.export.webhook.url" $hook.url }}{{ end }}
{{- range $what, $endpoint := $endpoints }}
{{- if and $endpoint (not (hasPrefix "https://" (lower (toString $endpoint)))) }}
{{- fail (printf "%s %s must be https in enterprise mode: every node refuses to start otherwise." $what $endpoint) }}
{{- end }}
{{- end }}
{{- end }}
{{- if not (has $backend (list "" "s3" "webhook")) }}
{{- fail (printf "audit.export.backend %q: the chart sets s3 or webhook (or leave it empty)." $backend) }}
{{- end }}
{{- if and (eq $backend "s3") (not $xs3.bucket) }}
{{- fail "audit.export.backend s3 needs audit.export.s3.bucket." }}
{{- end }}
{{- if and (eq $backend "webhook") (not $hook.url) }}
{{- fail "audit.export.backend webhook needs audit.export.webhook.url." }}
{{- end }}
{{- if and (eq $backend "webhook") $enterprise (not $hook.bearerTokenSecret) }}
{{- fail "audit.export.webhook in enterprise mode needs bearerTokenSecret: every node refuses an unauthenticated collector." }}
{{- end }}
{{- $keys := list }}
{{- if $enterprise }}
{{- $keys = concat $keys (list "SB_PAT_SCOPE" "SB_PUBLIC_API_SOCKET" "SB_PUBLIC_API_SOCKET_GROUP" "SB_PAT_LOCAL_LISTEN") }}
{{- end }}
{{- if $creds.existingSecret }}
{{- $keys = concat $keys (list "AWS_ACCESS_KEY_ID" "AWS_SECRET_ACCESS_KEY") }}
{{- end }}
{{- if $ca.existingConfigMap }}
{{- $keys = append $keys "AWS_CA_BUNDLE" }}
{{- end }}
{{- if $w.bucket }}
{{- $keys = concat $keys (list "SB_AUDIT_WITNESS_BACKEND" "SB_AUDIT_WITNESS_S3_BUCKET" "SB_AUDIT_WITNESS_S3_PREFIX" "SB_AUDIT_WITNESS_S3_REGION" "SB_AUDIT_WITNESS_S3_ENDPOINT" "SB_AUDIT_WITNESS_S3_PATH_STYLE") }}
{{- end }}
{{- if $backend }}
{{- $keys = concat $keys (list "SB_AUDIT_EXPORT_BACKEND" "SB_AUDIT_EXPORT_S3_BUCKET" "SB_AUDIT_EXPORT_S3_PREFIX" "SB_AUDIT_EXPORT_S3_REGION" "SB_AUDIT_EXPORT_S3_ENDPOINT" "SB_AUDIT_EXPORT_S3_PATH_STYLE" "SB_SECRET_AUDIT_EXPORT_URL" "SB_SECRET_AUDIT_EXPORT_BEARER_TOKEN") }}
{{- end }}
{{- range $k := $keys }}
{{- if hasKey ($.Values.worker.extraEnv | default dict) $k }}
{{- fail (printf "%s is set twice: the chart sets it from enterprise and audit; remove worker.extraEnv.%s." $k $k) }}
{{- end }}
{{- end }}
{{- if $enterprise }}
# The admin token works only from this pod itself and the cluster's own
# nodes: the edge reaches sandboxd on the public socket, where it is
# refused, and the operator calls with an API token of its own.
- { name: SB_PAT_SCOPE, value: host }
- { name: SB_PUBLIC_API_SOCKET, value: {{ include "aerolvm.publicSocket" . | quote }} }
# The edge's group: a number, which the image names no group for.
- { name: SB_PUBLIC_API_SOCKET_GROUP, value: "65532" }
# The admin token works on this loopback listener only, never on the API
# port: a mesh sidecar would deliver outside callers there from loopback.
# The operator and `kubectl port-forward` reach it inside the pod.
- { name: SB_PAT_LOCAL_LISTEN, value: "127.0.0.1:21219" }
{{- end }}
{{- with $w.bucket }}
- { name: SB_AUDIT_WITNESS_BACKEND, value: s3 }
- { name: SB_AUDIT_WITNESS_S3_BUCKET, value: {{ . | quote }} }
{{- with $w.prefix }}
- { name: SB_AUDIT_WITNESS_S3_PREFIX, value: {{ . | quote }} }
{{- end }}
{{- with $w.region }}
- { name: SB_AUDIT_WITNESS_S3_REGION, value: {{ . | quote }} }
{{- end }}
{{- with $w.endpoint }}
- { name: SB_AUDIT_WITNESS_S3_ENDPOINT, value: {{ . | quote }} }
{{- end }}
{{- if $w.pathStyle }}
- { name: SB_AUDIT_WITNESS_S3_PATH_STYLE, value: "true" }
{{- end }}
{{- end }}
{{- if eq $backend "s3" }}
- { name: SB_AUDIT_EXPORT_BACKEND, value: s3 }
- { name: SB_AUDIT_EXPORT_S3_BUCKET, value: {{ $xs3.bucket | quote }} }
{{- with $xs3.prefix }}
- { name: SB_AUDIT_EXPORT_S3_PREFIX, value: {{ . | quote }} }
{{- end }}
{{- with $xs3.region }}
- { name: SB_AUDIT_EXPORT_S3_REGION, value: {{ . | quote }} }
{{- end }}
{{- with $xs3.endpoint }}
- { name: SB_AUDIT_EXPORT_S3_ENDPOINT, value: {{ . | quote }} }
{{- end }}
{{- if $xs3.pathStyle }}
- { name: SB_AUDIT_EXPORT_S3_PATH_STYLE, value: "true" }
{{- end }}
{{- else if eq $backend "webhook" }}
- { name: SB_AUDIT_EXPORT_BACKEND, value: webhook }
- { name: SB_SECRET_AUDIT_EXPORT_URL, value: {{ $hook.url | quote }} }
{{- with $hook.bearerTokenSecret }}
- name: SB_SECRET_AUDIT_EXPORT_BEARER_TOKEN
  valueFrom:
    secretKeyRef: { name: {{ . | quote }}, key: {{ $hook.bearerTokenKey | default "token" | quote }} }
{{- end }}
{{- end }}
{{- with $creds.existingSecret }}
- name: AWS_ACCESS_KEY_ID
  valueFrom:
    secretKeyRef: { name: {{ . | quote }}, key: AWS_ACCESS_KEY_ID }
- name: AWS_SECRET_ACCESS_KEY
  valueFrom:
    secretKeyRef: { name: {{ . | quote }}, key: AWS_SECRET_ACCESS_KEY }
{{- end }}
{{- with $ca.existingConfigMap }}
- { name: AWS_CA_BUNDLE, value: {{ printf "/etc/aerolvm/aws-ca/%s" ($ca.key | default "ca.crt") | quote }} }
{{- end }}
{{- end -}}

{{- /* The public socket's folder (enterprise mode), for sandboxd and the edge. */ -}}
{{- define "aerolvm.publicSocketMount" -}}
{{- if (.Values.enterprise | default dict).enabled }}
- { name: public-api, mountPath: {{ include "aerolvm.publicSocketDir" . }} }
{{- end }}
{{- end -}}

{{- define "aerolvm.auditMount" -}}
{{- include "aerolvm.publicSocketMount" . }}
{{- with ((.Values.audit | default dict).credentials | default dict).caBundle }}
{{- if .existingConfigMap }}
- { name: aws-ca, mountPath: /etc/aerolvm/aws-ca, readOnly: true }
{{- end }}
{{- end }}
{{- end -}}

{{- define "aerolvm.auditVolume" -}}
{{- if (.Values.enterprise | default dict).enabled }}
- { name: public-api, emptyDir: {} }
{{- end }}
{{- with ((.Values.audit | default dict).credentials | default dict).caBundle }}
{{- if .existingConfigMap }}
- name: aws-ca
  configMap:
    name: {{ .existingConfigMap }}
{{- end }}
{{- end }}
{{- end -}}

{{- /* The node service account (audit.credentials.serviceAccount), when the
chart makes one. */ -}}
{{- define "aerolvm.nodeServiceAccountName" -}}
{{- $sa := ((.Values.audit | default dict).credentials | default dict).serviceAccount | default dict }}
{{- if $sa.create }}{{ include "aerolvm.nodeServiceAccount" . }}{{ end }}
{{- end -}}

{{/*
The annotations of a node pod, if any (callers trim the result and leave
the annotations key out when it is empty). In enterprise mode, no service
mesh sidecar (review S3): a sidecar delivers outside callers to sandboxd
from loopback, where they would count as the pod itself, and its own mTLS
would sit between nodes that already speak mTLS. Off, the pods are as
before. With IRSA (audit.credentials.serviceAccount), the audit store's
role reaches the agent container only (review S4).
*/}}
{{- define "aerolvm.nodePodAnnotations" -}}
{{- $sa := ((.root.Values.audit | default dict).credentials | default dict).serviceAccount | default dict }}
{{- if (.root.Values.enterprise | default dict).enabled }}
sidecar.istio.io/inject: "false"
linkerd.io/inject: disabled
{{- end }}
{{- if $sa.create }}
eks.amazonaws.com/skip-containers: {{ get (dict "server" "setup" "gateway" "edge,setup" "worker" "runtime,edge,egress,preflight,setup") .role | quote }}
{{- end }}
{{- end -}}
