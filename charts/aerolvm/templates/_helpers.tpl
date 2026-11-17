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
