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
