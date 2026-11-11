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

{{- define "aerolvm.image" -}}
{{- $tag := .root.Values.image.tag | default .root.Chart.AppVersion -}}
{{- printf "%s/%s:%s" .root.Values.image.registry .name $tag -}}
{{- end -}}

{{- define "aerolvm.edgeTLSSecret" -}}
{{- .Values.edge.existingTLSSecret | default (printf "%s-edge-tls" (include "aerolvm.name" .)) -}}
{{- end -}}

{{- define "aerolvm.tokenSecret" -}}
{{- .Values.apiToken.existingSecret | default (printf "%s-api-token" (include "aerolvm.name" .)) -}}
{{- end -}}
