{{- define "agentd.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}{{ .Release.Name | trunc 50 | trimSuffix "-" }}{{- else -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 50 | trimSuffix "-" }}{{- end -}}
{{- end -}}

{{- define "agentd.labels" -}}
app.kubernetes.io/name: agentd
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "agentd.image" -}}
{{- $ := index . 0 -}}{{- $component := index . 1 -}}
{{ printf "%s/%s/%s:%s" $.Values.image.registry $.Values.image.repository $component (default $.Chart.AppVersion $.Values.image.tag) }}
{{- end -}}

{{/* Reuse a generated value from an existing Secret so upgrades keep it. */}}
{{- define "agentd.keep" -}}
{{- $ := index . 0 -}}{{- $secret := index . 1 -}}{{- $key := index . 2 -}}{{- $gen := index . 3 -}}
{{- $existing := lookup "v1" "Secret" $.Release.Namespace $secret -}}
{{- if and $existing (index $existing.data $key) -}}{{ index $existing.data $key | b64dec }}{{- else -}}{{ $gen }}{{- end -}}
{{- end -}}

{{- define "agentd.serverSecret" -}}{{ default (printf "%s-agentserver" (include "agentd.fullname" .)) .Values.agentserver.existingSecret }}{{- end -}}
{{- define "agentd.serverSvc" -}}{{ include "agentd.fullname" . }}-agentserver{{- end -}}
{{- define "agentd.serverHost" -}}{{ include "agentd.serverSvc" . }}.{{ .Release.Namespace }}.svc{{- end -}}
