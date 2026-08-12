{{/*
suspicious.name - chart name, used as the base of every resource name
*/}}
{{- define "suspicious.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{/*
suspicious.fullname - release-qualified base name for all resources
*/}}
{{- define "suspicious.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "suspicious.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/*
suspicious.labels - standard label block, every resource includes this
*/}}
{{- define "suspicious.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
suspicious.mysqlHost - primary DB service name, depends on architecture
*/}}
{{- define "suspicious.mysqlHost" -}}
{{- if eq .Values.mysql.architecture "replication" -}}
{{- printf "%s-mysql-primary" .Release.Name -}}
{{- else -}}
{{- printf "%s-mysql" .Release.Name -}}
{{- end -}}
{{- end -}}

{{/*
suspicious.brokerHost / suspicious.cacheHost - bitnami/redis standalone master service names
*/}}
{{- define "suspicious.brokerHost" -}}
{{- printf "%s-broker-master" .Release.Name -}}
{{- end -}}

{{- define "suspicious.cacheHost" -}}
{{- printf "%s-cache-master" .Release.Name -}}
{{- end -}}
