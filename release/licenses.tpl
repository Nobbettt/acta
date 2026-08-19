{{ range . }}
================================================================================
Component: {{ .Name }}{{ with .Version }} {{ . }}{{ end }}
License: {{ .LicenseName }}

{{ .LicenseText }}
{{ end }}
