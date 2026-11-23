{{- /*
Privilege mode (plans/security-gaps-m1-m4.md M1, eng review D5 and D22): the
chart value privilegeMode, rendered into the worker as SB_PRIVILEGE_MODE.

  single  the agent container (sandboxd) is privileged and does its root
          work itself. The default, and every worker made before the value.
  split   the agent runs with no rights; the root helper, aerolvm-rootd,
          does the root work in the runtime container (_workerpod.tpl).
  auto    a new install gets split, unless a value below needs single; an
          upgrade keeps the mode its worker template has now (D22). Making
          auto the default later is the one line in values.yaml that says
          privilegeMode: single today.

A pod takes its mode when it is made. A chart upgrade changes the template;
running workers keep the mode they started with until the operator
replaces them (decommission), node by node. A worker made before this
value has no SB_PRIVILEGE_MODE, so an agent upgraded in place onto it runs
single, as before (D5).
*/ -}}

{{- /* aerolvm.privilegeMode is the mode the worker template renders:
"single" or "split". It refuses a value it does not know, and split with
any value split cannot run yet (aerolvm.splitGaps). */ -}}
{{- define "aerolvm.privilegeMode" -}}
{{- $mode := .Values.privilegeMode | default "single" | toString | trim -}}
{{- if not (has $mode (list "single" "split" "auto")) -}}
{{- fail (printf "privilegeMode is single, split or auto, got %q" $mode) -}}
{{- end -}}
{{- if hasKey (.Values.worker.extraEnv | default dict) "SB_PRIVILEGE_MODE" -}}
{{- fail "worker.extraEnv.SB_PRIVILEGE_MODE: set privilegeMode instead. The worker pod's shape follows it, and a split agent in a single pod has no root helper to talk to." -}}
{{- end -}}
{{- $gaps := include "aerolvm.splitGaps" . | trim -}}
{{- if eq $mode "auto" -}}
{{- $mode = include "aerolvm.autoPrivilegeMode" (dict "root" . "gaps" $gaps) -}}
{{- end -}}
{{- if and (eq $mode "split") $gaps -}}
{{- fail (printf "privilegeMode split cannot run with these values yet:\n%s\nChange them, or keep privilegeMode single." $gaps) -}}
{{- end -}}
{{- $mode -}}
{{- end -}}

{{- /* aerolvm.autoPrivilegeMode resolves auto. An upgrade keeps what the
worker template says now; an upgrade whose template cannot be read (helm
upgrade --dry-run=client) keeps single, the mode of every install made
before this value. A new install gets split unless a value needs single.
helm template cannot read the cluster, so it renders auto as a new install:
GitOps tools that render with helm template should set the mode, not auto. */ -}}
{{- define "aerolvm.autoPrivilegeMode" -}}
{{- $previous := include "aerolvm.previousPrivilegeMode" .root -}}
{{- if $previous -}}
{{- $previous -}}
{{- else if or .root.Release.IsUpgrade .gaps -}}
single
{{- else -}}
split
{{- end -}}
{{- end -}}

{{- /* aerolvm.previousPrivilegeMode is the mode of the worker template this
release has in the cluster now, or "" when there is none to read: the
single-mode StatefulSet's agent, or cluster mode's pod-templates
ConfigMap, whichever exists. A template with no SB_PRIVILEGE_MODE is
single. */ -}}
{{- define "aerolvm.previousPrivilegeMode" -}}
{{- $name := include "aerolvm.name" . -}}
{{- $mode := "" -}}
{{- with lookup "apps/v1" "StatefulSet" .Release.Namespace $name -}}
{{- $mode = "single" -}}
{{- range ((((.spec | default dict).template | default dict).spec | default dict).containers | default list) -}}
{{- if eq .name "agent" -}}
{{- range (.env | default list) -}}
{{- if and (eq .name "SB_PRIVILEGE_MODE") (eq (toString .value) "split") -}}
{{- $mode = "split" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- with lookup "v1" "ConfigMap" .Release.Namespace (printf "%s-pod-templates" $name) -}}
{{- with (.data | default dict).worker -}}
{{- $mode = ternary "split" "single" (contains "{ name: SB_PRIVILEGE_MODE, value: split }" .) -}}
{{- end -}}
{{- end -}}
{{- $mode -}}
{{- end -}}

{{- /* aerolvm.splitGaps lists the values split cannot run with yet, one
line each, naming the value and what to change; empty when split can run.

The daemon's: each is a setting pkg/daemon/privilege_mode.go refuses at
start in split (checkPrivilegeMode), so a bad combination fails at helm
install, not as a pod that restarts forever. The Kubernetes ones are worker
pod wiring this chart does not have yet. pkg/daemon's
TestChartRefusesWhatSplitRefuses keeps this list and the daemon's in step. */ -}}
{{- define "aerolvm.splitGaps" -}}
{{- $w := .Values.worker -}}
{{- $env := $w.extraEnv | default dict -}}
{{- /* strconv.ParseBool's words, which sandboxd reads switches with. */ -}}
{{- $true := list "1" "t" "T" "TRUE" "true" "True" -}}
{{- $false := list "0" "f" "F" "FALSE" "false" "False" -}}
{{- /* Firecracker: sandboxd runs it in split, except with the VM pool
(privmode's firecracker_warm_pool step), but this chart does not wire it
into a split worker pod yet, and no live run has proven it there. */}}
{{- if $w.firecracker.enabled }}
- worker.firecracker.enabled is true: this chart does not run Firecracker in a split worker pod yet. Set it to false.
{{- end }}
{{- /* gVisor moves, and the containerd warm pool that
cluster.agentSandboxAPI's warm pools park in, are the root helper's from
M1 PR 13: no refusal. */}}
{{- if $w.wasm.enabled }}
- worker.wasm.enabled is true: this chart does not wire WASM sandboxes into a split worker pod yet. Set it to false.
{{- end }}
{{- if $w.isolate.enabled }}
- worker.isolate.enabled is true: this chart does not wire V8-isolate sandboxes into a split worker pod yet. Set it to false.
{{- end }}
{{- range $k := list "SB_ENABLE_FIRECRACKER" "SB_ENABLE_WASM" "SB_ENABLE_ISOLATE" }}
{{- if and (hasKey $env $k) (has (index $env $k | toString | trim) $true) }}
- worker.extraEnv.{{ $k }} turns on what split does not run yet. Remove it.
{{- end }}
{{- end }}
{{- range $k := list "SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED" "SB_CONTAINERD_BUILDKIT_ROOTLESS" }}
{{- if and (hasKey $env $k) (has (index $env $k | toString | trim) $false) }}
- worker.extraEnv.{{ $k }} is false: split needs it on. Remove it.
{{- end }}
{{- end }}
{{- if and (hasKey $env "SB_CONTAINER_ENGINE") (ne (index $env "SB_CONTAINER_ENGINE" | toString | trim | lower) "containerd") }}
- worker.extraEnv.SB_CONTAINER_ENGINE names another engine: split runs the containerd engine only. Remove it.
{{- end }}
{{- /* The helper's move limits are the one exception: the chart does not
set them, and worker.extraEnv reaches the helper's container too. */}}
{{- range $k, $_ := $env }}
{{- if and (or (hasPrefix "SB_ROOTD_" $k) (eq $k "SB_MOUNTS_CRED_DIR")) (not (has $k (list "SB_ROOTD_MOVE_MAX_BYTES" "SB_ROOTD_MOVE_MAX_STAGED"))) }}
- worker.extraEnv.{{ $k }}: the chart sets it in split, where the agent and the root helper share folders. Remove it.
{{- end }}
{{- end }}
{{- end -}}

{{- /* aerolvm.privilegeModeNotes is NOTES.txt's part: the mode a split or
auto install runs, and what to do after an upgrade that changed it. The
worker template still in the cluster while helm upgrade renders the notes
is the previous release's (aerolvm.previousPrivilegeMode). A single install
that stays single gets no line. */ -}}
{{- define "aerolvm.privilegeModeNotes" -}}
{{- $mode := include "aerolvm.privilegeMode" . -}}
{{- $previous := "" -}}
{{- if .Release.IsUpgrade }}{{ $previous = include "aerolvm.previousPrivilegeMode" . }}{{ end -}}
{{- if and (eq (toString .Values.privilegeMode) "auto") (eq $mode "single") (not .Release.IsUpgrade) }}

privilegeMode auto chose single, because split cannot run with these values yet:
{{ include "aerolvm.splitGaps" . | trim | indent 2 }}
{{- end }}
{{- if eq $mode "split" }}

Privilege mode split: each worker's agent container runs as uid 65531 with no
rights, and a signed root helper in its runtime container does the root work.
`aerolvm k8s verify` reports each worker pool's mode.
{{- end }}
{{- if and $previous (ne $previous $mode) }}

This upgrade changed privilegeMode from {{ $previous }} to {{ $mode }}. A pod gets its
mode when it is made: running workers keep {{ $previous }}, and new ones get {{ $mode }}.
{{- if eq .Values.mode "cluster" }}
Move the workers over one at a time by replacing each worker's machine
(kubectl cordon <node>): the operator decommissions that worker first. Wait
until its replacement says Serving before the next. Workers in the two
modes run side by side meanwhile.
{{- else }}
Delete pod {{ include "aerolvm.name" . }}-0 when no sandbox is running: it is made again
in {{ $mode }} mode, and deleting it ends every sandbox on it.
{{- end }}
{{- end }}
{{- end -}}
