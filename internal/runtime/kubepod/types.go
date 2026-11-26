package kubepod

import "time"

// The few Kubernetes pod fields the driver writes or reads. The driver
// only creates and deletes pods; it never sends back a pod it read, so a
// field missing here is never lost on the server (there is no
// read-modify-write). Optional booleans are pointers because false must be
// sent: automountServiceAccountToken left out means true.

// Pod is a core/v1 Pod.
type Pod struct {
	APIVersion string     `json:"apiVersion,omitempty"`
	Kind       string     `json:"kind,omitempty"`
	Metadata   ObjectMeta `json:"metadata"`
	Spec       PodSpec    `json:"spec"`
	Status     *PodStatus `json:"status,omitempty"`
}

// ObjectMeta is the part of metav1.ObjectMeta the driver uses.
type ObjectMeta struct {
	Name              string            `json:"name,omitempty"`
	Namespace         string            `json:"namespace,omitempty"`
	UID               string            `json:"uid,omitempty"`
	ResourceVersion   string            `json:"resourceVersion,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
	DeletionTimestamp *time.Time        `json:"deletionTimestamp,omitempty"`
}

// PodSpec is the part of core/v1 PodSpec the driver sets.
type PodSpec struct {
	RuntimeClassName              string              `json:"runtimeClassName,omitempty"`
	RestartPolicy                 string              `json:"restartPolicy,omitempty"`
	AutomountServiceAccountToken  *bool               `json:"automountServiceAccountToken,omitempty"`
	EnableServiceLinks            *bool               `json:"enableServiceLinks,omitempty"`
	TerminationGracePeriodSeconds *int64              `json:"terminationGracePeriodSeconds,omitempty"`
	SecurityContext               *PodSecurityContext `json:"securityContext,omitempty"`
	InitContainers                []Container         `json:"initContainers,omitempty"`
	Containers                    []Container         `json:"containers"`
	Volumes                       []Volume            `json:"volumes,omitempty"`
	NodeName                      string              `json:"nodeName,omitempty"`
}

// PodSecurityContext is the pod-wide security settings.
type PodSecurityContext struct {
	SeccompProfile *SeccompProfile `json:"seccompProfile,omitempty"`
}

// SeccompProfile names a seccomp profile.
type SeccompProfile struct {
	Type string `json:"type"`
}

// Container is the part of core/v1 Container the driver sets.
type Container struct {
	Name            string           `json:"name"`
	Image           string           `json:"image"`
	Command         []string         `json:"command,omitempty"`
	Args            []string         `json:"args,omitempty"`
	Env             []EnvVar         `json:"env,omitempty"`
	Resources       *Resources       `json:"resources,omitempty"`
	VolumeMounts    []VolumeMount    `json:"volumeMounts,omitempty"`
	SecurityContext *SecurityContext `json:"securityContext,omitempty"`
}

// EnvVar is a plain name and value. The driver never puts a secret in one.
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Resources holds requests and limits as Kubernetes quantity strings.
type Resources struct {
	Requests map[string]string `json:"requests,omitempty"`
	Limits   map[string]string `json:"limits,omitempty"`
}

// VolumeMount mounts a pod volume into a container.
type VolumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
}

// SecurityContext is one container's security settings.
type SecurityContext struct {
	Privileged               *bool         `json:"privileged,omitempty"`
	AllowPrivilegeEscalation *bool         `json:"allowPrivilegeEscalation,omitempty"`
	Capabilities             *Capabilities `json:"capabilities,omitempty"`
	RunAsNonRoot             *bool         `json:"runAsNonRoot,omitempty"`
	RunAsUser                *int64        `json:"runAsUser,omitempty"`
	RunAsGroup               *int64        `json:"runAsGroup,omitempty"`
	ReadOnlyRootFilesystem   *bool         `json:"readOnlyRootFilesystem,omitempty"`
}

// Capabilities adds and drops Linux capabilities.
type Capabilities struct {
	Add  []string `json:"add,omitempty"`
	Drop []string `json:"drop,omitempty"`
}

// Volume is a pod volume. Sandbox pods use only emptyDir: never a host path.
type Volume struct {
	Name     string    `json:"name"`
	EmptyDir *EmptyDir `json:"emptyDir,omitempty"`
}

// EmptyDir is a volume that lives and dies with the pod.
type EmptyDir struct {
	SizeLimit string `json:"sizeLimit,omitempty"`
}

// PodStatus is the part of core/v1 PodStatus the driver reads.
type PodStatus struct {
	Phase                 string            `json:"phase,omitempty"`
	Reason                string            `json:"reason,omitempty"`
	Message               string            `json:"message,omitempty"`
	PodIP                 string            `json:"podIP,omitempty"`
	Conditions            []PodCondition    `json:"conditions,omitempty"`
	InitContainerStatuses []ContainerStatus `json:"initContainerStatuses,omitempty"`
	ContainerStatuses     []ContainerStatus `json:"containerStatuses,omitempty"`
}

// PodCondition is one of a pod's conditions, such as PodScheduled.
type PodCondition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// ContainerStatus is one container's state as the kubelet reports it.
type ContainerStatus struct {
	Name  string         `json:"name"`
	State ContainerState `json:"state"`
}

// ContainerState holds at most one of its three states.
type ContainerState struct {
	Waiting    *StateWaiting    `json:"waiting,omitempty"`
	Running    *StateRunning    `json:"running,omitempty"`
	Terminated *StateTerminated `json:"terminated,omitempty"`
}

// StateWaiting is a container not running yet.
type StateWaiting struct {
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// StateRunning is a running container.
type StateRunning struct {
	StartedAt *time.Time `json:"startedAt,omitempty"`
}

// StateTerminated is a container that ended.
type StateTerminated struct {
	ExitCode int32  `json:"exitCode"`
	Reason   string `json:"reason,omitempty"`
	Message  string `json:"message,omitempty"`
}

// Pod phases (core/v1 PodPhase).
const (
	PhasePending   = "Pending"
	PhaseRunning   = "Running"
	PhaseSucceeded = "Succeeded"
	PhaseFailed    = "Failed"
)

func boolPtr(b bool) *bool    { return &b }
func int64Ptr(n int64) *int64 { return &n }
