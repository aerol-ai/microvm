// Package kubeapi is the Kubernetes agent-sandbox API the gateways serve
// (plans/kubernetes-v2-architecture.md §16, C17): the upstream kinds of
// kubernetes-sigs/agent-sandbox, answered straight from AerolVM with
// nothing stored in etcd per sandbox.
//
// The wire types here are hand-written JSON copies of the upstream v1beta1
// types (release v1.0.11, commit 890de53a4dd18e35313173e6dc34d9559b1a9733)
// and of the few apimachinery types the API needs. The module takes no
// Kubernetes dependency for them: the shapes are small and stable, and a
// client library would pull hundreds of packages into every sandboxd.
package kubeapi

// The upstream group versions this API serves.
const (
	Group             = "agents.x-k8s.io"
	ExtensionsGroup   = "extensions.agents.x-k8s.io"
	Version           = "v1beta1"
	UpstreamRelease   = "v1.0.11"
	UpstreamCommit    = "890de53a4dd18e35313173e6dc34d9559b1a9733"
	SandboxKind       = "Sandbox"
	SandboxListKind   = "SandboxList"
	SandboxesResource = "sandboxes"
)

// Annotations AerolVM puts on what it renders.
const (
	// AnnotationSandboxID is the AerolVM sandbox ID behind an object.
	AnnotationSandboxID = "aerolvm.io/sandbox-id"
	// AnnotationName is the AerolVM name when it is not a valid
	// Kubernetes name, so the object is named by its ID instead.
	AnnotationName = "aerolvm.io/name"
	// AnnotationRuntime is the AerolVM runtime.
	AnnotationRuntime = "aerolvm.io/runtime"
)

// TypeMeta is metav1.TypeMeta.
type TypeMeta struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
}

// ObjectMeta is the subset of metav1.ObjectMeta this API sets or reads.
// Times are RFC 3339 strings, as Kubernetes writes them.
type ObjectMeta struct {
	Name              string            `json:"name,omitempty"`
	GenerateName      string            `json:"generateName,omitempty"`
	Namespace         string            `json:"namespace,omitempty"`
	UID               string            `json:"uid,omitempty"`
	ResourceVersion   string            `json:"resourceVersion,omitempty"`
	Generation        int64             `json:"generation,omitempty"`
	CreationTimestamp string            `json:"creationTimestamp,omitempty"`
	DeletionTimestamp string            `json:"deletionTimestamp,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
}

// ListMeta is metav1.ListMeta.
type ListMeta struct {
	ResourceVersion    string `json:"resourceVersion,omitempty"`
	Continue           string `json:"continue,omitempty"`
	RemainingItemCount *int64 `json:"remainingItemCount,omitempty"`
}

// Condition is metav1.Condition.
type Condition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	ObservedGeneration int64  `json:"observedGeneration,omitempty"`
	LastTransitionTime string `json:"lastTransitionTime"`
	Reason             string `json:"reason"`
	Message            string `json:"message"`
}

// EnvVar is the name/value subset of corev1.EnvVar this API accepts.
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

// ResourceRequirements is corev1.ResourceRequirements for cpu and memory.
type ResourceRequirements struct {
	Limits   map[string]string `json:"limits,omitempty"`
	Requests map[string]string `json:"requests,omitempty"`
}

// Container is the subset of corev1.Container this API accepts and shows.
type Container struct {
	Name      string                `json:"name"`
	Image     string                `json:"image,omitempty"`
	Command   []string              `json:"command,omitempty"`
	Args      []string              `json:"args,omitempty"`
	Env       []EnvVar              `json:"env,omitempty"`
	Resources *ResourceRequirements `json:"resources,omitempty"`
}

// PodSpec is the subset of corev1.PodSpec this API accepts and shows.
type PodSpec struct {
	Containers       []Container `json:"containers"`
	RuntimeClassName string      `json:"runtimeClassName,omitempty"`
}

// PodMetadata is the upstream PodMetadata.
type PodMetadata struct {
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// PodTemplate is the upstream PodTemplate.
type PodTemplate struct {
	Spec     PodSpec     `json:"spec"`
	Metadata PodMetadata `json:"metadata"`
}

// Upstream enum values.
const (
	OperatingModeRunning   = "Running"
	OperatingModeSuspended = "Suspended"
	ShutdownPolicyDelete   = "Delete"
	ShutdownPolicyRetain   = "Retain"

	ConditionReady     = "Ready"
	ConditionSuspended = "Suspended"
	ConditionFinished  = "Finished"

	ReasonDependenciesReady = "DependenciesReady"
	ReasonSandboxSuspended  = "SandboxSuspended"
	ReasonPodTerminated     = "PodTerminated"
	ReasonNotSuspended      = "NotSuspended"
	ReasonPodFailed         = "PodFailed"
	ReasonPodTerminating    = "PodTerminating"
)

// SandboxSpec is the upstream SandboxSpec: the blueprint and lifecycle
// inlined, as upstream does.
type SandboxSpec struct {
	PodTemplate     PodTemplate `json:"podTemplate"`
	ShutdownTime    string      `json:"shutdownTime,omitempty"`
	ShutdownPolicy  string      `json:"shutdownPolicy,omitempty"`
	OperatingMode   string      `json:"operatingMode,omitempty"`
	Service         *bool       `json:"service,omitempty"`
	FailedPodPolicy string      `json:"failedPodPolicy,omitempty"`
}

// SandboxStatus is the upstream SandboxStatus, without the Pod-only fields
// AerolVM has nothing for (service, selector, pod IPs).
type SandboxStatus struct {
	Conditions []Condition `json:"conditions,omitempty"`
	NodeName   string      `json:"nodeName,omitempty"`
}

// Sandbox is agents.x-k8s.io/v1beta1 Sandbox.
type Sandbox struct {
	TypeMeta `json:",inline"`
	Metadata ObjectMeta    `json:"metadata"`
	Spec     SandboxSpec   `json:"spec"`
	Status   SandboxStatus `json:"status,omitempty"`
}

// SandboxList is agents.x-k8s.io/v1beta1 SandboxList.
type SandboxList struct {
	TypeMeta `json:",inline"`
	Metadata ListMeta  `json:"metadata"`
	Items    []Sandbox `json:"items"`
}

// Status is metav1.Status, the body of every error answer.
type Status struct {
	TypeMeta `json:",inline"`
	Metadata ListMeta `json:"metadata"`
	Status   string   `json:"status"`
	Message  string   `json:"message"`
	Reason   string   `json:"reason"`
	Code     int      `json:"code"`
}

// WatchEvent is metav1.WatchEvent.
type WatchEvent struct {
	Type   string `json:"type"`
	Object any    `json:"object"`
}

// APIResource and APIResourceList are the discovery documents.
type APIResource struct {
	Name         string   `json:"name"`
	SingularName string   `json:"singularName"`
	Namespaced   bool     `json:"namespaced"`
	Kind         string   `json:"kind"`
	Verbs        []string `json:"verbs"`
	ShortNames   []string `json:"shortNames,omitempty"`
	Categories   []string `json:"categories,omitempty"`
}

type APIResourceList struct {
	TypeMeta     `json:",inline"`
	GroupVersion string        `json:"groupVersion"`
	APIResources []APIResource `json:"resources"`
}

// GroupVersion is apiVersion for the core kinds.
func GroupVersion() string { return Group + "/" + Version }
