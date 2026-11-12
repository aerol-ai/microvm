package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Roles of an AerolNode.
const (
	RoleServer  = "server"
	RoleGateway = "gateway"
	RoleWorker  = "worker"
)

// States of an AerolNode (plans/kubernetes-v2-architecture.md §10.2).
const (
	StatePending         = "Pending"         // the operator made the pod
	StateJoining         = "Joining"         // machine found, pod starting, joining
	StateServing         = "Serving"         // joined, ready
	StateRestarting      = "Restarting"      // agent swapped in place
	StateDraining        = "Draining"        // cordoned, no new sandboxes
	StateDecommissioning = "Decommissioning" // moving what is left
	StateRemoved         = "Removed"         // nothing left; pod and node gone
	StateSuspect         = "Suspect"         // gossip lost it
	StateDead            = "Dead"            // past the grace; failover runs
	StateMaintenance     = "Maintenance"     // a server held for backup/restore/recover-quorum (C22)
	StateFailed          = "Failed"          // cannot start; Reason says why
)

// Annotations people and the operator set.
const (
	// AnnotationMaintenance on a server's AerolNode recreates its pod with
	// a holding entrypoint and its volume, for `sandboxd backup`, `restore`
	// and `recover-quorum` (C22).
	AnnotationMaintenance = "aerolvm.io/maintenance"
	// AnnotationDecommission on a worker's AerolNode starts its
	// decommission; the operator sets it on scale-down, a cordoned machine
	// or a drifted NodeClaim.
	AnnotationDecommission = "aerolvm.io/decommission"
	// AnnotationForceDelete on a worker pod lets a person delete it past
	// the delete guard (C26); the delete is audited.
	AnnotationForceDelete = "aerolvm.io/force-delete"
	// AnnotationOperatorDelete marks a pod the operator itself is
	// deleting, which the delete guard always allows.
	AnnotationOperatorDelete = "aerolvm.io/operator-delete"
)

// AerolNodeSpec says what the node is. The operator writes it once.
type AerolNodeSpec struct {
	// Cluster is the AerolCluster's name.
	Cluster string `json:"cluster"`
	// +kubebuilder:validation:Enum=server;gateway;worker
	Role string `json:"role"`
	// Pool is the worker pool, for workers.
	// +optional
	Pool string `json:"pool,omitempty"`
	// Zone is where the operator pins the pod (§11).
	Zone string `json:"zone"`
}

// DecommissionStatus is a worker's decommission so far (C9).
type DecommissionStatus struct {
	StartedAt metav1.Time `json:"startedAt"`
	// DrainUntil ends the drain window; the moves start then.
	DrainUntil metav1.Time `json:"drainUntil"`
	// Deadline is when what could not move is stopped.
	Deadline metav1.Time `json:"deadline"`
	// Moved counts the sandboxes moved to other workers.
	Moved int32 `json:"moved"`
	// Remaining counts the sandboxes still placed on the node.
	Remaining int32 `json:"remaining"`
	// NodeDeleted is set once the node left the AerolVM cluster.
	// +optional
	NodeDeleted bool `json:"nodeDeleted,omitempty"`
}

// AerolNodeStatus is what the operator saw last. Counters are written at
// most once a minute (G4).
type AerolNodeStatus struct {
	// +optional
	State string `json:"state,omitempty"`
	// Reason explains the state, such as why a worker never became ready.
	// +optional
	Reason string `json:"reason,omitempty"`
	// PodName is the node's pod.
	// +optional
	PodName string `json:"podName,omitempty"`
	// NodeName is the Kubernetes Node the pod runs on.
	// +optional
	NodeName string `json:"nodeName,omitempty"`
	// Version is the sandboxd build the node reports.
	// +optional
	Version string `json:"version,omitempty"`
	// Sandboxes is how many sandboxes run on it.
	// +optional
	Sandboxes int32 `json:"sandboxes,omitempty"`
	// FreeCPU and FreeMemory are its room for new sandboxes.
	// +optional
	FreeCPU string `json:"freeCPU,omitempty"`
	// +optional
	FreeMemory string `json:"freeMemory,omitempty"`
	// AgentImage is the agent container's image the operator last set,
	// and AgentImageID the image ID the kubelet reported for it: a swap is
	// confirmed only when the ID changes (eng review SC-1).
	// +optional
	AgentImage string `json:"agentImage,omitempty"`
	// +optional
	AgentImageID string `json:"agentImageID,omitempty"`
	// +optional
	Decommission *DecommissionStatus `json:"decommission,omitempty"`
	// LastUpdated is when the counters were last written.
	// +optional
	LastUpdated metav1.Time `json:"lastUpdated,omitempty"`
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// AerolNode is one server, gateway or worker. Only the operator writes it.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=an
// +kubebuilder:printcolumn:name="Role",type=string,JSONPath=`.spec.role`
// +kubebuilder:printcolumn:name="Zone",type=string,JSONPath=`.spec.zone`
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.status.version`
// +kubebuilder:printcolumn:name="Sandboxes",type=integer,JSONPath=`.status.sandboxes`
// +kubebuilder:printcolumn:name="Free CPU",type=string,JSONPath=`.status.freeCPU`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type AerolNode struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AerolNodeSpec   `json:"spec,omitempty"`
	Status AerolNodeStatus `json:"status,omitempty"`
}

// AerolNodeList is a list of AerolNodes.
//
// +kubebuilder:object:root=true
type AerolNodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AerolNode `json:"items"`
}
