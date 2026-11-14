package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AerolClusterSpec is one AerolVM cell: its version, zones, servers,
// gateways and worker pools (plans/kubernetes-v2-architecture.md §10.1).
type AerolClusterSpec struct {
	// Version is the AerolVM release every node runs, such as v0.7.2. It is
	// the one place that sets the version on Kubernetes (eng review D6):
	// raising it starts an upgrade, lowering it rolls back.
	// +kubebuilder:validation:Pattern=`^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$`
	Version string `json:"version"`

	// Cell is this cluster's number, 1 to 255. It goes into every new
	// sandbox ID (C12), so it never changes after the cluster starts.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=255
	// +kubebuilder:default=1
	// +optional
	Cell int32 `json:"cell,omitempty"`

	// Zones the cluster spreads over, such as [eu-west-1a, eu-west-1b,
	// eu-west-1c]. Servers go one per zone; gateways and workers spread
	// across them.
	// +kubebuilder:validation:MinItems=1
	Zones []string `json:"zones"`

	// Images says where the images come from.
	// +optional
	Images ImageSpec `json:"images,omitempty"`

	// Servers are the Raft servers: three or five, one zone each.
	Servers ServerSpec `json:"servers"`

	// Gateways serve the API, sandbox links, SSH and TLS ports (C11).
	Gateways GatewaySpec `json:"gateways"`

	// WorkerPools run the sandboxes, one worker pod per machine.
	// +kubebuilder:validation:MinItems=1
	WorkerPools []WorkerPoolSpec `json:"workerPools"`

	// Edge is the sandbox-link domain and its certificate (C25).
	// +optional
	Edge EdgeSpec `json:"edge,omitempty"`

	// Security holds node identity and secret settings.
	// +optional
	Security SecuritySpec `json:"security,omitempty"`

	// Federation makes this cell one of several (C16): each new sandbox
	// ID carries its cell, hidden by a key the cells share, and a request
	// for another cell's sandbox is answered with that cell's address,
	// which the SDKs follow. Set it before the first sandbox: IDs made
	// without the key are served only by the cell that made them.
	// +optional
	Federation *FederationSpec `json:"federation,omitempty"`
}

// FederationSpec is this cell's place among the others.
type FederationSpec struct {
	// IDKeySecret names a Secret in this namespace whose key "key" holds
	// the federation's ID key (SB_CELL_ID_KEY): base64 of at least 32
	// random bytes (openssl rand -base64 32), the same in every cell, and
	// never changed. The operator copies it to the worker namespace.
	IDKeySecret corev1.LocalObjectReference `json:"idKeySecret"`
	// Cells is every other cell's public API address by its number, such
	// as {"2": "https://cell2.example.com"} (SB_CELL_ENDPOINTS).
	// +optional
	Cells map[string]string `json:"cells,omitempty"`
}

// ImageSpec names the image registry.
type ImageSpec struct {
	// Registry holds aerolvm, aerolvm-runtime and aerolvm-edge, tagged by
	// version. A bank's own registry mirrors them (`aerolvm release pull
	// --images`).
	// +kubebuilder:default="ghcr.io/aerol-ai"
	// +optional
	Registry string `json:"registry,omitempty"`
	// +optional
	PullPolicy corev1.PullPolicy `json:"pullPolicy,omitempty"`
	// +optional
	PullSecrets []corev1.LocalObjectReference `json:"pullSecrets,omitempty"`
}

// ServerSpec is the Raft server tier.
type ServerSpec struct {
	// Count is 3 or 5. Three survive any one zone; five survive any one
	// zone or any two servers (§11).
	// +kubebuilder:validation:Enum=3;5
	// +kubebuilder:default=3
	Count int32 `json:"count"`
	// Storage is each server's disk. It cannot move between zones, so each
	// server is pinned to its zone.
	Storage StorageSpec `json:"storage"`
	// LogStorage, when set, is a second disk for each server that holds
	// only its Raft log (sandboxd's SB_RAFT_WAL_DIR). A commit waits for a
	// log write on the leader and then on a follower, so the log's disk
	// sets the commit time; on the cell bench, a log on a disk of its own
	// brought Raft apply p99 under 25 ms at 1,354 creates a second
	// (plans/kubernetes-v2-architecture.md §9.5). A server keeps the layout
	// it was made with: setting or clearing this changes only servers made
	// after it, because a new disk laid over a log would hide it.
	// +optional
	LogStorage *StorageSpec `json:"logStorage,omitempty"`
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

// StorageSpec is one persistent volume.
type StorageSpec struct {
	// +kubebuilder:default="20Gi"
	Size resource.Quantity `json:"size"`
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`
}

// GatewaySpec is the stateless gateway tier.
type GatewaySpec struct {
	// MinReplicas is how many gateways the cluster keeps, at least one per
	// zone. Lowering it retires the surplus.
	// +kubebuilder:validation:Minimum=1
	MinReplicas int32 `json:"minReplicas"`
	// MaxReplicas caps the gateways. The operator refuses a cap below
	// minReplicas or below one per zone. Zero: no cap.
	// +optional
	MaxReplicas int32 `json:"maxReplicas,omitempty"`
	// Service is the gateways' own load balancer. Ignored with GatewayRef.
	// +optional
	Service GatewayServiceSpec `json:"service,omitempty"`
	// GatewayRef puts the gateways behind the bank's own Gateway API
	// Gateway instead of a load balancer (§7.1).
	// +optional
	GatewayRef *GatewayRef `json:"gatewayRef,omitempty"`
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

// GatewayServiceSpec shapes the gateways' Service.
type GatewayServiceSpec struct {
	// +kubebuilder:default=LoadBalancer
	// +optional
	Type corev1.ServiceType `json:"type,omitempty"`
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// GatewayRef names a Gateway API Gateway.
type GatewayRef struct {
	Name string `json:"name"`
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// WorkerPoolSpec is one kind of worker machine.
type WorkerPoolSpec struct {
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=40
	Name string `json:"name"`
	// Runtimes this pool runs: runc and gvisor today. Its workers run
	// only these, so [gvisor] never runs a sandbox on runc. Empty: what
	// the chart's worker settings allow.
	// +optional
	Runtimes []string `json:"runtimes,omitempty"`
	// NodeSelector picks the pool's machines, such as
	// {aerolvm.io/pool: gvisor-general}.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
	// Machine is the size of one machine; the worker pod asks for nearly
	// all of it (§8.1).
	Machine MachineSpec `json:"machine"`
	// MinWorkers is the floor, spread across the zones.
	// +kubebuilder:validation:Minimum=0
	MinWorkers int32 `json:"minWorkers"`
	// +kubebuilder:validation:Minimum=0
	MaxWorkers int32 `json:"maxWorkers"`
	// HeadroomPercent is how much of each zone's room is kept free; the
	// operator adds a worker when a zone has less (§10.4).
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=90
	// +optional
	HeadroomPercent int32 `json:"headroomPercent,omitempty"`
	// ZoneLossReservePercent is extra room per zone, so more of a lost
	// zone's recreate sandboxes come back quickly (RQ15).
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=90
	// +optional
	ZoneLossReservePercent int32 `json:"zoneLossReservePercent,omitempty"`
	// Images are pulled before a new worker says it is ready.
	// +optional
	Images []string `json:"images,omitempty"`
	// Provisioner says who brings machines and sets the decommission
	// deadline: karpenter, nap, eks-managed, aks-pool or none.
	// +kubebuilder:validation:Enum=karpenter;nap;eks-managed;aks-pool;none
	// +kubebuilder:default=none
	// +optional
	Provisioner string `json:"provisioner,omitempty"`
	// +optional
	Decommission DecommissionSpec `json:"decommission,omitempty"`
	// MaxMachineAge retires a worker whose machine is older, by
	// decommission: one per zone at a time, and only while no zone is
	// short of room. Worker NodePools set Karpenter's expireAfter to Never
	// (§10.6), so this is how their machines still get patched. Empty:
	// never.
	// +optional
	MaxMachineAge *metav1.Duration `json:"maxMachineAge,omitempty"`
}

// MachineSpec is one machine's size.
type MachineSpec struct {
	// +kubebuilder:validation:Minimum=1
	CPU int32 `json:"cpu"`
	// +kubebuilder:validation:Minimum=1
	MemoryGiB int32 `json:"memoryGiB"`
}

// DecommissionSpec times a worker's decommission (§10.5).
type DecommissionSpec struct {
	// DrainWindow is the time sandboxes get to end by themselves before
	// the moves start. Default 15m (5m on eks-managed pools, §10.6).
	// +optional
	DrainWindow *metav1.Duration `json:"drainWindow,omitempty"`
	// Deadline is when what could not move is stopped, counted from the
	// start. Default 45m.
	// +optional
	Deadline *metav1.Duration `json:"deadline,omitempty"`
}

// EdgeSpec is the sandbox-link domain (C25).
type EdgeSpec struct {
	// Domain is the wildcard's base: links are <id>-<port>.<domain>.
	// +optional
	Domain string `json:"domain,omitempty"`
	// IssuerRef is the cert-manager issuer of the wildcard certificate.
	// +optional
	IssuerRef *IssuerRef `json:"issuerRef,omitempty"`
	// TLSSecret holds the wildcard certificate in the AerolCluster's
	// namespace. The operator keeps a copy, its certificate and key only,
	// in the worker namespace, where worker pods mount it: a Secret volume
	// is namespaced, and a second Certificate would be a second issuance.
	// +optional
	TLSSecret string `json:"tlsSecret,omitempty"`
}

// IssuerRef names a cert-manager issuer.
type IssuerRef struct {
	// +kubebuilder:validation:Enum=Issuer;ClusterIssuer
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// SecuritySpec holds identity and secret settings.
type SecuritySpec struct {
	// ExternalCA gets every pod's node certificate from the bank's issuer
	// through cert-manager instead of a join token (R2, C23), so no CA key
	// is in the cluster. Set it before the cluster starts: once server 0
	// has started it, turning it on or off is refused. A changed issuerRef
	// applies to new nodes only, and its issuer must sign with the same CA.
	// +optional
	ExternalCA *ExternalCASpec `json:"externalCA,omitempty"`
	// CreatePolicy names a ConfigMap in this namespace whose key
	// policy.yaml is the create policy (SB_CREATE_POLICY_FILE) on every
	// node; the operator copies it to the worker namespace. While it is
	// missing, every create is refused.
	// +optional
	CreatePolicy *corev1.LocalObjectReference `json:"createPolicy,omitempty"`
}

// ExternalCASpec names the bank's issuer. It must return its CA as the
// Secret's ca.crt: that CA is every node's trust.
type ExternalCASpec struct {
	IssuerRef IssuerRef `json:"issuerRef"`
}

// AerolClusterStatus is what the operator saw last.
type AerolClusterStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Phase is Bootstrapping, Ready, Upgrading or Degraded.
	// +optional
	Phase string `json:"phase,omitempty"`
	// Version is the version every node runs, once they all agree.
	// +optional
	Version string `json:"version,omitempty"`
	// +optional
	Servers TierStatus `json:"servers,omitempty"`
	// +optional
	Gateways TierStatus `json:"gateways,omitempty"`
	// +optional
	Workers TierStatus `json:"workers,omitempty"`
	// Rollout is AerolVM's own upgrade record, when one exists.
	// +optional
	Rollout *RolloutStatus `json:"rollout,omitempty"`
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// TierStatus counts one tier's nodes.
type TierStatus struct {
	Ready   int32 `json:"ready"`
	Desired int32 `json:"desired"`
}

// RolloutStatus mirrors the leader's rollout record.
type RolloutStatus struct {
	ID     string `json:"id,omitempty"`
	State  string `json:"state,omitempty"`
	Target string `json:"target,omitempty"`
}

// AerolCluster is one AerolVM cell.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ac
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.spec.version`
// +kubebuilder:printcolumn:name="Running",type=string,JSONPath=`.status.version`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Servers",type=integer,JSONPath=`.status.servers.ready`
// +kubebuilder:printcolumn:name="Workers",type=integer,JSONPath=`.status.workers.ready`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type AerolCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AerolClusterSpec   `json:"spec,omitempty"`
	Status AerolClusterStatus `json:"status,omitempty"`
}

// AerolClusterList is a list of AerolClusters.
//
// +kubebuilder:object:root=true
type AerolClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AerolCluster `json:"items"`
}
