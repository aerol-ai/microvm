// Package v1alpha1 holds the AerolVM operator's Kubernetes objects
// (plans/kubernetes-v2-architecture.md §10.1): AerolCluster, one per cell,
// which people write, and AerolNode, one per server, gateway or worker, which
// only the operator writes. There is no object per sandbox.
//
// +kubebuilder:object:generate=true
// +groupName=aerolvm.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is the group and version of these objects.
	GroupVersion = schema.GroupVersion{Group: "aerolvm.io", Version: "v1alpha1"}

	// SchemeBuilder adds the objects to a scheme. Plain apimachinery, so
	// a client that only reads these objects needs no controller-runtime.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the objects in this group-version to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion, &AerolCluster{}, &AerolClusterList{}, &AerolNode{}, &AerolNodeList{})
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
