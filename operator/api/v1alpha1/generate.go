package v1alpha1

// The CRDs, the deep copies and the operator's RBAC come from the Go types
// and the +kubebuilder markers. Run "go generate ./api/..." from operator/
// after changing either; CI runs it and fails on a diff. The chart ships
// its own copy of the CRDs (Helm installs crds/ before templates), kept
// equal by TestChartCRDsMatch.
//go:generate go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.23.0 object crd rbac:roleName=aerolvm-operator paths=../../... output:crd:dir=../../config/crd output:rbac:dir=../../config/rbac
//go:generate cp ../../config/crd/aerolvm.io_aerolclusters.yaml ../../config/crd/aerolvm.io_aerolnodes.yaml ../../../charts/aerolvm/crds/
