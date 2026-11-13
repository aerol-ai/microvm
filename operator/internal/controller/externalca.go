package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
)

// External-CA mode (C23, plans/kubernetes-v2-architecture.md §15.2.1): the
// bank's issuer signs every pod's node certificate through cert-manager, so
// no CA key enters the cluster (D11) and the operator mints no join tokens.
//
//	AerolNode ─► Certificate <node>-cert: the spec's issuer, URIs node:<id>
//	  and aerolvm-role:<role>, one key for the node's whole life
//	  ─► cert-manager ─► Secret <node>-cert (tls.crt, tls.key, ca.crt)
//	not ready ─► CertificatePending on the AerolNode; no pod yet
//	ready     ─► the pod, with that Secret as its cluster TLS dir
//	  ─► setup: init --external-ca (server 0) or join --by-certificate

const (
	// CondCertificatePending is on an AerolNode while its certificate
	// waits for the issuer; its message says what it waits for.
	CondCertificatePending = "CertificatePending"
	// CondExternalCA records, when server 0 starts the cluster, whether
	// it started in external-CA mode. The mode can never change after:
	// every node's identity and trust come from it.
	CondExternalCA = "ExternalCA"
	// TLSVolume is the node certificate's Secret in an external-CA pod.
	TLSVolume = "cluster-tls"
	// TLSDir is where it is mounted: SB_CLUSTER_TLS_DIR. Not under
	// /etc/sandboxd, which a server keeps on its disk: the files here are
	// cert-manager's, and the kubelet swaps them in place on a renewal.
	TLSDir = "/var/run/aerolvm-tls"
	// clusterServerName is the DNS name every node certificate carries and
	// every node dials by (internal/cluster/tls.go).
	clusterServerName = "aerolvm-cluster-node"
)

var certificateGVK = schema.GroupVersionKind{Group: "cert-manager.io", Version: "v1", Kind: "Certificate"}

// NodeCert names a node's Certificate and the Secret cert-manager writes.
func NodeCert(node string) string { return node + "-cert" }

func externalCA(c *v1.AerolCluster) bool { return c.Spec.Security.ExternalCA != nil }

// refuseModeChange keeps a started cluster in the mode it started in. A
// cluster started before the mode existed has no record and used tokens.
func refuseModeChange(c *v1.AerolCluster) string {
	if !meta.IsStatusConditionTrue(c.Status.Conditions, CondBootstrapped) {
		return ""
	}
	was := meta.IsStatusConditionTrue(c.Status.Conditions, CondExternalCA)
	switch {
	case was && !externalCA(c):
		return "security.externalCA was set when the cluster started and cannot be removed: every node's certificate comes from that issuer"
	case !was && externalCA(c):
		return "security.externalCA cannot be added to a running cluster: its nodes joined with tokens and trust the cluster's own CA"
	}
	return ""
}

// recordMode notes the mode server 0 started the cluster in.
func (r *ClusterReconciler) recordMode(c *v1.AerolCluster) {
	if externalCA(c) {
		ref := c.Spec.Security.ExternalCA.IssuerRef
		r.setCondition(c, CondExternalCA, metav1.ConditionTrue, "SetAtStart", "node certificates come from "+ref.Kind+" "+ref.Name)
		return
	}
	r.setCondition(c, CondExternalCA, metav1.ConditionFalse, "SetAtStart", "nodes join with tokens; the CA is on the servers")
}

// nodeCertificate is the Certificate for node n, in the namespace its pod
// runs in.
func nodeCertificate(c *v1.AerolCluster, n *v1.AerolNode, ns string) *unstructured.Unstructured {
	labels := map[string]string{LabelName: "aerolvm", LabelCluster: c.Name, LabelNode: n.Name, LabelManagedBy: "aerolvm-operator"}
	secretLabels := map[string]any{}
	for k, v := range labels {
		secretLabels[k] = v
	}
	dns := []any{clusterServerName}
	if n.Spec.Role == v1.RoleServer {
		// A server's own stable name (lesson L7); other pods have none
		// before they start.
		dns = append(dns, ServerDNS(n.Name, c.Name, ns))
	}
	ref := c.Spec.Security.ExternalCA.IssuerRef
	u := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{
		"secretName": NodeCert(n.Name),
		// The labels say whose the Secret is, so the operator deletes
		// only its own (removeNodeCert).
		"secretTemplate": map[string]any{"labels": secretLabels},
		// Many issuers (Vault roles, private CAs) refuse a request with
		// no subject; sandboxd itself reads only the SANs.
		"commonName": n.Name,
		"dnsNames":   dns,
		"uris":       []any{"node:" + n.Name, "aerolvm-role:" + sandboxdRole(n.Spec.Role)},
		"usages":     []any{"digital signature", "server auth", "client auth"},
		// The cluster pins the key a node first joined with and refuses
		// any other for that node ID (opAdmitNodeByCert), so a renewal
		// must keep it. cert-manager's default since v1.18 is a new key
		// on every renewal, which would lock the node out at its first.
		"privateKey": map[string]any{"algorithm": "ECDSA", "size": int64(256), "rotationPolicy": "Never"},
		"issuerRef":  map[string]any{"group": "cert-manager.io", "kind": ref.Kind, "name": ref.Name},
	}}}
	u.SetGroupVersionKind(certificateGVK)
	u.SetName(NodeCert(n.Name))
	u.SetNamespace(ns)
	u.SetLabels(labels)
	return u
}

// ensureNodeCert asks the issuer for node n's certificate once, then says
// what it still waits for: "" once its Secret holds a certificate that
// cert-manager calls ready, with the CA beside it.
func (r *NodeReconciler) ensureNodeCert(ctx context.Context, c *v1.AerolCluster, n *v1.AerolNode, ns string) (string, error) {
	cert := &unstructured.Unstructured{}
	cert.SetGroupVersionKind(certificateGVK)
	err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: NodeCert(n.Name)}, cert)
	switch {
	case meta.IsNoMatchError(err):
		return "cert-manager is not installed (no Certificate kind)", nil
	case apierrors.IsNotFound(err):
		want := nodeCertificate(c, n, ns)
		if ns == n.Namespace {
			if err := controllerutil.SetControllerReference(n, want, r.Scheme); err != nil {
				return "", err
			}
		}
		if err := r.Create(ctx, want); err != nil && !apierrors.IsAlreadyExists(err) {
			return "", err
		}
		ref := c.Spec.Security.ExternalCA.IssuerRef
		return fmt.Sprintf("requested from %s %s", ref.Kind, ref.Name), nil
	case err != nil:
		return "", err
	}
	if ok, why := certificateReady(cert); !ok {
		return why, nil
	}
	var s corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: NodeCert(n.Name)}, &s); err != nil {
		if apierrors.IsNotFound(err) {
			return "Secret " + NodeCert(n.Name) + " is not written yet", nil
		}
		return "", err
	}
	for _, k := range []string{"tls.crt", "tls.key", "ca.crt"} {
		if len(s.Data[k]) == 0 {
			// ca.crt is the trust: a node with no CA beside its
			// certificate can verify no other node.
			return "Secret " + NodeCert(n.Name) + " has no " + k + " (the issuer must return its CA as ca.crt)", nil
		}
	}
	// The Secret goes with its Certificate. cert-manager leaves it behind
	// unless it runs with --enable-certificate-owner-ref, and a node's
	// private key must not outlive the node.
	if !ownedBy(&s, cert) {
		patch := client.MergeFrom(s.DeepCopy())
		if err := controllerutil.SetOwnerReference(cert, &s, r.Scheme); err != nil {
			return "", err
		}
		if err := r.Patch(ctx, &s, patch); err != nil {
			return "", err
		}
	}
	return "", nil
}

func ownedBy(o, owner metav1.Object) bool {
	for _, ref := range o.GetOwnerReferences() {
		if ref.UID == owner.GetUID() {
			return true
		}
	}
	return false
}

// certificateReady reads cert-manager's Ready condition.
func certificateReady(cert *unstructured.Unstructured) (bool, string) {
	conds, _, _ := unstructured.NestedSlice(cert.Object, "status", "conditions")
	for _, raw := range conds {
		cond, _ := raw.(map[string]any)
		if cond["type"] != "Ready" {
			continue
		}
		if cond["status"] == "True" {
			return true, ""
		}
		msg, _ := cond["message"].(string)
		if msg == "" {
			msg, _ = cond["reason"].(string)
		}
		return false, "the issuer has not signed it: " + msg
	}
	return false, "the issuer has not signed it yet"
}

// certificatePending holds node n until its certificate is ready.
func (r *NodeReconciler) certificatePending(n *v1.AerolNode, why string) {
	meta.SetStatusCondition(&n.Status.Conditions, metav1.Condition{
		Type: CondCertificatePending, Status: metav1.ConditionTrue, Reason: "WaitingForIssuer", Message: why,
		ObservedGeneration: n.Generation,
	})
	r.setState(n, v1.StatePending, "waiting for its certificate: "+why)
}

// removeNodeCert deletes node name's Certificate and its Secret, when the
// node leaves for good. The Secret is deleted only when its labels say it
// is that node's, so a Secret someone else made under the name stays.
func (r *NodeReconciler) removeNodeCert(ctx context.Context, ns, name string) error {
	cert := &unstructured.Unstructured{}
	cert.SetGroupVersionKind(certificateGVK)
	cert.SetNamespace(ns)
	cert.SetName(NodeCert(name))
	if err := r.Delete(ctx, cert); err != nil && !apierrors.IsNotFound(err) && !meta.IsNoMatchError(err) {
		return err
	}
	var s corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: NodeCert(name)}, &s)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if s.Labels[LabelNode] != name || s.Labels[LabelManagedBy] != "aerolvm-operator" {
		return nil
	}
	return client.IgnoreNotFound(r.Delete(ctx, &s))
}

// useNodeCert mounts node's certificate Secret as its cluster TLS dir, its
// keys renamed to the files sandboxd reads. A maintenance pod runs no
// sandboxd and must start even with the Secret gone, so there it is
// optional.
func useNodeCert(spec *corev1.PodSpec, node string, optional bool) {
	spec.Volumes = append(spec.Volumes, corev1.Volume{Name: TLSVolume, VolumeSource: corev1.VolumeSource{
		Secret: &corev1.SecretVolumeSource{SecretName: NodeCert(node), DefaultMode: ptr[int32](0o400), Optional: ptr(optional),
			Items: []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}, {Key: "tls.crt", Path: "node.crt"}, {Key: "tls.key", Path: "node.key"}}},
	}})
	i := containerIndex(spec.Containers, AgentContainer)
	spec.Containers[i].VolumeMounts = append(spec.Containers[i].VolumeMounts,
		corev1.VolumeMount{Name: TLSVolume, MountPath: TLSDir, ReadOnly: true})
	setEnv(spec, AgentContainer, []corev1.EnvVar{{Name: "SB_CLUSTER_TLS_DIR", Value: TLSDir}})
}

// joinServiceURL is the servers' join port behind their headless Service:
// any server answers a join by certificate (a follower hands the write to
// the leader), and the name lists every server, so one that is down costs
// a refused dial, not the join.
func joinServiceURL(c *v1.AerolCluster) string {
	return fmt.Sprintf("https://%s.%s.svc:%d", ServersService(c.Name), c.Namespace, JoinPort)
}
