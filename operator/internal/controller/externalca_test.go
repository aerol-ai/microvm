package controller

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
)

// External-CA mode (C23): the operator asks cert-manager for one
// certificate per node, makes the pod only once it is ready, mounts it as
// the pod's cluster TLS dir and joins with it, and never mints a token.

func externalCACluster() *v1.AerolCluster {
	c := testCluster()
	c.Spec.Security.ExternalCA = &v1.ExternalCASpec{IssuerRef: v1.IssuerRef{Kind: "ClusterIssuer", Name: "bank-ca"}}
	return c
}

func (g *nodeRig) certificate(ns, node string) *unstructured.Unstructured {
	g.t.Helper()
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(certificateGVK)
	if err := g.cl.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: NodeCert(node)}, u); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		g.t.Fatal(err)
	}
	return u
}

// issue does what cert-manager does once the issuer signs: Ready, and the
// Secret with the keys given.
func (g *nodeRig) issue(ns, node string, keys ...string) {
	g.t.Helper()
	ctx := context.Background()
	u := g.certificate(ns, node)
	_ = unstructured.SetNestedSlice(u.Object, []any{map[string]any{"type": "Ready", "status": "True"}}, "status", "conditions")
	if err := g.cl.Update(ctx, u); err != nil {
		g.t.Fatal(err)
	}
	labels, _, _ := unstructured.NestedStringMap(u.Object, "spec", "secretTemplate", "labels")
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: NodeCert(node), Namespace: ns, Labels: labels}, Data: map[string][]byte{}}
	for _, k := range keys {
		s.Data[k] = []byte("pem")
	}
	if err := g.cl.Create(ctx, s); apierrors.IsAlreadyExists(err) {
		err = g.cl.Update(ctx, s)
	} else if err != nil {
		g.t.Fatal(err)
	}
}

func TestExternalCAWorkerWaitsForItsCertificate(t *testing.T) {
	ctx := context.Background()
	const name = "prod-general-ccccc"
	g := newNodeRig(t, bootstrapped(externalCACluster()), node(name, v1.RoleWorker, "general", "z-a"))

	// First pass: the Certificate is asked for, nothing else.
	g.reconcile(name)
	cert := g.certificate(testWorkerNS, name)
	if cert == nil {
		t.Fatal("no Certificate")
	}
	if len(cert.GetOwnerReferences()) != 0 {
		t.Fatalf("owner across namespaces: %+v", cert.GetOwnerReferences())
	}
	n := g.node(name)
	if c := meta.FindStatusCondition(n.Status.Conditions, CondCertificatePending); c == nil || c.Status != metav1.ConditionTrue ||
		!strings.Contains(c.Message, "ClusterIssuer bank-ca") || n.Status.State != v1.StatePending {
		t.Fatalf("pending = %+v state %s", n.Status.Conditions, n.Status.State)
	}
	if g.pod(testWorkerNS, name) != nil || len(g.api.minted) != 0 {
		t.Fatalf("pod made or token minted (%v) before the certificate", g.api.minted)
	}

	// Signed, but the Secret lacks the CA: still waiting, and why.
	g.issue(testWorkerNS, name, "tls.crt", "tls.key")
	g.reconcile(name)
	if n := g.node(name); !strings.Contains(n.Status.Reason, "no ca.crt") || g.pod(testWorkerNS, name) != nil {
		t.Fatalf("no CA: reason %q", n.Status.Reason)
	}

	g.issue(testWorkerNS, name, "tls.crt", "tls.key", "ca.crt")
	g.reconcile(name)
	p := g.pod(testWorkerNS, name)
	if p == nil {
		t.Fatal("no pod once the certificate is ready")
	}
	if n := g.node(name); meta.FindStatusCondition(n.Status.Conditions, CondCertificatePending) != nil {
		t.Fatalf("pending left on: %+v", n.Status.Conditions)
	}
	if len(g.api.minted) != 0 {
		t.Fatalf("token minted in external-CA mode: %v", g.api.minted)
	}
	var s corev1.Secret
	if err := g.cl.Get(ctx, types.NamespacedName{Namespace: testWorkerNS, Name: NodeCert(name)}, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.OwnerReferences) != 1 || s.OwnerReferences[0].Kind != "Certificate" || s.OwnerReferences[0].Name != NodeCert(name) {
		t.Fatalf("the Secret does not go with its Certificate: %+v", s.OwnerReferences)
	}
}

// A later server joins by its certificate. Its setup failing mints nothing
// (in token mode a server's failed setup gets a token): setup retries the
// join with the same certificate by itself.
func TestExternalCAServerSetupFailingMintsNoToken(t *testing.T) {
	ctx := context.Background()
	const name = "prod-server-1"
	g := newNodeRig(t, bootstrapped(externalCACluster()), node(name, v1.RoleServer, "", "z-b"), machine("m1"))
	g.reconcile(name)
	g.issue(testNS, name, "tls.crt", "tls.key", "ca.crt")
	g.reconcile(name)
	p := g.pod(testNS, name)
	if p == nil {
		t.Fatal("no pod")
	}
	p.Spec.NodeName = "m1"
	if err := g.cl.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: SetupContainer,
		LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 2}},
		State:                corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}}}
	if err := g.cl.Status().Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	g.reconcile(name)
	var s corev1.Secret
	if err := g.cl.Get(ctx, types.NamespacedName{Namespace: testNS, Name: JoinSecret(name)}, &s); !apierrors.IsNotFound(err) || len(g.api.minted) != 0 {
		t.Fatalf("a token minted in external-CA mode: %v %v", err, g.api.minted)
	}
}

func TestExternalCAServerZeroInitsWithItsCertificate(t *testing.T) {
	const name = "prod-server-0"
	g := newNodeRig(t, externalCACluster(), node(name, v1.RoleServer, "", "z-a"), machine("m1"))
	g.reconcile(name)
	cert := g.certificate(testNS, name)
	if cert == nil || len(cert.GetOwnerReferences()) != 1 || cert.GetOwnerReferences()[0].Name != name {
		t.Fatalf("server's Certificate is not its AerolNode's: %+v", cert)
	}
	dns, _, _ := unstructured.NestedStringSlice(cert.Object, "spec", "dnsNames")
	if !slices.Contains(dns, ServerDNS(name, "prod", testNS)) {
		t.Fatalf("server DNS name missing: %v", dns)
	}
	if g.pod(testNS, name) != nil {
		t.Fatal("server 0 started before its certificate")
	}
	g.issue(testNS, name, "tls.crt", "tls.key", "ca.crt")
	g.reconcile(name)
	p := g.pod(testNS, name)
	if p == nil {
		t.Fatal("no pod")
	}
	cmd := p.Spec.InitContainers[len(p.Spec.InitContainers)-1].Command[2]
	if !strings.Contains(cmd, "sandboxd init --files-only --external-ca --role server --node-id prod-server-0") {
		t.Fatalf("setup = %s", cmd)
	}

	// Its pod is lost: the pod made again keeps the same Certificate and
	// key (the cluster pinned that key), with no write to either.
	uid := cert.GetUID()
	if err := g.cl.Delete(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	writes := 0
	g.r.Client = interceptor.NewClient(g.cl.(client.WithWatch), interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, ok := obj.(*corev1.Pod); !ok {
				writes++
			}
			return c.Create(ctx, obj, opts...)
		},
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			writes++
			return c.Patch(ctx, obj, patch, opts...)
		},
	})
	g.reconcile(name)
	g.r.Client = g.cl
	if g.pod(testNS, name) == nil || writes != 0 || g.certificate(testNS, name).GetUID() != uid {
		t.Fatalf("pod made again: pod %v, %d certificate writes", g.pod(testNS, name) != nil, writes)
	}
}

// cert-manager missing, or an error reading the Certificate.
func TestExternalCACertificateReadErrors(t *testing.T) {
	const name = "prod-general-ddddd"
	c := bootstrapped(externalCACluster())
	g := newNodeRig(t, c, node(name, v1.RoleWorker, "general", "z-a"))
	fail := errors.New("api down")
	var getErr error
	g.r.Client = interceptor.NewClient(g.cl.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if u, ok := obj.(*unstructured.Unstructured); ok && u.GroupVersionKind() == certificateGVK && getErr != nil {
				return getErr
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})
	getErr = &meta.NoKindMatchError{GroupKind: certificateGVK.GroupKind(), SearchedVersions: []string{"v1"}}
	g.reconcile(name)
	if n := g.node(name); !strings.Contains(n.Status.Reason, "cert-manager is not installed") {
		t.Fatalf("reason %q", n.Status.Reason)
	}
	getErr = fail
	if _, err := g.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNS, Name: name}}); !errors.Is(err, fail) {
		t.Fatalf("read error = %v", err)
	}
}

func TestCertificateReady(t *testing.T) {
	for _, tc := range []struct {
		conds []any
		ok    bool
		why   string
	}{
		{nil, false, "not signed it yet"},
		{[]any{map[string]any{"type": "Issuing", "status": "True"}}, false, "not signed it yet"},
		{[]any{map[string]any{"type": "Ready", "status": "False", "message": "request denied"}}, false, "request denied"},
		{[]any{map[string]any{"type": "Ready", "status": "False", "reason": "Pending"}}, false, "Pending"},
		{[]any{map[string]any{"type": "Ready", "status": "True"}}, true, ""},
	} {
		u := &unstructured.Unstructured{Object: map[string]any{}}
		if tc.conds != nil {
			_ = unstructured.SetNestedSlice(u.Object, tc.conds, "status", "conditions")
		}
		ok, why := certificateReady(u)
		if ok != tc.ok || !strings.Contains(why, tc.why) {
			t.Errorf("%v: ready %v %q", tc.conds, ok, why)
		}
	}
}

func TestNodeCertificateSpec(t *testing.T) {
	c := externalCACluster()
	for _, tc := range []struct {
		role, ns, uriRole string
		serverDNS         bool
	}{
		{v1.RoleServer, testNS, "server", true},
		{v1.RoleGateway, testNS, "ingress", false},
		{v1.RoleWorker, testWorkerNS, "worker", false},
	} {
		n := node("prod-x", tc.role, "general", "z-a")
		u := nodeCertificate(c, n, tc.ns)
		spec, _, _ := unstructured.NestedMap(u.Object, "spec")
		uris, _, _ := unstructured.NestedStringSlice(spec, "uris")
		if !slices.Equal(uris, []string{"node:prod-x", "aerolvm-role:" + tc.uriRole}) {
			t.Errorf("%s: uris %v", tc.role, uris)
		}
		dns, _, _ := unstructured.NestedStringSlice(spec, "dnsNames")
		if dns[0] != clusterServerName || (len(dns) == 2) != tc.serverDNS {
			t.Errorf("%s: dnsNames %v", tc.role, dns)
		}
		if rot, _, _ := unstructured.NestedString(spec, "privateKey", "rotationPolicy"); rot != "Never" {
			t.Errorf("%s: a renewal would make a new key the cluster refuses (rotationPolicy %q)", tc.role, rot)
		}
		if kind, _, _ := unstructured.NestedString(spec, "issuerRef", "kind"); kind != "ClusterIssuer" {
			t.Errorf("%s: issuer kind %q", tc.role, kind)
		}
		if l, _, _ := unstructured.NestedStringMap(spec, "secretTemplate", "labels"); l[LabelNode] != "prod-x" || l[LabelManagedBy] != "aerolvm-operator" {
			t.Errorf("%s: secret labels %v", tc.role, l)
		}
		if secret, _, _ := unstructured.NestedString(spec, "secretName"); secret != "prod-x-cert" || u.GetNamespace() != tc.ns {
			t.Errorf("%s: secret %s in %s", tc.role, secret, u.GetNamespace())
		}
	}
}

// Every pod of an external-CA cluster mounts its certificate as its TLS
// dir and joins with it; a token-mode pod has neither.
func TestStampExternalCA(t *testing.T) {
	tmpl := templates(t)
	c := bootstrapped(externalCACluster())
	stamp := func(n *v1.AerolNode, ns string, boot, maint bool) *corev1.Pod {
		t.Helper()
		in := StampInput{JoinURL: testJoinURL, JoinCA: testJoinCA, Cluster: c, Node: n, Namespace: ns, Version: "v0.7.2", Bootstrap: boot, Maintenance: maint}
		switch n.Spec.Role {
		case v1.RoleServer:
			in.PVC = PVCName(n.Name)
		case v1.RoleWorker:
			in.Pool = &c.Spec.WorkerPools[0]
		}
		t0, err := ParsePodTemplate(tmpl.Data[n.Spec.Role])
		if err != nil {
			t.Fatal(err)
		}
		p, err := Stamp(t0, in)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tc := range []struct {
		n          *v1.AerolNode
		ns         string
		boot       bool
		wantCmd    string
		wantNoFlag string
	}{
		{node("prod-server-0", v1.RoleServer, "", "z-a"), testNS, true, "sandboxd init --files-only --external-ca --role server", "--token"},
		{node("prod-server-1", v1.RoleServer, "", "z-b"), testNS, false,
			"sandboxd join https://prod-servers.aerolvm-system.svc:7003 --by-certificate --role server --node-id prod-server-1", "--token"},
		{node("prod-gw-aaaaa", v1.RoleGateway, "", "z-a"), testNS, false, "--by-certificate --role ingress", "--ca-cert-hash"},
		{node("prod-general-aaaaa", v1.RoleWorker, "general", "z-a"), testWorkerNS, false, "--by-certificate --role worker", "--from-operator"},
	} {
		p := stamp(tc.n, tc.ns, tc.boot, false)
		setup := p.Spec.InitContainers[len(p.Spec.InitContainers)-1]
		if cmd := setup.Command[2]; !strings.Contains(cmd, tc.wantCmd) || strings.Contains(cmd, tc.wantNoFlag) {
			t.Errorf("%s: setup = %s", tc.n.Name, cmd)
		}
		vol := volumeNamed(p.Spec.Volumes, TLSVolume)
		if vol == nil || vol.Secret == nil || vol.Secret.SecretName != NodeCert(tc.n.Name) || *vol.Secret.Optional {
			t.Fatalf("%s: TLS volume %+v", tc.n.Name, vol)
		}
		got := map[string]string{}
		for _, it := range vol.Secret.Items {
			got[it.Key] = it.Path
		}
		if len(got) != 3 || got["tls.crt"] != "node.crt" || got["tls.key"] != "node.key" || got["ca.crt"] != "ca.crt" {
			t.Errorf("%s: items %v", tc.n.Name, got)
		}
		if volumeNamed(p.Spec.Volumes, JoinIdentityVolume) != nil || mountNamed(setup.VolumeMounts, JoinIdentityVolume) != nil || envValue(setup.Env, JoinCAEnv) != "" {
			t.Errorf("%s: a join-token identity in external-CA mode", tc.n.Name)
		}
		agent := p.Spec.Containers[containerIndex(p.Spec.Containers, AgentContainer)]
		for _, ctr := range []corev1.Container{agent, setup} {
			if m := mountNamed(ctr.VolumeMounts, TLSVolume); m == nil || m.MountPath != TLSDir || !m.ReadOnly {
				t.Errorf("%s/%s: TLS mount %+v", tc.n.Name, ctr.Name, m)
			}
			if envValue(ctr.Env, "SB_CLUSTER_TLS_DIR") != TLSDir {
				t.Errorf("%s/%s: SB_CLUSTER_TLS_DIR %q", tc.n.Name, ctr.Name, envValue(ctr.Env, "SB_CLUSTER_TLS_DIR"))
			}
		}
	}

	// A maintenance pod runs no sandboxd and never waits on the Secret.
	p := stamp(node("prod-server-1", v1.RoleServer, "", "z-b"), testNS, false, true)
	if vol := volumeNamed(p.Spec.Volumes, TLSVolume); vol == nil || !*vol.Secret.Optional {
		t.Fatalf("maintenance TLS volume %+v", vol)
	}

	// Token mode is unchanged.
	c = bootstrapped(testCluster())
	p = stamp(node("prod-server-1", v1.RoleServer, "", "z-b"), testNS, false, false)
	if volumeNamed(p.Spec.Volumes, TLSVolume) != nil || volumeNamed(p.Spec.Volumes, JoinIdentityVolume) == nil {
		t.Fatal("token mode got the external-CA volume")
	}
}

func volumeNamed(vs []corev1.Volume, name string) *corev1.Volume {
	for i := range vs {
		if vs[i].Name == name {
			return &vs[i]
		}
	}
	return nil
}

func mountNamed(ms []corev1.VolumeMount, name string) *corev1.VolumeMount {
	for i := range ms {
		if ms[i].Name == name {
			return &ms[i]
		}
	}
	return nil
}

// A node that leaves takes its certificate and key with it; a Secret by
// that name that the operator did not make stays.
func TestExternalCARemovedNodeTakesItsCertificate(t *testing.T) {
	ctx := context.Background()
	c := bootstrapped(externalCACluster())
	const name, other = "prod-general-eeeee", "prod-general-fffff"
	g := newNodeRig(t, c, node(name, v1.RoleWorker, "general", "z-a"), node(other, v1.RoleWorker, "general", "z-a"))
	for _, nm := range []string{name, other} {
		g.reconcile(nm)
		g.issue(testWorkerNS, nm, "tls.crt", "tls.key", "ca.crt")
	}
	// other's Secret is someone else's (no labels).
	var s corev1.Secret
	_ = g.cl.Get(ctx, types.NamespacedName{Namespace: testWorkerNS, Name: NodeCert(other)}, &s)
	s.Labels = nil
	if err := g.cl.Update(ctx, &s); err != nil {
		t.Fatal(err)
	}
	for _, nm := range []string{name, other} {
		n := g.node(nm)
		n.Status.State = v1.StateRemoved
		if err := g.cl.Status().Update(ctx, n); err != nil {
			t.Fatal(err)
		}
		g.reconcile(nm)
		if g.node(nm) != nil || g.certificate(testWorkerNS, nm) != nil {
			t.Fatalf("%s: AerolNode or Certificate left", nm)
		}
	}
	if err := g.cl.Get(ctx, types.NamespacedName{Namespace: testWorkerNS, Name: NodeCert(name)}, &s); !apierrors.IsNotFound(err) {
		t.Fatalf("the node's key left behind: %v", err)
	}
	if err := g.cl.Get(ctx, types.NamespacedName{Namespace: testWorkerNS, Name: NodeCert(other)}, &s); err != nil {
		t.Fatalf("a Secret the operator did not make was deleted: %v", err)
	}
}

// A worker AerolNode deleted outright, or with a finalizer holding it:
// its certificate in the worker namespace goes too.
func TestExternalCASweepsAGoneWorkersCertificate(t *testing.T) {
	ctx := context.Background()
	c := bootstrapped(externalCACluster())
	const swept, held = "prod-general-ggggg", "prod-general-hhhhh"
	h := node(held, v1.RoleWorker, "general", "z-a")
	h.Finalizers = []string{"test/hold"}
	g := newNodeRig(t, c, node(swept, v1.RoleWorker, "general", "z-a"), h)
	for _, nm := range []string{swept, held} {
		g.reconcile(nm)
		g.issue(testWorkerNS, nm, "tls.crt", "tls.key", "ca.crt")
		g.reconcile(nm)
		if g.pod(testWorkerNS, nm) == nil {
			t.Fatalf("%s: no pod", nm)
		}
		if err := g.cl.Delete(ctx, g.node(nm)); err != nil {
			t.Fatal(err)
		}
		g.reconcile(nm)
		var s corev1.Secret
		if err := g.cl.Get(ctx, types.NamespacedName{Namespace: testWorkerNS, Name: NodeCert(nm)}, &s); !apierrors.IsNotFound(err) {
			t.Fatalf("%s: certificate Secret left: %v", nm, err)
		}
		if g.certificate(testWorkerNS, nm) != nil || g.pod(testWorkerNS, nm) != nil {
			t.Fatalf("%s: Certificate or pod left", nm)
		}
	}
	// Token mode: nothing to sweep, and no Certificate call.
	if err := g.r.sweepCert(ctx, testWorkerNS, "prod-general-zzzzz"); err != nil {
		t.Fatal(err)
	}
}

// The mode is set when the cluster starts, and recorded then; turning it on
// or off later is refused, and the refusal clears once the spec is put back.
func TestExternalCAModeIsFixedAtStart(t *testing.T) {
	r, _, _ := clusterRig(t, externalCACluster(), templates(t))
	got := reconcileCluster(t, r)
	got = reconcileCluster(t, r)
	if !meta.IsStatusConditionTrue(got.Status.Conditions, CondBootstrapped) || !meta.IsStatusConditionTrue(got.Status.Conditions, CondExternalCA) {
		t.Fatalf("mode not recorded at start: %+v", got.Status.Conditions)
	}

	ctx := context.Background()
	got.Spec.Security.ExternalCA = nil
	if err := r.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	got = reconcileCluster(t, r)
	if c := meta.FindStatusCondition(got.Status.Conditions, CondRefused); c == nil || c.Status != metav1.ConditionTrue ||
		!strings.Contains(c.Message, "cannot be removed") {
		t.Fatalf("turning it off was not refused: %+v", got.Status.Conditions)
	}
	got.Spec.Security.ExternalCA = &v1.ExternalCASpec{IssuerRef: v1.IssuerRef{Kind: "ClusterIssuer", Name: "bank-ca"}}
	if err := r.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	got = reconcileCluster(t, r)
	if meta.FindStatusCondition(got.Status.Conditions, CondRefused) != nil || got.Status.Phase == "Refused" {
		t.Fatalf("refusal left after the spec was put back: %+v", got.Status)
	}

	// A token-mode cluster, recorded or started before the record existed.
	tok := bootstrapped(testCluster())
	tok.Spec.Security.ExternalCA = &v1.ExternalCASpec{IssuerRef: v1.IssuerRef{Kind: "Issuer", Name: "x"}}
	if why := refuseSpec(tok); !strings.Contains(why, "cannot be added") {
		t.Fatalf("turning it on = %q", why)
	}
	meta.SetStatusCondition(&tok.Status.Conditions, metav1.Condition{Type: CondExternalCA, Status: metav1.ConditionFalse, Reason: "SetAtStart"})
	if why := refuseSpec(tok); !strings.Contains(why, "cannot be added") {
		t.Fatalf("turning it on (recorded) = %q", why)
	}
	fresh := externalCACluster()
	fresh.Spec.Security.ExternalCA.IssuerRef.Name = ""
	if why := refuseSpec(fresh); !strings.Contains(why, "issuerRef.name is empty") {
		t.Fatalf("no issuer = %q", why)
	}
	if why := refuseSpec(testCluster()); why != "" {
		t.Fatalf("token mode refused: %q", why)
	}
}

func TestExternalCAPendingGauge(t *testing.T) {
	r, _, _ := clusterRig(t, bootstrapped(externalCACluster()))
	pending := node("prod-general-aaaaa", v1.RoleWorker, "general", "z-a")
	meta.SetStatusCondition(&pending.Status.Conditions, metav1.Condition{Type: CondCertificatePending, Status: metav1.ConditionTrue, Reason: "WaitingForIssuer"})
	c := externalCACluster()
	r.updateStatus(context.Background(), c, []v1.AerolNode{*pending, *node("prod-general-bbbbb", v1.RoleWorker, "general", "z-a")})
	var m dto.Metric
	_ = nodeCertsPending.Write(&m)
	if m.GetGauge().GetValue() != 1 {
		t.Fatalf("pending gauge = %v", m.GetGauge().GetValue())
	}
	r.updateStatus(context.Background(), c, nil)
	_ = nodeCertsPending.Write(&m)
	if m.GetGauge().GetValue() != 0 {
		t.Fatalf("pending gauge after = %v", m.GetGauge().GetValue())
	}
}
