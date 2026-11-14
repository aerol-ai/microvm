package controller

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/yaml"

	dto "github.com/prometheus/client_model/go"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
	"github.com/aerol-ai/microvm/operator/internal/aerolapi"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// fakeAPI is the admin API with every answer set by the test.
type fakeAPI struct {
	mu         sync.Mutex
	ready      bool
	adoptErr   error
	adopted    int
	mintErr    error
	minted     []string
	nodes      map[string]aerolapi.Node
	members    []aerolapi.Node
	membersErr error
	cordoned   []string
	evacuate   func(id string, req aerolapi.EvacuateRequest) (aerolapi.EvacuateResult, error)
	gone       []string
	deleted    []string
	deleteErr  error
	rollout    *upgradewire.Rollout
	rolloutErr error
	applyErr   error
	applied    []string
	rolledBack int
}

func newFakeAPI() *fakeAPI { return &fakeAPI{ready: true, nodes: map[string]aerolapi.Node{}} }

func (f *fakeAPI) factory(string, string) AerolAPI { return f }

func (f *fakeAPI) Ready(context.Context) bool { return f.ready }
func (f *fakeAPI) Adopt(context.Context) error {
	f.adopted++
	return f.adoptErr
}
func (f *fakeAPI) MintJoinToken(_ context.Context, role, _, by string) (aerolapi.JoinToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mintErr != nil {
		return aerolapi.JoinToken{}, f.mintErr
	}
	f.minted = append(f.minted, role+":"+by)
	return aerolapi.JoinToken{Token: "tok-" + role, CACertHash: "sha256:abc", JoinURLs: []string{"https://s0:7003"}}, nil
}
func (f *fakeAPI) GetNode(_ context.Context, id string) (aerolapi.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.nodes[id]
	if !ok {
		return aerolapi.Node{}, &aerolapi.Error{Status: http.StatusNotFound, Reason: "unknown node"}
	}
	return n, nil
}
func (f *fakeAPI) Members(context.Context) ([]aerolapi.Node, error) { return f.members, f.membersErr }
func (f *fakeAPI) Cordon(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cordoned = append(f.cordoned, id)
	return nil
}
func (f *fakeAPI) Uncordon(context.Context, string) error { return nil }
func (f *fakeAPI) Evacuate(_ context.Context, id string, req aerolapi.EvacuateRequest) (aerolapi.EvacuateResult, error) {
	if f.evacuate == nil {
		return aerolapi.EvacuateResult{Done: true}, nil
	}
	return f.evacuate(id, req)
}
func (f *fakeAPI) Gone(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gone = append(f.gone, id)
	return nil
}
func (f *fakeAPI) DeleteNode(_ context.Context, id string, _ bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, id)
	return f.deleteErr
}
func (f *fakeAPI) Rollout(context.Context) (*upgradewire.Rollout, error) {
	return f.rollout, f.rolloutErr
}
func (f *fakeAPI) ApplyImages(_ context.Context, v string, _ upgradewire.ApplyRequest) (*upgradewire.Rollout, error) {
	f.applied = append(f.applied, v)
	if f.applyErr != nil {
		return nil, f.applyErr
	}
	return &upgradewire.Rollout{TargetVersion: v, State: upgradewire.StateRunning}, nil
}
func (f *fakeAPI) Rollback(context.Context) error {
	f.rolledBack++
	return nil
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(v1.AddToScheme(s))
	// cert-manager's Certificate, which the operator reads and writes
	// unstructured (external-CA mode, C23).
	s.AddKnownTypeWithName(certificateGVK, &unstructured.Unstructured{})
	s.AddKnownTypeWithName(certificateGVK.GroupVersion().WithKind("CertificateList"), &unstructured.UnstructuredList{})
	return s
}

const (
	testNS       = "aerolvm-system"
	testWorkerNS = "aerolvm-workers"
)

func testCluster() *v1.AerolCluster {
	return &v1.AerolCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "prod", Namespace: testNS, UID: "uid-prod", Generation: 1},
		Spec: v1.AerolClusterSpec{
			Version: "v0.7.2", Cell: 3, Zones: []string{"z-a", "z-b", "z-c"},
			Images:   v1.ImageSpec{Registry: "registry.example/aerol"},
			Servers:  v1.ServerSpec{Count: 3, Storage: v1.StorageSpec{Size: resource.MustParse("20Gi")}},
			Gateways: v1.GatewaySpec{MinReplicas: 3},
			WorkerPools: []v1.WorkerPoolSpec{{
				Name: "general", Runtimes: []string{"gvisor"}, NodeSelector: map[string]string{"aerolvm.io/pool": "general"},
				Machine: v1.MachineSpec{CPU: 32, MemoryGiB: 128}, MinWorkers: 3, MaxWorkers: 9, HeadroomPercent: 15,
			}},
		},
	}
}

// templates is the pod-templates ConfigMap, the shape the chart renders.
func templates(t *testing.T) *corev1.ConfigMap {
	t.Helper()
	agent := corev1.Container{
		Name: AgentContainer, Image: "ghcr.io/aerol-ai/aerolvm:v0.7.1",
		Env: []corev1.EnvVar{{Name: "SB_API_PORT", Value: "21212"}, {Name: "SB_NODE_ROLE", Value: "single"},
			{Name: "SB_ENABLE_NETWORK_RULES", Value: "true"}, {Name: "SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT", Value: "true"}},
		VolumeMounts: []corev1.VolumeMount{{Name: EtcVolume, MountPath: "/etc/sandboxd"}, {Name: StateVolume, MountPath: "/var/lib/sandboxd"}},
		Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{
			corev1.ResourceCPU: resource.MustParse("1"), corev1.ResourceMemory: resource.MustParse("1Gi")}},
	}
	vols := []corev1.Volume{{Name: EtcVolume, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: StateVolume, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
	enc := func(spec corev1.PodSpec) string {
		raw, err := yaml.Marshal(corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"t": "1"}}, Spec: spec})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	worker := corev1.PodSpec{Containers: []corev1.Container{
		{Name: RuntimeContainer, Image: "ghcr.io/aerol-ai/aerolvm-runtime:v0.7.1"},
		agent,
		{Name: "edge", Image: "ghcr.io/aerol-ai/aerolvm-edge:v0.7.1", Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{
			corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("512Mi")}}},
	}, Volumes: vols}
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "aerolvm-pod-templates", Namespace: testNS},
		Data: map[string]string{
			TemplateServer:  enc(corev1.PodSpec{Containers: []corev1.Container{agent}, Volumes: vols}),
			TemplateGateway: enc(corev1.PodSpec{Containers: []corev1.Container{agent}, Volumes: vols}),
			TemplateWorker:  enc(worker),
		},
	}
}

func adminSecret() *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: AdminSecret("prod"), Namespace: testNS},
		Data: map[string][]byte{"token": []byte("admin-token")}}
}

func newFakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objs...).
		WithStatusSubresource(&v1.AerolCluster{}, &v1.AerolNode{}).
		WithIndex(&corev1.Pod{}, "spec.nodeName", func(o client.Object) []string { return []string{o.(*corev1.Pod).Spec.NodeName} }).
		Build()
}

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

var _ = record.NewFakeRecorder

func metavCond(typ string) metav1.Condition {
	return metav1.Condition{Type: typ, Status: metav1.ConditionTrue, Reason: "Test", Message: "test"}
}

// testutilCounter reads a counter's value.
func testutilCounter(c interface{ Write(*dto.Metric) error }) float64 {
	var m dto.Metric
	_ = c.Write(&m)
	return m.GetCounter().GetValue()
}

// newFakeClientWith is newFakeClient with calls intercepted, for failures.
func newFakeClientWith(t *testing.T, funcs interceptor.Funcs, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objs...).WithInterceptorFuncs(funcs).Build()
}
