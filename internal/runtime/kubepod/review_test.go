package kubepod

// Tests for the review notes on #1482 (M4 PR 2b).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/models"
)

const testDigest = "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// Note 1: no create input is dropped without a word.
func TestRenderPodRefusesUnenforcedInputs(t *testing.T) {
	d := newTestDriver(t, newFakeAPI(t), nil)
	base := models.CreateSandboxRequest{Image: "alpine"}
	network := map[string]func(*models.CreateSandboxRequest){
		"network_block_all":       func(r *models.CreateSandboxRequest) { r.NetworkBlockAll = true },
		"network_allow_out":       func(r *models.CreateSandboxRequest) { r.NetworkAllowOut = []string{"example.com"} },
		"network_deny_out":        func(r *models.CreateSandboxRequest) { r.NetworkDenyOut = []string{"10.0.0.0/8"} },
		"egress_profiles":         func(r *models.CreateSandboxRequest) { r.EgressProfiles = []string{"pypi"} },
		"network_egress_mode":     func(r *models.CreateSandboxRequest) { r.NetworkEgressMode = "learn" },
		"network_egress_rules":    func(r *models.CreateSandboxRequest) { r.NetworkEgressRules = []models.EgressRule{{}} },
		"egress_withheld_env":     func(r *models.CreateSandboxRequest) { r.EgressWithheldEnv = []string{"TOKEN"} },
		"network_bytes_in_limit":  func(r *models.CreateSandboxRequest) { r.NetworkBytesInLimit = 1 },
		"network_bytes_out_limit": func(r *models.CreateSandboxRequest) { r.NetworkBytesOutLimit = 1 },
	}
	for field, set := range network {
		req := base
		set(&req)
		_, err := d.renderPod(req, testID)
		if !errors.Is(err, ErrNetworkRulesNotSupported) || !strings.Contains(err.Error(), field) {
			t.Errorf("%s: renderPod = %v, want ErrNetworkRulesNotSupported naming it", field, err)
		}
	}
	for name, set := range map[string]func(*models.CreateSandboxRequest){
		"mounts":           func(r *models.CreateSandboxRequest) { r.Mounts = []models.MountSpec{{}} },
		"platform volumes": func(r *models.CreateSandboxRequest) { r.PlatformVolumes = []models.PlatformVolumeMount{{}} },
	} {
		req := base
		set(&req)
		if _, err := d.renderPod(req, testID); !errors.Is(err, ErrMountsNotSupported) {
			t.Errorf("%s: renderPod = %v, want ErrMountsNotSupported", name, err)
		}
	}
	if d.NetRulesEnabled() {
		t.Error("NetRulesEnabled must be false: the service then refuses network policies too")
	}
}

func TestRenderPodNoRootRule(t *testing.T) {
	d := newTestDriver(t, newFakeAPI(t), nil)
	p, err := d.renderPod(models.CreateSandboxRequest{Image: "alpine", RequireNonRootUser: true}, testID)
	if err != nil {
		t.Fatal(err)
	}
	if sc := p.Spec.Containers[0].SecurityContext; sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
		t.Fatalf("security = %+v, want runAsNonRoot", sc)
	}
}

func TestPinnedImage(t *testing.T) {
	other := "sha256:" + strings.Repeat("f", 64)
	cases := []struct {
		image, pin, want string
		err              error
	}{
		{"alpine:3.20", "", "alpine:3.20", nil},
		{"alpine:3.20", testDigest, "alpine:3.20@" + testDigest, nil},
		{"registry:5000/team/app", testDigest, "registry:5000/team/app@" + testDigest, nil},
		{"alpine@" + testDigest, testDigest, "alpine@" + testDigest, nil},
		{"alpine@" + other, testDigest, "", ErrImageDigestMismatch},
		{"alpine", "sha256:short", "", nil},
	}
	for _, tc := range cases {
		got, err := pinnedImage(tc.image, tc.pin)
		switch {
		case tc.want == "" && tc.err == nil:
			if err == nil {
				t.Errorf("pinnedImage(%q, %q) = %q, want an error", tc.image, tc.pin, got)
			}
		case tc.err != nil:
			if !errors.Is(err, tc.err) {
				t.Errorf("pinnedImage(%q, %q) = %v, want %v", tc.image, tc.pin, err, tc.err)
			}
		case err != nil || got != tc.want:
			t.Errorf("pinnedImage(%q, %q) = %q, %v; want %q", tc.image, tc.pin, got, err, tc.want)
		}
	}
	d := newTestDriver(t, newFakeAPI(t), nil)
	p, err := d.renderPod(models.CreateSandboxRequest{Image: "alpine:3.20", ImageDigest: testDigest}, testID)
	if err != nil || p.Spec.Containers[0].Image != "alpine:3.20@"+testDigest {
		t.Fatalf("pinned create = %v, %v", p, err)
	}
}

// Note 2: a start sends a pod rebuilt from the sandbox's own inputs, never
// the file's other content.
func TestStartRebuildsTheKeptSpec(t *testing.T) {
	f := newFakeAPI(t)
	f.setKubelet(runningKubelet)
	d := newTestDriver(t, f, nil)
	req := models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 2.007, MemoryMB: 300, DiskGB: 2, RequireNonRootUser: true, ContainerCommand: []string{"sleep", "1d"}}
	want, err := d.renderPod(req, testID)
	if err != nil {
		t.Fatal(err)
	}
	// The file is changed behind the worker's back (a deep copy: want
	// must stay as rendered).
	var tampered Pod
	raw, _ := json.Marshal(want)
	_ = json.Unmarshal(raw, &tampered)
	tampered.Metadata.Labels[LabelWorker] = "worker-7"
	tampered.Spec.Volumes = append(tampered.Spec.Volumes, Volume{Name: "host"})
	tampered.Spec.Containers[0].SecurityContext.Privileged = boolPtr(true)
	tampered.Spec.Containers[0].Env = append(tampered.Spec.Containers[0].Env, EnvVar{Name: "SECRET", Value: "s3cr3t"})
	tampered.Spec.InitContainers[0].Image = "elsewhere/toolbox"
	tampered.Spec.Containers = append(tampered.Spec.Containers, Container{Name: "extra", Image: "evil"})
	if err := d.specs.put(&tampered); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Start(context.Background(), testID); err != nil {
		t.Fatalf("Start: %v", err)
	}
	sent := f.get(testNS, testID)
	sent.Status, sent.Metadata.UID, sent.Metadata.ResourceVersion, sent.Metadata.Namespace = nil, "", "", want.Metadata.Namespace
	if !reflect.DeepEqual(sent.Spec, want.Spec) || !reflect.DeepEqual(sent.Metadata.Labels, want.Metadata.Labels) {
		got, _ := json.Marshal(sent)
		t.Fatalf("start sent %s\nwant the pod rendered from the sandbox's inputs", got)
	}
	kept, err := d.specs.get(testID)
	if err != nil || !reflect.DeepEqual(kept.Spec, want.Spec) {
		t.Errorf("kept spec not replaced by the rebuilt one: %v", err)
	}
}

func TestStartRefusesAKeptSpecItCannotRead(t *testing.T) {
	cases := []struct {
		name string
		edit func(p *Pod)
		cfg  func(c *Config)
		want string
	}{
		{"no sandbox ID", func(p *Pod) { delete(p.Metadata.Annotations, AnnotationSandboxID) }, nil, "no sandbox ID"},
		{"another sandbox's ID", func(p *Pod) { p.Metadata.Annotations[AnnotationSandboxID] = "sb-ffffffffffffffff" }, nil, "names sandbox"},
		{"no sandbox container", func(p *Pod) { p.Spec.Containers[0].Name = "other" }, nil, "no sandbox container"},
		{"cpu not in millicores", func(p *Pod) { p.Spec.Containers[0].Resources.Limits["cpu"] = "1.5" }, nil, "cpu"},
		{"memory not in Mi", func(p *Pod) { p.Spec.Containers[0].Resources.Limits["memory"] = "512M" }, nil, "memory"},
		{"disk not in Gi", func(p *Pod) { p.Spec.Containers[0].Resources.Limits["ephemeral-storage"] = "4G" }, nil, "ephemeral-storage"},
		{"zero memory", func(p *Pod) { p.Spec.Containers[0].Resources.Limits["memory"] = "0Mi" }, nil, "memory"},
		{"runtime no longer offered", func(*Pod) {}, func(c *Config) {
			c.RuntimeClasses = map[string]string{models.RuntimeDocker: "runc"}
			c.DefaultRuntime = models.RuntimeDocker
		}, "cannot start here as it was made"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t)
			d := newTestDriver(t, f, nil)
			p, err := d.renderPod(models.CreateSandboxRequest{Image: "alpine", DiskGB: 4}, testID)
			if err != nil {
				t.Fatal(err)
			}
			tc.edit(p)
			if err := d.specs.put(p); err != nil {
				t.Fatal(err)
			}
			if tc.cfg != nil {
				cfg := d.cfg
				tc.cfg(&cfg)
				d = newTestDriver(t, f, func(c *Config) { *c = cfg })
			}
			_, err = d.Start(context.Background(), testID)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Start = %v, want an error with %q", err, tc.want)
			}
			if n := f.count("POST "); n != 0 {
				t.Errorf("%d pod creates for a spec that cannot be used", n)
			}
		})
	}
}

func TestSandboxRequestRoundTrip(t *testing.T) {
	d := newTestDriver(t, newFakeAPI(t), nil)
	for _, req := range []models.CreateSandboxRequest{
		{Image: "alpine", CPU: 2.007, MemoryMB: 1},
		{Image: "python:3.12@" + testDigest, Runtime: models.RuntimeDocker, CPU: 0.25, MemoryMB: 4096, DiskGB: 10, RequireNonRootUser: true, ContainerCommand: []string{"python", "-m", "http.server"}},
		{Image: "alpine", ImageDigest: testDigest},
	} {
		first, err := d.renderPod(req, testID)
		if err != nil {
			t.Fatal(err)
		}
		back, id, err := sandboxRequestOf(first)
		if err != nil || id != testID {
			t.Fatalf("sandboxRequestOf = %v, %q", err, id)
		}
		again, err := d.renderPod(back, id)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := json.Marshal(first)
		b, _ := json.Marshal(again)
		if string(a) != string(b) {
			t.Errorf("render → read back → render differs:\n%s\n%s", a, b)
		}
	}
}

// Note 4: the client checks the API server's certificate.
func TestInClusterClientRefusesAnotherServer(t *testing.T) {
	trusted := httptest.NewTLSServer(http.NotFoundHandler())
	defer trusted.Close()
	var served atomic.Bool
	impostor := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Store(true)
		_, _ = w.Write([]byte(`{"metadata":{"name":"p"}}`))
	}))
	// Every httptest TLS server shares one built-in certificate, so the
	// impostor gets a certificate of its own, for the same address.
	impostor.TLS = &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}}
	impostor.StartTLS()
	defer impostor.Close()
	// The service account's CA is the trusted server's; the address is the
	// impostor's, whose certificate that CA did not sign.
	fakeServiceAccount(t, trusted, "tok")
	u, _ := url.Parse(impostor.URL)
	t.Setenv("KUBERNETES_SERVICE_HOST", u.Hostname())
	t.Setenv("KUBERNETES_SERVICE_PORT", u.Port())
	c, err := InClusterClient()
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetPod(context.Background(), "ns", "p")
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("GetPod from a server the CA did not sign = %v, want a certificate error", err)
	}
	if served.Load() {
		t.Error("the request reached the impostor: no token may be sent to an unchecked server")
	}
	if err := c.WatchPods(context.Background(), "ns", "", "", nil, func(WatchEvent) error { return nil }); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("WatchPods = %v, want a certificate error", err)
	}
}

// selfSigned is a fresh certificate for 127.0.0.1 that no CA signed.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "impostor"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost", "example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// A failed create waits until its pod is gone, so it leaves nothing and a
// retry of the same ID is not refused as "still stopping" (found on kind:
// the clean-up used to return while the pod was still terminating).
func TestFailedCreateLeavesNothing(t *testing.T) {
	pullFails := func(p *Pod) {
		p.Status = &PodStatus{Phase: PhasePending, ContainerStatuses: []ContainerStatus{{
			Name: sandboxContainer, State: ContainerState{Waiting: &StateWaiting{Reason: "ErrImagePull"}},
		}}}
	}
	f := newFakeAPI(t)
	f.setKubelet(pullFails)
	f.setGoneAfter(3)
	d := newTestDriver(t, f, nil)
	if _, err := d.Create(context.Background(), testReq, testID, "tok", nil); err == nil {
		t.Fatal("want the pull error")
	}
	if f.get(testNS, testID) != nil {
		t.Fatal("the failed create returned while its pod was still there")
	}
	f.setKubelet(runningKubelet)
	if _, err := d.Create(context.Background(), testReq, testID, "tok", nil); err != nil {
		t.Fatalf("retry of the same ID: %v", err)
	}

	t.Run("a pod that never goes is left to the orphan sweep", func(t *testing.T) {
		f := newFakeAPI(t)
		f.setKubelet(pullFails)
		f.setGoneAfter(-1)
		d := newTestDriver(t, f, nil)
		d.undoWait = 30 * time.Millisecond
		if _, err := d.Create(context.Background(), testReq, testID, "tok", nil); err == nil {
			t.Fatal("want the pull error")
		}
		if hasSpec(d, testID) {
			t.Error("spec kept")
		}
		listed, err := d.ListManaged(context.Background())
		if err != nil || listed[testID] == nil || listed[testID].Status != models.SandboxStatusStopped {
			t.Fatalf("ListManaged = %v, %v: want the stopping pod listed, stopped", listed, err)
		}
	})
}

// Note 5: a pod the API server stores after the clean-up of an unanswered
// create already looked (and found nothing) is this worker's pod with no
// spec. The list shows it, so reconcile's orphan sweep, which destroys
// every listed instance with no row, removes it with Destroy.
func TestLatePodIsListedAndDestroyed(t *testing.T) {
	f := newFakeAPI(t)
	f.setGoneAfter(1)
	d := newTestDriver(t, f, nil)
	d.undoUnanswered(context.Background(), errors.New("no answer"), testID, testID)
	if n := len(f.deleteCalls()); n != 0 {
		t.Fatalf("clean-up deleted %d pods with none there", n)
	}
	// The API server stores it now.
	p, err := d.renderPod(testReq, testID)
	if err != nil {
		t.Fatal(err)
	}
	p.Status = &PodStatus{Phase: PhaseRunning, PodIP: "10.244.0.9"}
	f.put(p)

	listed, err := d.ListManaged(context.Background())
	if err != nil || listed[testID] == nil || listed[testID].Status != models.SandboxStatusStarted {
		t.Fatalf("ListManaged = %v, %v: want the late pod listed", listed, err)
	}
	stub := &models.Sandbox{ID: testID, ContainerID: listed[testID].ContainerID}
	if err := d.Destroy(context.Background(), stub); err != nil {
		t.Fatalf("Destroy of the listed orphan: %v", err)
	}
	if f.get(testNS, testID) != nil {
		t.Error("orphan pod still there")
	}
	if st, err := d.Inspect(context.Background(), testID); !sbruntime.InstanceGone(st, err) {
		t.Errorf("Inspect after the sweep = %+v, %v; want gone", st, err)
	}
	if _, err := os.Stat(d.specs.path(testID)); err == nil {
		t.Error("a spec appeared for the orphan")
	}
}
