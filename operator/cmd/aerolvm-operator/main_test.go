package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

func TestParse(t *testing.T) {
	if _, err := parse(nil); err == nil {
		t.Fatal("no namespace accepted")
	}
	o, err := parse([]string{"--namespace", "aerolvm-system", "--service-account", "aerolvm-operator"})
	if err != nil || o.workerNamespace != "aerolvm-system" || o.templates != "aerolvm-pod-templates" || !o.leaderElect {
		t.Fatalf("defaults = %+v %v", o, err)
	}
	o, err = parse([]string{"--namespace", "a", "--worker-namespace", "b", "--leader-elect=false"})
	if err != nil || o.workerNamespace != "b" || o.leaderElect {
		t.Fatalf("flags = %+v %v", o, err)
	}
	if _, err := parse([]string{"--nope"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
	if s := newScheme(); !s.IsGroupRegistered("aerolvm.io") {
		t.Fatal("scheme lacks the aerolvm.io group")
	}
}

// wire adds both controllers, the delete guard and the health checks to a
// manager without starting it, so no API server is needed. run's own error
// path is a config that does not parse.
func TestWire(t *testing.T) {
	o, err := parse([]string{"--namespace", "aerolvm-system", "--worker-namespace", "aerolvm-workers", "--service-account", "aerolvm-operator"})
	if err != nil {
		t.Fatal(err)
	}
	scheme := newScheme()
	// A mapper from the scheme: wiring asks for resource mappings, and the
	// default mapper would ask the (absent) API server.
	mapper := meta.NewDefaultRESTMapper(nil)
	for gvk := range scheme.AllKnownTypes() {
		mapper.Add(gvk, meta.RESTScopeNamespace)
	}
	mgr, err := ctrl.NewManager(&rest.Config{Host: "http://127.0.0.1:1"}, ctrl.Options{
		Scheme: scheme,
		MapperProvider: func(*rest.Config, *http.Client) (meta.RESTMapper, error) {
			return mapper, nil
		},
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		WebhookServer:          webhook.NewServer(webhook.Options{Port: 0, CertDir: t.TempDir()}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := wire(mgr, o, scheme); err != nil {
		t.Fatalf("wire: %v", err)
	}
	// Wired twice: the index is already there, and wire says so.
	if err := wire(mgr, o, scheme); err == nil {
		t.Fatal("a second wire of one manager returned nil")
	}
	// A second manager in this process: its controllers' names are taken
	// (controller-runtime checks them process-wide), and wire says so.
	mgr2, err := ctrl.NewManager(&rest.Config{Host: "http://127.0.0.1:1"}, ctrl.Options{
		Scheme: scheme,
		MapperProvider: func(*rest.Config, *http.Client) (meta.RESTMapper, error) {
			return mapper, nil
		},
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		WebhookServer:          webhook.NewServer(webhook.Options{Port: 0, CertDir: t.TempDir()}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := wire(mgr2, o, scheme); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("a controller name used twice: %v", err)
	}
	if err := run([]string{"--nope"}); err == nil {
		t.Fatal("run accepted an unknown flag")
	}
}

// With no kubeconfig and no in-cluster settings run stops at the config.
func TestRunWithoutConfig(t *testing.T) {
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing"))
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("HOME", t.TempDir())
	if err := run([]string{"--namespace", "a"}); err == nil {
		t.Fatal("run with no config returned nil")
	}
}

// run with good flags gets as far as wiring, which needs the API server: a
// kubeconfig that points nowhere is an error, not an exit.
func TestRunWithoutAPIServer(t *testing.T) {
	kc := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(kc, []byte(`apiVersion: v1
kind: Config
clusters: [{name: x, cluster: {server: "http://127.0.0.1:1"}}]
contexts: [{name: x, context: {cluster: x, user: x}}]
users: [{name: x, user: {}}]
current-context: x
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kc)
	err := run([]string{"--namespace", "a", "--metrics-bind-address", "0", "--health-probe-bind-address", "0", "--leader-elect=false"})
	if err == nil {
		t.Fatal("run with no API server returned nil")
	}
}
