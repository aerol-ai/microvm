// Command aerolvm-operator runs AerolVM on Kubernetes
// (plans/kubernetes-v2-architecture.md P2, §7.4): it turns an AerolCluster
// into servers, gateways and workers, carries out upgrades, decommissions
// workers before their machines go, and guards worker pods against a plain
// delete. Two replicas, one leader at a time.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
	"github.com/aerol-ai/microvm/operator/internal/controller"
	guard "github.com/aerol-ai/microvm/operator/internal/webhook"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "aerolvm-operator:", err)
		os.Exit(1)
	}
}

type options struct {
	namespace       string
	workerNamespace string
	templates       string
	metricsAddr     string
	probeAddr       string
	webhookPort     int
	certDir         string
	leaderElect     bool
	serviceAccount  string
	joinURL         string
	joinCAFile      string
	nodeConcurrency int
}

func parse(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet("aerolvm-operator", flag.ContinueOnError)
	fs.StringVar(&o.namespace, "namespace", os.Getenv("POD_NAMESPACE"), "namespace of the AerolClusters, servers and gateways")
	fs.StringVar(&o.workerNamespace, "worker-namespace", "", "namespace of the worker pods (default: --namespace)")
	fs.StringVar(&o.templates, "pod-templates", "aerolvm-pod-templates", "ConfigMap with the server, gateway and worker pod templates")
	fs.StringVar(&o.metricsAddr, "metrics-bind-address", ":8080", "")
	fs.StringVar(&o.probeAddr, "health-probe-bind-address", ":8081", "")
	fs.IntVar(&o.webhookPort, "webhook-port", 9443, "")
	fs.StringVar(&o.certDir, "webhook-cert-dir", "/etc/aerolvm-operator/webhook", "")
	fs.BoolVar(&o.leaderElect, "leader-elect", true, "")
	fs.StringVar(&o.serviceAccount, "service-account", os.Getenv("POD_SERVICE_ACCOUNT"), "the operator's own service account, which the delete guard always allows")
	fs.StringVar(&o.joinURL, "join-url", "", "where a new pod asks the operator for its join token: https://<operator Service>.<namespace>.svc"+controller.JoinIssuePath)
	fs.StringVar(&o.joinCAFile, "join-ca-file", "", "the CA a joining pod trusts the operator by (default: ca.crt in --webhook-cert-dir)")
	fs.IntVar(&o.nodeConcurrency, "node-concurrency", controller.DefaultNodeConcurrency, "AerolNodes reconciled at once")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if o.nodeConcurrency < 1 {
		return o, fmt.Errorf("--node-concurrency must be at least 1")
	}
	if o.namespace == "" {
		return o, fmt.Errorf("--namespace (or POD_NAMESPACE) is required")
	}
	if o.workerNamespace == "" {
		o.workerNamespace = o.namespace
	}
	if o.joinCAFile == "" {
		o.joinCAFile = filepath.Join(o.certDir, "ca.crt")
	}
	return o, nil
}

func newScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(v1.AddToScheme(s))
	return s
}

func run(args []string) error {
	o, err := parse(args)
	if err != nil {
		return err
	}
	ctrl.SetLogger(zap.New())
	scheme := newScheme()
	namespaces := map[string]cache.Config{o.namespace: {}, o.workerNamespace: {}}
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return err
	}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: o.metricsAddr},
		HealthProbeBindAddress: o.probeAddr,
		WebhookServer:          webhook.NewServer(webhook.Options{Port: o.webhookPort, CertDir: o.certDir}),
		LeaderElection:         o.leaderElect,
		LeaderElectionID:       "aerolvm-operator.aerolvm.io",
		Cache:                  cache.Options{DefaultNamespaces: namespaces},
		// Karpenter's NodeClaims are read untyped (no Karpenter Go module
		// here); cached like everything else, so a worker pass reads the
		// informer, not the API server.
		Client: client.Options{Cache: &client.CacheOptions{Unstructured: true}},
	})
	if err != nil {
		return err
	}
	if err := wire(mgr, o, scheme); err != nil {
		return err
	}
	return mgr.Start(ctrl.SetupSignalHandler())
}

// wire adds the controllers, the delete guard and the health checks to mgr.
// Apart from run so a test can wire a manager that never starts.
func wire(mgr ctrl.Manager, o options, scheme *runtime.Scheme) error {
	// The node controller finds the pods on a Kubernetes Node that changed.
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &corev1.Pod{}, "spec.nodeName", func(o client.Object) []string {
		return []string{o.(*corev1.Pod).Spec.NodeName}
	}); err != nil {
		return err
	}
	rec := mgr.GetEventRecorderFor("aerolvm-operator")
	if err := (&controller.ClusterReconciler{Client: mgr.GetClient(), Scheme: scheme, Recorder: rec, WorkerNamespace: o.workerNamespace,
		Templates: o.templates, Reader: mgr.GetAPIReader()}).SetupWithManager(mgr); err != nil {
		return err
	}
	if err := (&controller.NodeReconciler{
		Client: mgr.GetClient(), Scheme: scheme, Recorder: rec,
		Namespace: o.namespace, WorkerNamespace: o.workerNamespace, Templates: o.templates,
		Reader: mgr.GetAPIReader(), MaxConcurrentReconciles: o.nodeConcurrency,
		JoinURL: o.joinURL, JoinCA: func() ([]byte, error) { return os.ReadFile(o.joinCAFile) },
	}).SetupWithManager(mgr); err != nil {
		return err
	}
	user := ""
	if o.serviceAccount != "" {
		user = "system:serviceaccount:" + o.namespace + ":" + o.serviceAccount
	}
	mgr.GetWebhookServer().Register(guard.Path, &webhook.Admission{Handler: &guard.PodGuard{
		Client: mgr.GetAPIReader(), OperatorUser: user, Namespace: o.namespace,
	}})
	var _ admission.Handler = (*guard.PodGuard)(nil)
	// Node identity (§15.2): every replica answers a joining pod.
	mgr.GetWebhookServer().Register(controller.JoinIssuePath, &controller.JoinIssuer{
		Client: mgr.GetClient(), Reader: mgr.GetAPIReader(), Reviewer: controller.ClientTokenReviewer{Client: mgr.GetClient()},
		API: controller.DefaultAPIFactory, Namespace: o.namespace, WorkerNamespace: o.workerNamespace,
	})
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return err
	}
	return mgr.AddReadyzCheck("readyz", healthz.Ping)
}
