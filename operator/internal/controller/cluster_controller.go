package controller

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// The cluster controller (plans/kubernetes-v2-architecture.md §10): one
// AerolCluster becomes its admin token, its Services, and one AerolNode per
// server, gateway and worker. The node controller turns each AerolNode into
// its pod. Upgrades are AerolVM's own rollout, started and carried out here
// (§13): the leader decides the order, the operator swaps images.

// Ports sandboxd listens on (the chart's templates use the same).
const (
	APIPort      = 21212
	RaftPort     = 7000
	GossipPort   = 7001
	InternalPort = 7002
	JoinPort     = 7003
)

// Conditions on an AerolCluster.
const (
	// CondBootstrapped is set once server 0 started the cluster. From then
	// on no server ever runs init again: a server that lost its volume
	// joins, so a lost disk can never start a second cluster.
	CondBootstrapped = "Bootstrapped"
	CondReady        = "Ready"
	CondRefused      = "Refused"
)

// AnnotationAgentVersion on an AerolNode asks the node controller to swap
// the node's agent to that version: its turn in the rollout came (C13).
const AnnotationAgentVersion = "aerolvm.io/agent-version"

// ClusterReconciler reconciles AerolClusters.
type ClusterReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	API      APIFactory
	// WorkerNamespace holds the worker pods.
	WorkerNamespace string
	// Now is the clock; tests replace it.
	Now func() time.Time
}

// +kubebuilder:rbac:groups=aerolvm.io,resources=aerolclusters;aerolnodes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=aerolvm.io,resources=aerolclusters/status;aerolnodes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets;services;persistentvolumeclaims;configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile brings one AerolCluster's objects to its spec.
func (r *ClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	var c v1.AerolCluster
	if err := r.Get(ctx, req.NamespacedName, &c); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if c.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}
	if why := refuseSpec(&c); why != "" {
		r.setCondition(&c, CondRefused, metav1.ConditionTrue, "Unsupported", why)
		c.Status.Phase = "Refused"
		return ctrl.Result{}, r.Status().Update(ctx, &c)
	}
	// Fixed: the status update at the end of this pass clears it.
	meta.RemoveStatusCondition(&c.Status.Conditions, CondRefused)
	token, err := r.ensureAdminSecret(ctx, &c)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := r.ensureServices(ctx, &c); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.syncEdgeSecret(ctx, &c); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.syncCreatePolicy(ctx, &c); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.syncFederationKey(ctx, &c); err != nil {
		return ctrl.Result{}, err
	}
	nodes, err := listNodes(ctx, r.Client, &c)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := r.ensureServers(ctx, &c, nodes); err != nil {
		return ctrl.Result{}, err
	}
	api := r.API(apiURL(&c), token)
	bootstrapped := meta.IsStatusConditionTrue(c.Status.Conditions, CondBootstrapped)
	if !bootstrapped {
		// The rest needs a running control plane: join tokens come from it.
		if api.Ready(ctx) {
			if err := api.Adopt(ctx); err != nil {
				logger.Info("adopt on the first server failed; retrying", "err", err)
				return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
			}
			r.setCondition(&c, CondBootstrapped, metav1.ConditionTrue, "FirstServerUp", ServerName(c.Name, 0)+" started the cluster")
			r.recordMode(&c)
			r.event(&c, corev1.EventTypeNormal, "Bootstrapped", ServerName(c.Name, 0)+" started the cluster")
		}
		r.updateStatus(ctx, &c, nodes)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, r.Status().Update(ctx, &c)
	}
	if err := r.ensureGateways(ctx, &c, nodes); err != nil {
		return ctrl.Result{}, err
	}
	members, merr := api.Members(ctx)
	if merr != nil {
		logger.Info("reading members failed; scaling waits", "err", merr)
	}
	if err := r.ensureWorkers(ctx, &c, nodes, members, merr == nil); err != nil {
		return ctrl.Result{}, err
	}
	nodes, err = listNodes(ctx, r.Client, &c)
	if err != nil {
		return ctrl.Result{}, err
	}
	// The running version first: the upgrade decision reads it.
	r.updateStatus(ctx, &c, nodes)
	if err := r.reconcileUpgrade(ctx, &c, api, nodes); err != nil {
		logger.Info("upgrade step failed; retrying", "err", err)
		upgradeStepFailures.Inc()
	}
	r.updateStatus(ctx, &c, nodes)
	return ctrl.Result{RequeueAfter: 30 * time.Second}, r.Status().Update(ctx, &c)
}

// refuseSpec names what this build cannot do yet.
func refuseSpec(c *v1.AerolCluster) string {
	if why := refuseModeChange(c); why != "" {
		return why
	}
	if ca := c.Spec.Security.ExternalCA; ca != nil && ca.IssuerRef.Name == "" {
		return "security.externalCA.issuerRef.name is empty"
	}
	if len(c.Spec.Zones) == 0 {
		return "zones is empty"
	}
	if c.Spec.Servers.Count != 3 && c.Spec.Servers.Count != 5 {
		return "servers.count must be 3 or 5"
	}
	if g := c.Spec.Gateways; g.MaxReplicas > 0 && int(g.MaxReplicas) < wantedGateways(c) {
		return fmt.Sprintf("gateways.maxReplicas (%d) is below the %d gateways the cluster keeps: minReplicas, and at least one per zone", g.MaxReplicas, wantedGateways(c))
	}
	seen := map[string]bool{}
	for _, p := range c.Spec.WorkerPools {
		if seen[p.Name] {
			return "worker pool " + p.Name + " is named twice"
		}
		seen[p.Name] = true
		if p.MaxWorkers > 0 && p.MinWorkers > p.MaxWorkers {
			return "worker pool " + p.Name + ": minWorkers is above maxWorkers"
		}
	}
	if f := c.Spec.Federation; f != nil {
		// sandboxd refuses the same values at start; refusing them here
		// says why on the AerolCluster instead of in crash-looping pods.
		if f.IDKeySecret.Name == "" {
			return "federation.idKeySecret.name is empty"
		}
		for k, addr := range f.Cells {
			n, err := strconv.Atoi(k)
			u, uerr := url.Parse(addr)
			if err != nil || n < 1 || n > 255 {
				return "federation.cells: " + k + " is not a cell number from 1 to 255"
			}
			if n == int(max(c.Spec.Cell, 1)) {
				return "federation.cells: " + k + " is this cell"
			}
			if uerr != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				return "federation.cells: " + k + " is not an http(s) address"
			}
		}
	}
	return ""
}

func apiURL(c *v1.AerolCluster) string {
	return fmt.Sprintf("http://%s.%s.svc:%d", APIService(c.Name), c.Namespace, APIPort)
}

// ensureAdminSecret makes the cluster's admin token once. The operator
// holds it and puts it in every server's settings, where `sandboxd init`
// reads it (C23); it never leaves the operator's namespace.
func (r *ClusterReconciler) ensureAdminSecret(ctx context.Context, c *v1.AerolCluster) (string, error) {
	var s corev1.Secret
	key := types.NamespacedName{Namespace: c.Namespace, Name: AdminSecret(c.Name)}
	err := r.Get(ctx, key, &s)
	if err == nil {
		if tok := string(s.Data["token"]); tok != "" {
			return tok, nil
		}
		return "", fmt.Errorf("secret %s has no token", key.Name)
	}
	if !apierrors.IsNotFound(err) {
		return "", err
	}
	tok, err := randomToken(40)
	if err != nil {
		return "", err
	}
	s = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: c.Namespace, Labels: clusterLabels(c)},
		Data:       map[string][]byte{"token": []byte(tok)},
	}
	if err := controllerutil.SetControllerReference(c, &s, r.Scheme); err != nil {
		return "", err
	}
	return tok, r.Create(ctx, &s)
}

func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf))[:n], nil
}

func clusterLabels(c *v1.AerolCluster) map[string]string {
	return map[string]string{LabelName: "aerolvm", LabelCluster: c.Name, LabelManagedBy: "aerolvm-operator"}
}

// ensureServices makes the servers' headless Service (stable DNS names,
// published before ready because Raft needs its peers first), the API
// Service in front of the servers, and the gateways' load balancer.
func (r *ClusterReconciler) ensureServices(ctx context.Context, c *v1.AerolCluster) error {
	servers := map[string]string{LabelCluster: c.Name, LabelComponent: v1.RoleServer}
	headless := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: ServersService(c.Name), Namespace: c.Namespace}}
	if err := r.apply(ctx, c, headless, func() {
		headless.Labels = clusterLabels(c)
		headless.Spec.ClusterIP = corev1.ClusterIPNone
		headless.Spec.PublishNotReadyAddresses = true
		headless.Spec.Selector = servers
		headless.Spec.Ports = []corev1.ServicePort{
			port("raft", RaftPort), port("gossip", GossipPort), port("internal", InternalPort), port("join", JoinPort), port("api", APIPort),
		}
	}); err != nil {
		return err
	}
	api := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: APIService(c.Name), Namespace: c.Namespace}}
	if err := r.apply(ctx, c, api, func() {
		api.Labels = clusterLabels(c)
		api.Spec.Selector = servers
		api.Spec.Ports = []corev1.ServicePort{port("api", APIPort)}
	}); err != nil {
		return err
	}
	gw := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: GatewayService(c.Name), Namespace: c.Namespace}}
	return r.apply(ctx, c, gw, func() {
		gw.Labels = clusterLabels(c)
		gw.Annotations = c.Spec.Gateways.Service.Annotations
		typ := c.Spec.Gateways.Service.Type
		switch {
		case c.Spec.Gateways.GatewayRef != nil:
			// The bank's Gateway fronts the gateways through a plain
			// Service; the chart writes the routes (§7.1).
			typ = corev1.ServiceTypeClusterIP
		case typ == "":
			typ = corev1.ServiceTypeLoadBalancer
		}
		gw.Spec.Type = typ
		if typ == corev1.ServiceTypeLoadBalancer {
			// Clients' addresses reach the gateways, and no hop through
			// another machine sits in the way (§7.1).
			gw.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
		}
		gw.Spec.Selector = map[string]string{LabelCluster: c.Name, LabelComponent: v1.RoleGateway}
		// With the edge, the gateways' Caddy serves the API and the
		// sandbox links on 443 (and 80 for redirects). Without it nothing
		// listens there, so the Service carries sandboxd's own API port
		// instead, for in-cluster clients and a port-forward.
		if c.Spec.Edge.Domain != "" {
			gw.Spec.Ports = []corev1.ServicePort{port("https", 443), port("http", 80), port("ssh", 2220)}
		} else {
			gw.Spec.Ports = []corev1.ServicePort{port("api", APIPort), port("ssh", 2220)}
		}
	})
}

func port(name string, p int32) corev1.ServicePort {
	return corev1.ServicePort{Name: name, Port: p, TargetPort: intstr.FromInt32(p), Protocol: corev1.ProtocolTCP}
}

// apply creates or updates obj, owned by c.
func (r *ClusterReconciler) apply(ctx context.Context, c *v1.AerolCluster, obj client.Object, mutate func()) error {
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, obj, func() error {
		mutate()
		return controllerutil.SetControllerReference(c, obj, r.Scheme)
	})
	return err
}

// listNodes lists the cluster's AerolNodes, by name.
func listNodes(ctx context.Context, cl client.Client, c *v1.AerolCluster) ([]v1.AerolNode, error) {
	var list v1.AerolNodeList
	if err := cl.List(ctx, &list, client.InNamespace(c.Namespace), client.MatchingLabels{LabelCluster: c.Name}); err != nil {
		return nil, err
	}
	sort.Slice(list.Items, func(i, j int) bool { return list.Items[i].Name < list.Items[j].Name })
	return list.Items, nil
}

// ensureServers makes count servers, one zone each in turn, each with its
// own volume (§7.2). The first one alone until the cluster started: the
// others join it.
func (r *ClusterReconciler) ensureServers(ctx context.Context, c *v1.AerolCluster, nodes []v1.AerolNode) error {
	have := map[string]bool{}
	for _, n := range nodes {
		if n.Spec.Role == v1.RoleServer {
			have[n.Name] = true
		}
	}
	count := int(c.Spec.Servers.Count)
	if !meta.IsStatusConditionTrue(c.Status.Conditions, CondBootstrapped) {
		count = 1
	}
	// A lost server is not replaced while any server is in maintenance:
	// recover-quorum needs every survivor held (C22).
	if anyMaintenance(nodes) {
		return nil
	}
	for i := 0; i < count; i++ {
		name := ServerName(c.Name, i)
		if have[name] {
			continue
		}
		zone := c.Spec.Zones[i%len(c.Spec.Zones)]
		if err := r.ensurePVC(ctx, c, name); err != nil {
			return err
		}
		if err := r.createNode(ctx, c, name, v1.RoleServer, "", zone); err != nil {
			return err
		}
	}
	return nil
}

func anyMaintenance(nodes []v1.AerolNode) bool {
	for _, n := range nodes {
		if n.Spec.Role == v1.RoleServer && n.Annotations[v1.AnnotationMaintenance] == "true" {
			return true
		}
	}
	return false
}

// PVCName is server node's volume claim.
func PVCName(node string) string { return "data-" + node }

// LogPVCName is server node's Raft log claim (servers.logStorage).
func LogPVCName(node string) string { return "raftlog-" + node }

// AnnotationLogClaim, on a server's data claim, names its Raft log claim.
// It is written once, with the data claim, and the server's pods mount what
// it names from then on, whatever servers.logStorage says later: a log
// claim laid over a log already on the data disk would hide it, and
// dropping one would hide the log on it. sandboxd refuses either too
// (internal/raftlogdir); this keeps a server from ever being asked to.
const AnnotationLogClaim = "aerolvm.io/raft-log-claim"

// ensurePVC makes server node's volume, and its Raft log volume when
// servers.logStorage asks for one. They land in the server's zone because
// the server pod is pinned there and the storage class binds on first use
// (WaitForFirstConsumer, which the chart's docs require). A data claim that
// exists already keeps the layout it was made with.
//
// The data claim is made first, naming its log claim, and the log claim
// after: a log claim with no data claim can then only be a server's old
// log, kept when a person deleted the data claim to start the server
// afresh. A new server must not take it, and the operator never deletes a
// disk, so that is refused. A data claim whose log claim was not made yet
// (the operator stopped in between) gets it on the next pass.
func (r *ClusterReconciler) ensurePVC(ctx context.Context, c *v1.AerolCluster, node string) error {
	ls := c.Spec.Servers.LogStorage
	var pvc corev1.PersistentVolumeClaim
	err := r.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: PVCName(node)}, &pvc)
	switch {
	case err == nil:
		name := pvc.Annotations[AnnotationLogClaim]
		if name == "" {
			return nil
		}
		return r.ensureLogPVC(ctx, c, node, name)
	case !apierrors.IsNotFound(err):
		return err
	}
	pvc = serverClaim(c, PVCName(node), c.Spec.Servers.Storage)
	if ls != nil {
		var old corev1.PersistentVolumeClaim
		err := r.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: LogPVCName(node)}, &old)
		if err == nil {
			return fmt.Errorf("server %s: claim %s holds an old Raft log and %s is gone; delete %s too to make the server afresh", node, LogPVCName(node), PVCName(node), LogPVCName(node))
		}
		if !apierrors.IsNotFound(err) {
			return err
		}
		pvc.Annotations = map[string]string{AnnotationLogClaim: LogPVCName(node)}
	}
	if err := r.Create(ctx, &pvc); err != nil {
		return err
	}
	if ls == nil {
		return nil
	}
	return r.ensureLogPVC(ctx, c, node, LogPVCName(node))
}

// ensureLogPVC makes the log claim a server's data claim names, if it is
// not there. Its size and class come from servers.logStorage; with that
// cleared, a missing one cannot be made, and the server waits for it.
func (r *ClusterReconciler) ensureLogPVC(ctx context.Context, c *v1.AerolCluster, node, name string) error {
	var pvc corev1.PersistentVolumeClaim
	err := r.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: name}, &pvc)
	if err == nil || !apierrors.IsNotFound(err) {
		return err
	}
	ls := c.Spec.Servers.LogStorage
	if ls == nil {
		return fmt.Errorf("server %s: its data claim names Raft log claim %s, which is gone, and servers.logStorage is not set to make it again", node, name)
	}
	pvc = serverClaim(c, name, *ls)
	if err := r.Create(ctx, &pvc); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// serverClaim is one of a server's claims. No owner reference: a server's
// disk outlives everything but a person deleting it, deleting the
// AerolCluster included.
func serverClaim(c *v1.AerolCluster, name string, s v1.StorageSpec) corev1.PersistentVolumeClaim {
	return corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: c.Namespace, Labels: clusterLabels(c)},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			StorageClassName: s.StorageClassName,
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: s.Size},
			},
		},
	}
}

func (r *ClusterReconciler) createNode(ctx context.Context, c *v1.AerolCluster, name, role, pool, zone string) error {
	n := &v1.AerolNode{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: c.Namespace, Labels: clusterLabels(c)},
		Spec:       v1.AerolNodeSpec{Cluster: c.Name, Role: role, Pool: pool, Zone: zone},
	}
	n.Labels[LabelComponent] = role
	if pool != "" {
		n.Labels[LabelPool] = pool
	}
	if err := controllerutil.SetControllerReference(c, n, r.Scheme); err != nil {
		return err
	}
	if err := r.Create(ctx, n); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	r.event(c, corev1.EventTypeNormal, "NodeAdded", fmt.Sprintf("%s %s in %s", role, name, zone))
	return nil
}

// wantedGateways is how many gateways the cluster keeps: minReplicas, and
// at least one per zone. maxReplicas caps it (refuseSpec refuses a cap
// below it); nothing scales gateways past it.
func wantedGateways(c *v1.AerolCluster) int {
	return int(max(c.Spec.Gateways.MinReplicas, int32(len(c.Spec.Zones))))
}

// ensureGateways keeps wantedGateways gateways, spread across the zones. A
// gateway that ended is replaced by a new one (a new node: gateways hold
// no state). A surplus, left when minReplicas went down, is retired
// (review R7): the node controller deletes each one's pod and takes it out
// of the cluster (retireGateway).
func (r *ClusterReconciler) ensureGateways(ctx context.Context, c *v1.AerolCluster, nodes []v1.AerolNode) error {
	perZone := map[string]int{}
	var live []v1.AerolNode
	for _, n := range nodes {
		if n.Spec.Role == v1.RoleGateway && !ended(n) && n.Annotations[v1.AnnotationDecommission] != "true" {
			perZone[n.Spec.Zone]++
			live = append(live, n)
		}
	}
	want := wantedGateways(c)
	for have := len(live); have < want; have++ {
		zone := leastZone(c.Spec.Zones, perZone)
		suffix, err := randomToken(5)
		if err != nil {
			return err
		}
		if err := r.createNode(ctx, c, c.Name+"-gateway-"+suffix, v1.RoleGateway, "", zone); err != nil {
			return err
		}
		perZone[zone]++
	}
	why := fmt.Sprintf("scale-down: the cluster keeps %d gateways", want)
	for len(live) > want {
		i := surplusGateway(c.Spec.Zones, perZone, live)
		if err := r.markDecommission(ctx, c, live[i].Name, why); err != nil {
			return err
		}
		perZone[live[i].Spec.Zone]--
		live = append(live[:i], live[i+1:]...)
	}
	return nil
}

// surplusGateway picks the gateway to retire first: one in a zone no
// longer in the spec, then one not serving, then one from the zone with the
// most gateways, so every zone keeps its own. Ties go to the last name.
func surplusGateway(zones []string, perZone map[string]int, live []v1.AerolNode) int {
	inSpec := map[string]bool{}
	for _, z := range zones {
		inSpec[z] = true
	}
	rank := func(n v1.AerolNode) (bool, bool, int) {
		return !inSpec[n.Spec.Zone], n.Status.State != v1.StateServing, perZone[n.Spec.Zone]
	}
	best := 0
	for i := 1; i < len(live); i++ {
		ao, an, ac := rank(live[i])
		bo, bn, bc := rank(live[best])
		switch {
		case ao != bo:
			if ao {
				best = i
			}
		case an != bn:
			if an {
				best = i
			}
		case ac != bc:
			if ac > bc {
				best = i
			}
		case live[i].Name > live[best].Name:
			best = i
		}
	}
	return best
}

// ended reports a node whose pod is gone for good: removed, dead, or a
// failed start.
func ended(n v1.AerolNode) bool {
	switch n.Status.State {
	case v1.StateRemoved, v1.StateDead, v1.StateFailed:
		return true
	}
	return n.DeletionTimestamp != nil
}

// leastZone is the zone with the fewest, first in spec order on a tie.
func leastZone(zones []string, count map[string]int) string {
	best := zones[0]
	for _, z := range zones[1:] {
		if count[z] < count[best] {
			best = z
		}
	}
	return best
}

func (r *ClusterReconciler) setCondition(c *v1.AerolCluster, typ string, status metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&c.Status.Conditions, metav1.Condition{
		Type: typ, Status: status, Reason: reason, Message: msg, ObservedGeneration: c.Generation,
	})
}

func (r *ClusterReconciler) event(obj runtime.Object, typ, reason, msg string) {
	if r.Recorder != nil {
		r.Recorder.Event(obj, typ, reason, msg)
	}
}

// updateStatus counts each tier and reports the version every node runs.
func (r *ClusterReconciler) updateStatus(_ context.Context, c *v1.AerolCluster, nodes []v1.AerolNode) {
	c.Status.ObservedGeneration = c.Generation
	var servers, gateways, workers v1.TierStatus
	versions := map[string]int{}
	for _, n := range nodes {
		if ended(n) {
			continue
		}
		ready := n.Status.State == v1.StateServing
		var t *v1.TierStatus
		switch n.Spec.Role {
		case v1.RoleServer:
			t = &servers
		case v1.RoleGateway:
			t = &gateways
		default:
			t = &workers
		}
		t.Desired++
		if ready {
			t.Ready++
		}
		if n.Status.Version != "" {
			versions[n.Status.Version]++
		}
	}
	servers.Desired = c.Spec.Servers.Count
	c.Status.Servers, c.Status.Gateways, c.Status.Workers = servers, gateways, workers
	if len(versions) == 1 {
		for v := range versions {
			c.Status.Version = v
		}
	}
	switch {
	case !meta.IsStatusConditionTrue(c.Status.Conditions, CondBootstrapped):
		c.Status.Phase = "Bootstrapping"
	case c.Status.Rollout != nil && c.Status.Rollout.State != "" && c.Status.Rollout.State != upgradewire.StateDone && c.Status.Rollout.State != upgradewire.StateFinalized:
		c.Status.Phase = "Upgrading"
	case servers.Ready < servers.Desired || gateways.Ready == 0:
		c.Status.Phase = "Degraded"
	default:
		c.Status.Phase = "Ready"
	}
	ready := metav1.ConditionFalse
	if c.Status.Phase == "Ready" {
		ready = metav1.ConditionTrue
	}
	r.setCondition(c, CondReady, ready, c.Status.Phase, fmt.Sprintf("servers %d/%d, gateways %d, workers %d/%d",
		servers.Ready, servers.Desired, gateways.Ready, workers.Ready, workers.Desired))
	nodeStates.Reset()
	pending := 0
	for _, n := range nodes {
		nodeStates.WithLabelValues(n.Status.State, n.Spec.Role).Inc()
		if meta.IsStatusConditionTrue(n.Status.Conditions, CondCertificatePending) {
			pending++
		}
	}
	nodeCertsPending.Set(float64(pending))
}

// SetupWithManager registers the controller.
func (r *ClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.API == nil {
		r.API = DefaultAPIFactory
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.AerolCluster{}).
		Owns(&v1.AerolNode{}).
		Owns(&corev1.Service{}).
		Named("aerolcluster").
		Complete(r)
}

// syncCreatePolicy keeps a copy of the create policy's ConfigMap in the
// worker namespace, where worker pods mount it: a ConfigMap volume is
// namespaced. Only the policy key is copied.
func (r *ClusterReconciler) syncCreatePolicy(ctx context.Context, c *v1.AerolCluster) error {
	ref := c.Spec.Security.CreatePolicy
	if ref == nil || ref.Name == "" || r.WorkerNamespace == "" || r.WorkerNamespace == c.Namespace {
		return nil
	}
	var src corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: ref.Name}, &src); err != nil {
		// Not there yet: workers refuse creates until it is (fail closed).
		return client.IgnoreNotFound(err)
	}
	dst := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: r.WorkerNamespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, dst, func() error {
		dst.Labels = clusterLabels(c)
		dst.Data = map[string]string{CreatePolicyKey: src.Data[CreatePolicyKey]}
		return nil
	})
	return err
}

// syncEdgeSecret copies the sandbox-link certificate, its certificate and
// key only, into the worker namespace (C25). A renewal reaches the copy on
// the next pass; sandboxd reloads it from the file.
func (r *ClusterReconciler) syncEdgeSecret(ctx context.Context, c *v1.AerolCluster) error {
	name := c.Spec.Edge.TLSSecret
	if name == "" || r.WorkerNamespace == "" || r.WorkerNamespace == c.Namespace {
		return nil
	}
	var src corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: name}, &src); err != nil {
		// Not issued yet: worker pods wait for it, as a single-mode pod
		// waits for its Secret.
		return client.IgnoreNotFound(err)
	}
	dst := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: r.WorkerNamespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, dst, func() error {
		dst.Labels = clusterLabels(c)
		dst.Type = corev1.SecretTypeTLS
		dst.Data = map[string][]byte{
			corev1.TLSCertKey:       src.Data[corev1.TLSCertKey],
			corev1.TLSPrivateKeyKey: src.Data[corev1.TLSPrivateKeyKey],
		}
		return nil
	})
	return err
}

// syncFederationKey copies the federation's ID key, that key only, into the
// worker namespace, where worker pods read it: a Secret reference is
// namespaced. Until the Secret exists the pods that need it wait
// (CreateContainerConfigError), so no node mints IDs without the key.
func (r *ClusterReconciler) syncFederationKey(ctx context.Context, c *v1.AerolCluster) error {
	f := c.Spec.Federation
	if f == nil || f.IDKeySecret.Name == "" || r.WorkerNamespace == "" || r.WorkerNamespace == c.Namespace {
		return nil
	}
	var src corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: f.IDKeySecret.Name}, &src); err != nil {
		return client.IgnoreNotFound(err)
	}
	dst := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: f.IDKeySecret.Name, Namespace: r.WorkerNamespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, dst, func() error {
		dst.Labels = clusterLabels(c)
		dst.Data = map[string][]byte{FederationKeyKey: src.Data[FederationKeyKey]}
		return nil
	})
	return err
}
