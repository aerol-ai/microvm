package controller

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
	"github.com/aerol-ai/microvm/operator/internal/aerolapi"
)

// Node identity on Kubernetes (plans/kubernetes-v2-architecture.md §15.2,
// R2, D6, S-2). A pod proves which pod it is, and on which machine, with
// its pod-bound ServiceAccount token; only then does the operator make it a
// join token:
//
//	setup container ─► POST /v1/join-token, Bearer <projected token, audience aerolvm.io/join>
//	operator ─► TokenReview ─► the pod's name, UID and machine, from Kubernetes
//	         ─► that pod is live with that UID, is an AerolNode's, runs on that machine, has not joined
//	         ─► marks the pod (one token per pod per token life) ─► MintJoinToken, 10 minutes
//	         ◄─ token, CA hash, join URL
//
// No join token waits in a Secret for a pod that may never come: one is
// made only for a scheduled pod that asks, it lives ten minutes, and the
// servers bind it to the first key that uses it.

const (
	// JoinAudience is the audience of the token a pod proves itself with.
	// Its own audience, so the token is good for nothing else, and the API
	// server's own tokens are good for nothing here.
	JoinAudience = "aerolvm.io/join"
	// JoinIssuePath is where the webhook server answers a joining pod.
	JoinIssuePath = "/v1/join-token"
	// joinTokenLife bounds a join token the operator makes (S-2: at most
	// ten minutes). The pod asks for it once its setup runs, so the image
	// pull and the machine's start do not count against it.
	joinTokenLife = 10 * time.Minute
	// AnnotationJoinIssued on a pod records when the operator made its join
	// token: a second request inside the token's life is refused, so one
	// pod gets one join, whichever operator replica answers.
	AnnotationJoinIssued = "aerolvm.io/join-token-issued"
	// AnnotationJoinRefused on a pod says why the operator last refused
	// it a join token; the node controller shows it as the AerolNode's
	// IdentityDenied condition.
	AnnotationJoinRefused = "aerolvm.io/join-token-refused"
	// CondIdentityDenied is set while the operator refuses the node's pod
	// a join token (§19 identity denial, runbook AerolVMJoinTokenErrors).
	CondIdentityDenied = "IdentityDenied"
)

// The claims a pod-bound ServiceAccount token carries into TokenReview's
// answer. The node name needs Kubernetes 1.30 or later
// (ServiceAccountTokenPodNodeInfo).
const (
	claimPodName  = "authentication.kubernetes.io/pod-name"
	claimPodUID   = "authentication.kubernetes.io/pod-uid"
	claimNodeName = "authentication.kubernetes.io/node-name"
)

// Requests to TokenReview are spaced: anyone in the cluster can reach the
// endpoint, and each request costs the API server a review.
const (
	reviewsPerSecond = 20
	reviewBurst      = 40
	// podAskEvery spaces one pod's requests, a client stuck in a loop
	// included.
	podAskEvery = 2 * time.Second
	// markTries bounds the writes of a pod's issued mark that its other
	// changes can overtake.
	markTries = 5
)

// TokenReviewer asks Kubernetes who a token belongs to.
type TokenReviewer interface {
	Review(ctx context.Context, token string, audiences []string) (authenticationv1.TokenReviewStatus, error)
}

// ClientTokenReviewer is the real TokenReviewer: a TokenReview create.
type ClientTokenReviewer struct{ Client client.Client }

// Review runs one TokenReview.
func (r ClientTokenReviewer) Review(ctx context.Context, token string, audiences []string) (authenticationv1.TokenReviewStatus, error) {
	tr := &authenticationv1.TokenReview{Spec: authenticationv1.TokenReviewSpec{Token: token, Audiences: audiences}}
	if err := r.Client.Create(ctx, tr); err != nil {
		return authenticationv1.TokenReviewStatus{}, err
	}
	return tr.Status, nil
}

// JoinGrant is what a joining pod gets: the join token and what the join
// needs with it.
type JoinGrant struct {
	Token      string    `json:"token"`
	CACertHash string    `json:"ca_cert_hash"`
	JoinURL    string    `json:"join_url"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// +kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews,verbs=create

// JoinIssuer answers JoinIssuePath on the operator's webhook server. Every
// replica serves it; what makes a token single per pod is the pod's
// annotation, written with the pod's resource version.
type JoinIssuer struct {
	// Client reads AerolNodes, AerolClusters and the admin Secret, and
	// marks pods.
	Client client.Client
	// Reader reads the pod past the cache: its UID must be the live one.
	Reader   client.Reader
	Reviewer TokenReviewer
	API      APIFactory
	// Namespace holds the AerolNodes, servers and gateways;
	// WorkerNamespace the worker pods.
	Namespace       string
	WorkerNamespace string
	Now             func() time.Time

	mu      sync.Mutex
	tokens  float64
	filled  time.Time
	lastAsk map[types.UID]time.Time
}

// refusal is an answer other than a token: its status tells the pod
// whether to ask again (429, 503) or stop (401, 403, 409).
type refusal struct {
	code int
	msg  string
	// counted refusals raise the identity-denial alert: a token Kubernetes
	// would not vouch for, or a pod that is not who or where it says.
	counted bool
}

func (r *refusal) Error() string { return r.msg }

func deny(code int, format string, args ...any) *refusal {
	return &refusal{code: code, msg: fmt.Sprintf(format, args...), counted: code == http.StatusUnauthorized || code == http.StatusForbidden}
}

func retry(format string, args ...any) *refusal {
	return &refusal{code: http.StatusServiceUnavailable, msg: fmt.Sprintf(format, args...)}
}

func (h *JoinIssuer) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *JoinIssuer) podNamespace(role string) string {
	if role == v1.RoleWorker && h.WorkerNamespace != "" {
		return h.WorkerNamespace
	}
	return h.Namespace
}

// ServeHTTP answers one joining pod.
func (h *JoinIssuer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	grant, pod, err := h.issue(ctx, req)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if err == nil {
		joinRequests.WithLabelValues("issued").Inc()
		log.FromContext(ctx).Info("join token issued", "pod", pod.Namespace+"/"+pod.Name, "expires", grant.ExpiresAt)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(grant)
		return
	}
	var rf *refusal
	if !errors.As(err, &rf) {
		rf = retry("%v", err)
	}
	result := "refused"
	switch rf.code {
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		result = "retry"
		w.Header().Set("Retry-After", "2")
	}
	joinRequests.WithLabelValues(result).Inc()
	if rf.counted {
		joinTokenErrors.Inc()
	}
	who := req.RemoteAddr
	if pod != nil {
		who = pod.Namespace + "/" + pod.Name
		if rf.counted {
			h.markRefused(ctx, pod, rf.msg)
		}
	}
	log.FromContext(ctx).Info("join token refused", "caller", who, "status", rf.code, "reason", rf.msg)
	w.WriteHeader(rf.code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": rf.msg})
}

// issue checks one request and makes its token. The pod it returns, when
// the token named one, is for the log and the refusal mark.
func (h *JoinIssuer) issue(ctx context.Context, req *http.Request) (JoinGrant, *corev1.Pod, error) {
	if req.Method != http.MethodPost {
		return JoinGrant{}, nil, deny(http.StatusMethodNotAllowed, "POST only")
	}
	now := h.now()
	if !h.allowReview(now) {
		return JoinGrant{}, nil, &refusal{code: http.StatusTooManyRequests, msg: "too many join requests at once; ask again"}
	}
	token, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	if !ok || strings.TrimSpace(token) == "" {
		return JoinGrant{}, nil, deny(http.StatusUnauthorized, "no bearer token: send the pod's projected ServiceAccount token (audience %s)", JoinAudience)
	}
	var body struct {
		Node string `json:"node"`
	}
	if err := json.NewDecoder(io.LimitReader(req.Body, 4096)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		return JoinGrant{}, nil, deny(http.StatusBadRequest, "the request body is not JSON: %v", err)
	}

	st, err := h.Reviewer.Review(ctx, strings.TrimSpace(token), []string{JoinAudience})
	if err != nil {
		return JoinGrant{}, nil, retry("TokenReview failed: %v", err)
	}
	if !st.Authenticated {
		why := st.Error
		if why == "" {
			why = "not authenticated"
		}
		return JoinGrant{}, nil, deny(http.StatusUnauthorized, "Kubernetes does not vouch for this token for audience %s: %s", JoinAudience, why)
	}
	if !slices.Contains(st.Audiences, JoinAudience) {
		return JoinGrant{}, nil, deny(http.StatusUnauthorized, "wrong audience %v: the token must be for %s", st.Audiences, JoinAudience)
	}
	ns, sa, ok := serviceAccount(st.User.Username)
	if !ok {
		return JoinGrant{}, nil, deny(http.StatusForbidden, "%q is not a service account", st.User.Username)
	}
	if ns != h.Namespace && ns != h.podNamespace(v1.RoleWorker) {
		return JoinGrant{}, nil, deny(http.StatusForbidden, "namespace %s holds no AerolVM node", ns)
	}
	podName, uid := oneClaim(st.User.Extra, claimPodName), oneClaim(st.User.Extra, claimPodUID)
	if podName == "" || uid == "" {
		return JoinGrant{}, nil, deny(http.StatusForbidden, "not a pod-bound token: it names no pod")
	}
	if !h.allowPod(types.UID(uid), now) {
		return JoinGrant{}, nil, &refusal{code: http.StatusTooManyRequests, msg: "this pod asked a moment ago; ask again in a few seconds"}
	}

	var pod corev1.Pod
	if err := h.Reader.Get(ctx, types.NamespacedName{Namespace: ns, Name: podName}, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			return JoinGrant{}, nil, deny(http.StatusForbidden, "pod %s/%s does not exist: the token is another pod's", ns, podName)
		}
		return JoinGrant{}, nil, retry("reading pod %s/%s: %v", ns, podName, err)
	}
	if string(pod.UID) != uid {
		return JoinGrant{}, nil, deny(http.StatusForbidden, "the token is another pod's: pod %s/%s is not the pod it was made for", ns, podName)
	}
	if want := podServiceAccount(&pod); want != sa {
		return JoinGrant{}, nil, deny(http.StatusForbidden, "the token is service account %s's; pod %s runs as %s", sa, podName, want)
	}
	nodeName := pod.Labels[LabelNode]
	if pod.Labels[LabelManagedBy] != "aerolvm-operator" || nodeName != pod.Name {
		return JoinGrant{}, nil, deny(http.StatusForbidden, "pod %s/%s is not an AerolVM node's", ns, podName)
	}
	if pod.DeletionTimestamp != nil {
		return JoinGrant{}, &pod, deny(http.StatusConflict, "pod %s is being deleted", podName)
	}
	if body.Node != "" && body.Node != nodeName {
		return JoinGrant{}, &pod, deny(http.StatusForbidden, "asked for node %s with pod %s's token", body.Node, podName)
	}
	var n v1.AerolNode
	if err := h.Client.Get(ctx, types.NamespacedName{Namespace: h.Namespace, Name: nodeName}, &n); err != nil {
		if apierrors.IsNotFound(err) {
			return JoinGrant{}, &pod, deny(http.StatusForbidden, "no AerolNode %s", nodeName)
		}
		return JoinGrant{}, &pod, retry("reading AerolNode %s: %v", nodeName, err)
	}
	if h.podNamespace(n.Spec.Role) != ns {
		return JoinGrant{}, &pod, deny(http.StatusForbidden, "a %s's pod does not run in namespace %s", n.Spec.Role, ns)
	}

	// D6: the pod runs on the machine it says. The kubelet asked for the
	// token on its own machine, and Kubernetes put that machine in it.
	if pod.Spec.NodeName == "" {
		return JoinGrant{}, &pod, retry("pod %s is not on a machine yet", podName)
	}
	machine := oneClaim(st.User.Extra, claimNodeName)
	if machine == "" {
		return JoinGrant{}, &pod, deny(http.StatusForbidden, "the token names no machine: TokenReview carries one from Kubernetes 1.30")
	}
	if machine != pod.Spec.NodeName {
		return JoinGrant{}, &pod, deny(http.StatusForbidden, "wrong machine: the token was made on %s, pod %s runs on %s", machine, podName, pod.Spec.NodeName)
	}
	if n.Status.NodeName != "" && n.Status.NodeName != pod.Spec.NodeName {
		return JoinGrant{}, &pod, deny(http.StatusForbidden, "wrong machine: AerolNode %s runs on %s, not %s", nodeName, n.Status.NodeName, pod.Spec.NodeName)
	}

	var c v1.AerolCluster
	if err := h.Client.Get(ctx, types.NamespacedName{Namespace: n.Namespace, Name: n.Spec.Cluster}, &c); err != nil {
		if apierrors.IsNotFound(err) {
			return JoinGrant{}, &pod, deny(http.StatusForbidden, "no AerolCluster %s", n.Spec.Cluster)
		}
		return JoinGrant{}, &pod, retry("reading AerolCluster %s: %v", n.Spec.Cluster, err)
	}
	switch {
	case externalCA(&c):
		return JoinGrant{}, &pod, deny(http.StatusConflict, "external-CA mode: a pod joins with its certificate, not a token")
	case n.Annotations[v1.AnnotationMaintenance] == "true" || pod.Labels[v1.AnnotationMaintenance] == "true":
		return JoinGrant{}, &pod, deny(http.StatusConflict, "a maintenance pod runs no setup and needs no token")
	case n.Spec.Role == v1.RoleServer && n.Name == ServerName(c.Name, 0) && !meta.IsStatusConditionTrue(c.Status.Conditions, CondBootstrapped):
		return JoinGrant{}, &pod, deny(http.StatusConflict, "server 0 starts the cluster with init and needs no token")
	case n.Status.State == v1.StateRemoved || n.Status.State == v1.StateDead:
		return JoinGrant{}, &pod, deny(http.StatusConflict, "AerolNode %s is %s", nodeName, n.Status.State)
	case joined(&n, pod.Name):
		return JoinGrant{}, &pod, deny(http.StatusConflict, "node %s already joined with this pod", nodeName)
	}
	// Mark the pod first, with its resource version: of two requests for
	// one pod (two replicas, or a retry), only one write lands. A starting
	// pod changes often (the kubelet writes its status), so a conflict
	// reads the pod again: a mark another request wrote in between wins,
	// anything else is tried again.
	var marked *corev1.Pod
	for try := 1; ; try++ {
		if at := pod.Annotations[AnnotationJoinIssued]; at != "" {
			if t, err := time.Parse(time.RFC3339, at); err == nil && now.Before(t.Add(joinTokenLife)) {
				return JoinGrant{}, &pod, deny(http.StatusConflict, "pod %s got its join token at %s; it is good until %s", podName, at, t.Add(joinTokenLife).Format(time.RFC3339))
			}
		}
		m := pod.DeepCopy()
		if m.Annotations == nil {
			m.Annotations = map[string]string{}
		}
		m.Annotations[AnnotationJoinIssued] = now.UTC().Format(time.RFC3339)
		delete(m.Annotations, AnnotationJoinRefused)
		err := h.Client.Patch(ctx, m, client.MergeFromWithOptions(&pod, client.MergeFromWithOptimisticLock{}))
		if err == nil {
			marked = m
			break
		}
		if !apierrors.IsConflict(err) {
			return JoinGrant{}, &pod, retry("marking pod %s: %v", podName, err)
		}
		if try == markTries {
			return JoinGrant{}, &pod, retry("pod %s kept changing while it was marked; ask again", podName)
		}
		var fresh corev1.Pod
		if err := h.Reader.Get(ctx, types.NamespacedName{Namespace: ns, Name: podName}, &fresh); err != nil {
			return JoinGrant{}, &pod, retry("reading pod %s again: %v", podName, err)
		}
		if fresh.UID != pod.UID {
			return JoinGrant{}, &pod, deny(http.StatusForbidden, "the token is another pod's: pod %s/%s was replaced", ns, podName)
		}
		pod = fresh
	}
	admin, err := adminToken(ctx, h.Client, &c)
	if err != nil {
		h.unmark(ctx, marked)
		return JoinGrant{}, marked, retry("reading the admin credential: %v", err)
	}
	tok, err := h.API(apiURL(&c), admin).MintJoinToken(ctx, sandboxdRole(n.Spec.Role), joinTokenLife.String(), "aerolvm-operator:"+n.Name)
	if err != nil {
		// Minting needs a Raft leader. The pod asks again; unmark it so
		// the next request is not refused as a second one.
		joinTokenErrors.Inc()
		h.unmark(ctx, marked)
		return JoinGrant{}, marked, retry("the servers made no join token: %v", err)
	}
	return JoinGrant{Token: tok.Token, CACertHash: tok.CACertHash, JoinURL: joinURL(&c, tok), ExpiresAt: now.Add(joinTokenLife)}, marked, nil
}

// joined says whether this pod already served as its node: a pod that
// joined has its identity on its disk and never asks again.
func joined(n *v1.AerolNode, pod string) bool {
	if n.Status.PodName != pod {
		return false
	}
	switch n.Status.State {
	case v1.StateServing, v1.StateDraining, v1.StateSuspect, v1.StateRestarting, v1.StateDecommissioning:
		return true
	}
	return false
}

// joinURL is the join listener the pod uses: the answering server's, else
// server 0's stable DNS name (servers advertise their DNS names, C4).
func joinURL(c *v1.AerolCluster, tok aerolapi.JoinToken) string {
	if len(tok.JoinURLs) > 0 {
		return tok.JoinURLs[0]
	}
	return fmt.Sprintf("https://%s:%d", ServerDNS(ServerName(c.Name, 0), c.Name, c.Namespace), JoinPort)
}

// unmark takes the issued mark off a pod whose token was not made.
func (h *JoinIssuer) unmark(ctx context.Context, pod *corev1.Pod) {
	base := pod.DeepCopy()
	delete(pod.Annotations, AnnotationJoinIssued)
	if err := h.Client.Patch(ctx, pod, client.MergeFrom(base)); err != nil {
		// The mark only holds the pod's next request until the token's
		// life ends.
		log.FromContext(ctx).Info("could not unmark pod", "pod", pod.Name, "error", err.Error())
	}
}

// markRefused records why the pod was refused, for its AerolNode's
// IdentityDenied condition.
func (h *JoinIssuer) markRefused(ctx context.Context, pod *corev1.Pod, why string) {
	if pod.Annotations[AnnotationJoinRefused] == why {
		return
	}
	base := pod.DeepCopy()
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[AnnotationJoinRefused] = why
	_ = h.Client.Patch(ctx, pod, client.MergeFrom(base))
}

// allowReview takes one request from the shared bucket.
func (h *JoinIssuer) allowReview(now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.filled.IsZero() {
		h.tokens, h.filled = reviewBurst, now
	}
	h.tokens = min(reviewBurst, h.tokens+now.Sub(h.filled).Seconds()*reviewsPerSecond)
	h.filled = now
	if h.tokens < 1 {
		return false
	}
	h.tokens--
	return true
}

// allowPod spaces one pod's requests, and forgets pods that stopped asking.
func (h *JoinIssuer) allowPod(uid types.UID, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lastAsk == nil {
		h.lastAsk = map[types.UID]time.Time{}
	}
	if last, ok := h.lastAsk[uid]; ok && now.Sub(last) < podAskEvery {
		return false
	}
	for k, t := range h.lastAsk {
		if now.Sub(t) > joinTokenLife {
			delete(h.lastAsk, k)
		}
	}
	h.lastAsk[uid] = now
	return true
}

// serviceAccount splits system:serviceaccount:<namespace>:<name>.
func serviceAccount(user string) (string, string, bool) {
	rest, ok := strings.CutPrefix(user, "system:serviceaccount:")
	if !ok {
		return "", "", false
	}
	ns, name, ok := strings.Cut(rest, ":")
	return ns, name, ok && ns != "" && name != ""
}

func podServiceAccount(p *corev1.Pod) string {
	if p.Spec.ServiceAccountName == "" {
		return "default"
	}
	return p.Spec.ServiceAccountName
}

func oneClaim(extra map[string]authenticationv1.ExtraValue, key string) string {
	if v := extra[key]; len(v) == 1 {
		return v[0]
	}
	return ""
}

// adminToken reads one cluster's admin token from its Secret.
func adminToken(ctx context.Context, r client.Reader, c *v1.AerolCluster) (string, error) {
	var s corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: AdminSecret(c.Name)}, &s); err != nil {
		return "", err
	}
	return string(s.Data["token"]), nil
}

// ReadJoinCA checks the CA a joining pod trusts the operator by: the
// webhook certificate's ca.crt, from the chart's CA issuer. It is public,
// so it rides in the pod spec; the first certificate is the one used.
func ReadJoinCA(raw []byte) ([]byte, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("the operator's ca.crt holds no PEM certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, fmt.Errorf("the operator's ca.crt: %w", err)
	}
	return pem.EncodeToMemory(block), nil
}

// identityDenied shows the operator's last refusal of the node's pod as its
// IdentityDenied condition. A token issued clears the pod's mark, and so
// the condition.
func identityDenied(n *v1.AerolNode, pod *corev1.Pod) {
	why := pod.Annotations[AnnotationJoinRefused]
	if why == "" || joined(n, pod.Name) {
		meta.RemoveStatusCondition(&n.Status.Conditions, CondIdentityDenied)
		return
	}
	meta.SetStatusCondition(&n.Status.Conditions, metav1.Condition{
		Type: CondIdentityDenied, Status: metav1.ConditionTrue, Reason: "Refused", Message: why,
	})
}
