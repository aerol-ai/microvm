package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
)

// fakeReviewer answers TokenReview as the API server does: a token it does
// not know, or one made for another audience, is not authenticated.
type fakeReviewer struct {
	tokens map[string]authenticationv1.TokenReviewStatus
	err    error
	calls  int
}

func (f *fakeReviewer) Review(_ context.Context, token string, audiences []string) (authenticationv1.TokenReviewStatus, error) {
	f.calls++
	if f.err != nil {
		return authenticationv1.TokenReviewStatus{}, f.err
	}
	st, ok := f.tokens[token]
	if !ok {
		return authenticationv1.TokenReviewStatus{Error: "invalid bearer token"}, nil
	}
	if !slices.Contains(st.Audiences, audiences[0]) {
		return authenticationv1.TokenReviewStatus{Error: "token audiences " + strings.Join(st.Audiences, ",") + " is invalid for the target audiences " + audiences[0]}, nil
	}
	return st, nil
}

// podToken is what TokenReview says of a pod's projected token made on
// machine.
func podToken(p *corev1.Pod, machine string) authenticationv1.TokenReviewStatus {
	return authenticationv1.TokenReviewStatus{
		Authenticated: true, Audiences: []string{JoinAudience},
		User: authenticationv1.UserInfo{Username: "system:serviceaccount:" + p.Namespace + ":default", Extra: map[string]authenticationv1.ExtraValue{
			claimPodName: {p.Name}, claimPodUID: {string(p.UID)}, claimNodeName: {machine},
		}},
	}
}

func joiningPod(name, ns, machine string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: types.UID("uid-" + name),
			Labels: map[string]string{LabelManagedBy: "aerolvm-operator", LabelNode: name, LabelCluster: "prod"}},
		Spec: corev1.PodSpec{NodeName: machine, ServiceAccountName: "default"},
	}
}

type issuerRig struct {
	t   *testing.T
	cl  client.WithWatch
	api *fakeAPI
	rev *fakeReviewer
	h   *JoinIssuer
	now time.Time
}

func newIssuerRig(t *testing.T, c *v1.AerolCluster, objs ...client.Object) *issuerRig {
	t.Helper()
	cl := newFakeClient(t, append([]client.Object{c, adminSecret()}, objs...)...).(client.WithWatch)
	g := &issuerRig{t: t, cl: cl, api: newFakeAPI(), rev: &fakeReviewer{tokens: map[string]authenticationv1.TokenReviewStatus{}}, now: time.Unix(2_000_000_000, 0)}
	g.h = &JoinIssuer{Client: cl, Reader: cl, Reviewer: g.rev, API: g.api.factory, Namespace: testNS, WorkerNamespace: testWorkerNS,
		Now: func() time.Time { return g.now }}
	return g
}

// ask sends one request and returns its status and answer.
func (g *issuerRig) ask(token, body string) (int, map[string]any) {
	g.t.Helper()
	req := httptest.NewRequest(http.MethodPost, JoinIssuePath, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	g.h.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Header().Get("Cache-Control") != "no-store" {
		g.t.Fatal("a join answer may be cached")
	}
	return w.Code, out
}

func (g *issuerRig) pod(ns, name string) *corev1.Pod {
	g.t.Helper()
	var p corev1.Pod
	if err := g.cl.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &p); err != nil {
		g.t.Fatal(err)
	}
	return &p
}

// Every refusal in the plan's identity list (§19: wrong machine, a token
// for another pod, wrong audience, a token asked for twice or after the
// pod joined), and the checks around them. Each is refused or told to ask
// again, never given a token.
func TestJoinIssuerRefusals(t *testing.T) {
	const wrk = "prod-general-aaaaa"
	type rig = issuerRig
	cases := []struct {
		name  string
		setup func(g *rig, p *corev1.Pod, n *v1.AerolNode) (token, body string)
		code  int
		want  string
		// alerts: the identity-denial alert's counter moves (§19).
		alerts bool
	}{
		{"no bearer token", func(g *rig, p *corev1.Pod, _ *v1.AerolNode) (string, string) { return "", "" },
			http.StatusUnauthorized, "no bearer token", true},
		{"a token Kubernetes does not know", func(g *rig, p *corev1.Pod, _ *v1.AerolNode) (string, string) { return "forged", "" },
			http.StatusUnauthorized, "invalid bearer token", true},
		{"wrong audience", func(g *rig, p *corev1.Pod, _ *v1.AerolNode) (string, string) {
			st := podToken(p, "m1")
			st.Audiences = []string{"https://kubernetes.default.svc"}
			g.rev.tokens["api-token"] = st
			return "api-token", ""
		}, http.StatusUnauthorized, "is invalid for the target audiences aerolvm.io/join", true},
		{"an answer for another audience", func(g *rig, p *corev1.Pod, _ *v1.AerolNode) (string, string) {
			g.h.Reviewer = reviewerFunc(func() authenticationv1.TokenReviewStatus {
				st := podToken(p, "m1")
				st.Audiences = []string{"other"}
				return st
			})
			return "t", ""
		}, http.StatusUnauthorized, "wrong audience", true},
		{"TokenReview down", func(g *rig, p *corev1.Pod, _ *v1.AerolNode) (string, string) {
			g.rev.err = errors.New("connection refused")
			return "t", ""
		}, http.StatusServiceUnavailable, "TokenReview failed", false},
		{"a person, not a service account", func(g *rig, p *corev1.Pod, _ *v1.AerolNode) (string, string) {
			st := podToken(p, "m1")
			st.User.Username = "alice"
			g.rev.tokens["t"] = st
			return "t", ""
		}, http.StatusForbidden, "not a service account", true},
		{"a pod in another namespace", func(g *rig, p *corev1.Pod, _ *v1.AerolNode) (string, string) {
			st := podToken(p, "m1")
			st.User.Username = "system:serviceaccount:default:default"
			g.rev.tokens["t"] = st
			return "t", ""
		}, http.StatusForbidden, "holds no AerolVM node", true},
		{"not pod-bound", func(g *rig, p *corev1.Pod, _ *v1.AerolNode) (string, string) {
			st := podToken(p, "m1")
			st.User.Extra = nil
			g.rev.tokens["t"] = st
			return "t", ""
		}, http.StatusForbidden, "not a pod-bound token", true},
		{"a pod that is gone", func(g *rig, p *corev1.Pod, _ *v1.AerolNode) (string, string) {
			st := podToken(p, "m1")
			st.User.Extra[claimPodName] = authenticationv1.ExtraValue{"prod-general-zzzzz"}
			g.rev.tokens["t"] = st
			return "t", ""
		}, http.StatusForbidden, "does not exist: the token is another pod's", true},
		{"a token for another pod (an old pod by the same name)", func(g *rig, p *corev1.Pod, _ *v1.AerolNode) (string, string) {
			st := podToken(p, "m1")
			st.User.Extra[claimPodUID] = authenticationv1.ExtraValue{"uid-of-the-pod-before"}
			g.rev.tokens["t"] = st
			return "t", ""
		}, http.StatusForbidden, "the token is another pod's", true},
		{"another service account", func(g *rig, p *corev1.Pod, _ *v1.AerolNode) (string, string) {
			st := podToken(p, "m1")
			st.User.Username = "system:serviceaccount:" + testWorkerNS + ":builder"
			g.rev.tokens["t"] = st
			return "t", ""
		}, http.StatusForbidden, "service account builder", true},
		{"a pod the operator did not make", func(g *rig, p *corev1.Pod, _ *v1.AerolNode) (string, string) {
			p.Labels = nil
			mustUpdate(g, p)
			g.rev.tokens["t"] = podToken(p, "m1")
			return "t", ""
		}, http.StatusForbidden, "is not an AerolVM node's", true},
		{"asks for another node", func(g *rig, p *corev1.Pod, _ *v1.AerolNode) (string, string) {
			g.rev.tokens["t"] = podToken(p, "m1")
			return "t", `{"node":"prod-server-1"}`
		}, http.StatusForbidden, "asked for node prod-server-1", true},
		{"not JSON", func(g *rig, p *corev1.Pod, _ *v1.AerolNode) (string, string) {
			g.rev.tokens["t"] = podToken(p, "m1")
			return "t", `{`
		}, http.StatusBadRequest, "not JSON", false},
		{"no AerolNode", func(g *rig, p *corev1.Pod, n *v1.AerolNode) (string, string) {
			if err := g.cl.Delete(context.Background(), n); err != nil {
				g.t.Fatal(err)
			}
			g.rev.tokens["t"] = podToken(p, "m1")
			return "t", ""
		}, http.StatusForbidden, "no AerolNode", true},
		{"not on a machine yet", func(g *rig, p *corev1.Pod, _ *v1.AerolNode) (string, string) {
			p.Spec.NodeName = ""
			mustUpdate(g, p)
			g.rev.tokens["t"] = podToken(p, "m1")
			return "t", ""
		}, http.StatusServiceUnavailable, "not on a machine yet", false},
		{"a token that names no machine (Kubernetes before 1.30)", func(g *rig, p *corev1.Pod, _ *v1.AerolNode) (string, string) {
			st := podToken(p, "m1")
			delete(st.User.Extra, claimNodeName)
			g.rev.tokens["t"] = st
			return "t", ""
		}, http.StatusForbidden, "names no machine", true},
		{"wrong machine", func(g *rig, p *corev1.Pod, _ *v1.AerolNode) (string, string) {
			g.rev.tokens["t"] = podToken(p, "m2")
			return "t", ""
		}, http.StatusForbidden, "wrong machine: the token was made on m2", true},
		{"wrong machine for its AerolNode", func(g *rig, p *corev1.Pod, n *v1.AerolNode) (string, string) {
			n.Status.NodeName = "m9"
			if err := g.cl.Status().Update(context.Background(), n); err != nil {
				g.t.Fatal(err)
			}
			g.rev.tokens["t"] = podToken(p, "m1")
			return "t", ""
		}, http.StatusForbidden, "AerolNode prod-general-aaaaa runs on m9", true},
		{"already joined", func(g *rig, p *corev1.Pod, n *v1.AerolNode) (string, string) {
			n.Status.PodName, n.Status.State = p.Name, v1.StateServing
			if err := g.cl.Status().Update(context.Background(), n); err != nil {
				g.t.Fatal(err)
			}
			g.rev.tokens["t"] = podToken(p, "m1")
			return "t", ""
		}, http.StatusConflict, "already joined", false},
		{"a removed node", func(g *rig, p *corev1.Pod, n *v1.AerolNode) (string, string) {
			n.Status.State = v1.StateRemoved
			if err := g.cl.Status().Update(context.Background(), n); err != nil {
				g.t.Fatal(err)
			}
			g.rev.tokens["t"] = podToken(p, "m1")
			return "t", ""
		}, http.StatusConflict, "is Removed", false},
		{"asked twice inside the token's life", func(g *rig, p *corev1.Pod, _ *v1.AerolNode) (string, string) {
			p.Annotations = map[string]string{AnnotationJoinIssued: g.now.Add(-5 * time.Minute).UTC().Format(time.RFC3339)}
			mustUpdate(g, p)
			g.rev.tokens["t"] = podToken(p, "m1")
			return "t", ""
		}, http.StatusConflict, "got its join token at", false},
		{"a pod being deleted", func(g *rig, p *corev1.Pod, _ *v1.AerolNode) (string, string) {
			p.Finalizers = []string{"test"}
			mustUpdate(g, p)
			if err := g.cl.Delete(context.Background(), p); err != nil {
				g.t.Fatal(err)
			}
			g.rev.tokens["t"] = podToken(g.pod(p.Namespace, p.Name), "m1")
			return "t", ""
		}, http.StatusConflict, "being deleted", false},
		{"no leader to make the token", func(g *rig, p *corev1.Pod, _ *v1.AerolNode) (string, string) {
			g.api.mintErr = errors.New("no leader")
			g.rev.tokens["t"] = podToken(p, "m1")
			return "t", ""
		}, http.StatusServiceUnavailable, "made no join token: no leader", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := joiningPod(wrk, testWorkerNS, "m1")
			n := node(wrk, v1.RoleWorker, "general", "z-a")
			g := newIssuerRig(t, bootstrapped(testCluster()), p, n)
			token, body := tc.setup(g, g.pod(testWorkerNS, wrk), n)
			before := testutilCounter(joinTokenErrors)
			code, out := g.ask(token, body)
			if code != tc.code || !strings.Contains(out["error"].(string), tc.want) {
				t.Fatalf("got %d %v, want %d with %q", code, out, tc.code, tc.want)
			}
			if out["token"] != nil || (len(g.api.minted) != 0 && tc.code != http.StatusOK) {
				t.Fatalf("a token in a refusal: %v minted %v", out, g.api.minted)
			}
			if got := testutilCounter(joinTokenErrors) - before; (got == 1) != tc.alerts {
				t.Fatalf("identity-denial counter moved by %v, want alerts=%v", got, tc.alerts)
			}
		})
	}
}

// The pod gets one token, made for its role, and good for ten minutes; it
// is marked, so a second request (another replica, a retry) is refused,
// until the token's life is over and the pod has still not joined.
func TestJoinIssuerIssuesOneTokenPerPod(t *testing.T) {
	c := bootstrapped(testCluster())
	srv := joiningPod("prod-server-1", testNS, "m3")
	wrk := joiningPod("prod-general-aaaaa", testWorkerNS, "m1")
	g := newIssuerRig(t, c, srv, wrk, node("prod-server-1", v1.RoleServer, "", "z-b"), node("prod-general-aaaaa", v1.RoleWorker, "general", "z-a"))
	g.rev.tokens["srv"], g.rev.tokens["wrk"] = podToken(srv, "m3"), podToken(wrk, "m1")

	code, out := g.ask("wrk", `{"node":"prod-general-aaaaa"}`)
	if code != http.StatusOK || out["token"] != "tok-worker" || out["ca_cert_hash"] != "sha256:abc" || out["join_url"] != "https://s0:7003" {
		t.Fatalf("worker: %d %v", code, out)
	}
	if exp, _ := time.Parse(time.RFC3339, out["expires_at"].(string)); !exp.Equal(g.now.Add(10 * time.Minute)) {
		t.Fatalf("expires %v, want ten minutes", out["expires_at"])
	}
	if len(g.api.minted) != 1 || g.api.minted[0] != "worker:aerolvm-operator:prod-general-aaaaa" {
		t.Fatalf("minted %v", g.api.minted)
	}
	if at := g.pod(testWorkerNS, wrk.Name).Annotations[AnnotationJoinIssued]; at != g.now.UTC().Format(time.RFC3339) {
		t.Fatalf("pod mark %q", at)
	}
	code, out = g.ask("srv", "")
	if code != http.StatusOK || out["token"] != "tok-server" {
		t.Fatalf("server: %d %v", code, out)
	}

	// Again a moment later: spaced; a little later: refused, already given.
	g.now = g.now.Add(time.Second)
	if code, _ := g.ask("wrk", ""); code != http.StatusTooManyRequests {
		t.Fatalf("a second request a second later: %d", code)
	}
	g.now = g.now.Add(5 * time.Second)
	if code, out := g.ask("wrk", ""); code != http.StatusConflict || !strings.Contains(out["error"].(string), "got its join token") {
		t.Fatalf("a second token for one pod: %d %v", code, out)
	}
	// Its token expired and it never joined (a slow image, a failed join):
	// it may ask for a fresh one.
	g.now = g.now.Add(10 * time.Minute)
	if code, _ := g.ask("wrk", ""); code != http.StatusOK || len(g.api.minted) != 3 {
		t.Fatalf("after the token's life: %d minted %v", code, g.api.minted)
	}
}

// Two requests for one pod at once, answered by two replicas: the pod's
// mark is written with its resource version, so only one gets a token.
func TestJoinIssuerOneWinnerOfARace(t *testing.T) {
	p := joiningPod("prod-general-aaaaa", testWorkerNS, "m1")
	g := newIssuerRig(t, bootstrapped(testCluster()), p, node(p.Name, v1.RoleWorker, "general", "z-a"))
	g.rev.tokens["t"] = podToken(p, "m1")
	g.h.Client = interceptor.NewClient(g.cl, interceptor.Funcs{
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			return apierrors.NewConflict(schema.GroupResource{Resource: "pods"}, obj.GetName(), errors.New("the object has been modified"))
		},
	})
	if code, out := g.ask("t", ""); code != http.StatusConflict || !strings.Contains(out["error"].(string), "answered first") || len(g.api.minted) != 0 {
		t.Fatalf("the race's loser: %d %v minted %v", code, out, g.api.minted)
	}
}

// A token the servers could not make leaves no mark, so the pod's next
// request is answered.
func TestJoinIssuerUnmarksWhenNoTokenWasMade(t *testing.T) {
	p := joiningPod("prod-general-aaaaa", testWorkerNS, "m1")
	g := newIssuerRig(t, bootstrapped(testCluster()), p, node(p.Name, v1.RoleWorker, "general", "z-a"))
	g.rev.tokens["t"] = podToken(p, "m1")
	g.api.mintErr = errors.New("no leader")
	if code, _ := g.ask("t", ""); code != http.StatusServiceUnavailable {
		t.Fatalf("no leader: %d", code)
	}
	if at := g.pod(testWorkerNS, p.Name).Annotations[AnnotationJoinIssued]; at != "" {
		t.Fatalf("pod still marked %q with no token made", at)
	}
	g.api.mintErr = nil
	g.now = g.now.Add(3 * time.Second)
	if code, _ := g.ask("t", ""); code != http.StatusOK {
		t.Fatalf("once a leader is back: %d", code)
	}
}

// Pods with no token to ask for: external-CA mode, a maintenance pod and
// server 0 of a new cluster.
func TestJoinIssuerPodsThatNeedNoToken(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    *v1.AerolCluster
		node *v1.AerolNode
		ns   string
		want string
	}{
		{"external-CA mode", bootstrapped(externalCACluster()), node("prod-general-aaaaa", v1.RoleWorker, "general", "z-a"), testWorkerNS, "external-CA mode"},
		{"maintenance", bootstrapped(testCluster()), func() *v1.AerolNode {
			n := node("prod-server-1", v1.RoleServer, "", "z-b")
			n.Annotations = map[string]string{v1.AnnotationMaintenance: "true"}
			return n
		}(), testNS, "maintenance pod"},
		{"server 0 of a new cluster", testCluster(), node("prod-server-0", v1.RoleServer, "", "z-a"), testNS, "server 0 starts the cluster"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := joiningPod(tc.node.Name, tc.ns, "m1")
			g := newIssuerRig(t, tc.c, p, tc.node)
			g.rev.tokens["t"] = podToken(p, "m1")
			if code, out := g.ask("t", ""); code != http.StatusConflict || !strings.Contains(out["error"].(string), tc.want) || len(g.api.minted) != 0 {
				t.Fatalf("%d %v minted %v", code, out, g.api.minted)
			}
		})
	}
}

// The endpoint is reachable by any pod in the cluster: requests to
// TokenReview are spaced, and only a POST is answered.
func TestJoinIssuerLimits(t *testing.T) {
	g := newIssuerRig(t, bootstrapped(testCluster()))
	req := httptest.NewRequest(http.MethodGet, JoinIssuePath, nil)
	w := httptest.NewRecorder()
	g.h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", w.Code)
	}
	busy := 0
	for range reviewBurst + 10 {
		if code, _ := g.ask("forged", ""); code == http.StatusTooManyRequests {
			busy++
		}
	}
	if busy != 10 || g.rev.calls != reviewBurst {
		t.Fatalf("%d told to wait, %d reviews; want 10 and %d", busy, g.rev.calls, reviewBurst)
	}
	if w := httptest.NewRecorder(); true {
		g.h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, JoinIssuePath, nil))
		if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
			t.Fatalf("busy: %d, Retry-After %q", w.Code, w.Header().Get("Retry-After"))
		}
	}
	// The bucket fills again with time.
	g.now = g.now.Add(time.Second)
	if code, _ := g.ask("forged", ""); code != http.StatusUnauthorized {
		t.Fatalf("a second later: %d", code)
	}
	// A pod that stopped asking is forgotten.
	g.h.lastAsk = map[types.UID]time.Time{"old": g.now.Add(-time.Hour)}
	if !g.h.allowPod("new", g.now) || len(g.h.lastAsk) != 1 {
		t.Fatalf("pods remembered: %v", g.h.lastAsk)
	}
}

// A refused pod's AerolNode shows why, as IdentityDenied (the runbook's
// AerolVMJoinTokenErrors step), until a token is issued.
func TestJoinRefusalShowsOnTheNode(t *testing.T) {
	c := bootstrapped(testCluster())
	n := node("prod-general-aaaaa", v1.RoleWorker, "general", "z-a")
	g := newNodeRig(t, c, n, machine("m1"))
	g.reconcile(n.Name)
	p := g.pod(testWorkerNS, n.Name)
	p.Spec.NodeName = "m1"
	p.UID = "uid-a" // the fake client gives none
	if err := g.cl.Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	p = g.pod(testWorkerNS, n.Name)

	h := &JoinIssuer{Client: g.cl, Reader: g.cl, API: g.api.factory, Namespace: testNS, WorkerNamespace: testWorkerNS,
		Reviewer: reviewerFunc(func() authenticationv1.TokenReviewStatus { return podToken(p, "m2") })}
	req := httptest.NewRequest(http.MethodPost, JoinIssuePath, nil)
	req.Header.Set("Authorization", "Bearer t")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("wrong machine: %d", w.Code)
	}
	if why := g.pod(testWorkerNS, n.Name).Annotations[AnnotationJoinRefused]; !strings.Contains(why, "wrong machine") {
		t.Fatalf("refusal mark %q", why)
	}
	g.reconcile(n.Name)
	cond := meta.FindStatusCondition(g.node(n.Name).Status.Conditions, CondIdentityDenied)
	if cond == nil || cond.Status != metav1.ConditionTrue || !strings.Contains(cond.Message, "wrong machine") {
		t.Fatalf("IdentityDenied = %+v", cond)
	}

	// The right machine: a token, the mark and the condition gone.
	h.Reviewer = reviewerFunc(func() authenticationv1.TokenReviewStatus { return podToken(p, "m1") })
	h.Now = func() time.Time { return time.Now().Add(time.Minute) }
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("right machine: %d %s", w.Code, w.Body)
	}
	g.reconcile(n.Name)
	if cond := meta.FindStatusCondition(g.node(n.Name).Status.Conditions, CondIdentityDenied); cond != nil {
		t.Fatalf("IdentityDenied after a token: %+v", cond)
	}
}

func TestReadJoinCA(t *testing.T) {
	if got, err := ReadJoinCA(append(append([]byte{}, testJoinCA...), testJoinCA...)); err != nil || string(got) != string(testJoinCA) {
		t.Fatalf("ReadJoinCA = %q, %v", got, err)
	}
	for _, raw := range []string{"", "not pem", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"} {
		if _, err := ReadJoinCA([]byte(raw)); err == nil {
			t.Fatalf("%q accepted", raw)
		}
	}
	if _, _, ok := serviceAccount("system:serviceaccount:ns"); ok {
		t.Fatal("a service account with no name")
	}
}

type reviewerFunc func() authenticationv1.TokenReviewStatus

func (f reviewerFunc) Review(context.Context, string, []string) (authenticationv1.TokenReviewStatus, error) {
	return f(), nil
}

func mustUpdate(g *issuerRig, p *corev1.Pod) {
	g.t.Helper()
	if err := g.cl.Update(context.Background(), p); err != nil {
		g.t.Fatal(err)
	}
}

// The real reviewer is a TokenReview create, whose answer is its status.
func TestClientTokenReviewer(t *testing.T) {
	var asked authenticationv1.TokenReviewSpec
	cl := interceptor.NewClient(newFakeClient(t).(client.WithWatch), interceptor.Funcs{
		Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
			tr := obj.(*authenticationv1.TokenReview)
			asked = tr.Spec
			tr.Status = authenticationv1.TokenReviewStatus{Authenticated: true, Audiences: tr.Spec.Audiences}
			return nil
		},
	})
	st, err := ClientTokenReviewer{Client: cl}.Review(context.Background(), "tok", []string{JoinAudience})
	if err != nil || !st.Authenticated || asked.Token != "tok" || asked.Audiences[0] != JoinAudience {
		t.Fatalf("review = %+v %v, asked %+v", st, err, asked)
	}
	failing := interceptor.NewClient(newFakeClient(t).(client.WithWatch), interceptor.Funcs{
		Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
			return errors.New("forbidden")
		},
	})
	if _, err := (ClientTokenReviewer{Client: failing}).Review(context.Background(), "tok", nil); err == nil {
		t.Fatal("a failed TokenReview returned no error")
	}
	if (&refusal{msg: "why"}).Error() != "why" {
		t.Fatal("refusal text")
	}
}
