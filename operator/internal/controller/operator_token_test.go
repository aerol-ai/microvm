package controller

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/yaml"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
	"github.com/aerol-ai/microvm/operator/internal/aerolapi"
)

// hostScopedTemplates is the chart's templates with enterprise mode's
// SB_PAT_SCOPE=host (and env) on the server.
func hostScopedTemplates(t *testing.T, env ...corev1.EnvVar) *corev1.ConfigMap {
	t.Helper()
	cm := templates(t)
	tpl, err := ParsePodTemplate(cm.Data[TemplateServer])
	if err != nil {
		t.Fatal(err)
	}
	i := containerIndex(tpl.Spec.Containers, AgentContainer)
	tpl.Spec.Containers[i].Env = append(tpl.Spec.Containers[i].Env, append([]corev1.EnvVar{{Name: "SB_PAT_SCOPE", Value: "host"}}, env...)...)
	raw, err := yaml.Marshal(tpl)
	if err != nil {
		t.Fatal(err)
	}
	cm.Data[TemplateServer] = string(raw)
	return cm
}

func serverPod(name string, ready bool) *corev1.Pod {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNS,
			Labels: map[string]string{LabelCluster: "prod", LabelComponent: v1.RoleServer}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: status}}},
	}
}

// hostServerPod is a server pod made from the enterprise template: its agent
// takes the admin token only from inside the pod.
func hostServerPod(name string, ready bool) *corev1.Pod {
	p := serverPod(name, ready)
	p.Spec.Containers = []corev1.Container{{Name: AgentContainer, Env: []corev1.EnvVar{{Name: "SB_PAT_SCOPE", Value: "host"}}}}
	return p
}

// forwardRig records each port-forward the reconciler opens.
type forwardRig struct {
	opened  []string
	stopped int
	err     error
}

func (f *forwardRig) forward(_ context.Context, ns, pod string, port int) (string, func(), error) {
	if f.err != nil {
		return "", nil, f.err
	}
	f.opened = append(f.opened, ns+"/"+pod+":"+strconv.Itoa(port))
	return "http://127.0.0.1:40000", func() { f.stopped++ }, nil
}

func tokenRig(t *testing.T, c *v1.AerolCluster, objs ...client.Object) (*ClusterReconciler, *fakeAPI, *forwardRig, client.Client, *time.Time) {
	t.Helper()
	r, api, cl := clusterRig(t, c, objs...)
	r.Templates = "aerolvm-pod-templates"
	fw := &forwardRig{}
	r.Forward = fw.forward
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	r.Now = func() time.Time { return now }
	api.tokNow = r.Now
	return r, api, fw, cl, &now
}

func readTokenSecret(t *testing.T, cl client.Client) map[string]string {
	t.Helper()
	var s corev1.Secret
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: "prod-operator-token"}, &s); err != nil {
		t.Fatalf("operator token secret: %v", err)
	}
	out := map[string]string{}
	for k, v := range s.Data {
		out[k] = string(v)
	}
	return out
}

func (f *fakeAPI) calls(op string) []tokenCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []tokenCall
	for _, c := range f.tokenCalls {
		if c.op == op {
			out = append(out, c)
		}
	}
	return out
}

// lastClient is the credential the last client for the API Service was made
// with: the one the reconcile's own calls used.
func (f *fakeAPI) lastServiceCred(t *testing.T) Credentials {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.clients) - 1; i >= 0; i-- {
		if strings.HasPrefix(f.clients[i].base, "http://prod-api.") {
			return f.clients[i].cred
		}
	}
	t.Fatal("no API Service client was made")
	return Credentials{}
}

// Without SB_PAT_SCOPE=host on the servers nothing changes: no token, no
// port-forward, the admin token on every call.
func TestOperatorTokenOnlyForHostScopedServers(t *testing.T) {
	r, api, fw, cl, _ := tokenRig(t, testCluster(), adminSecret(), templates(t), serverPod("prod-server-0", true))
	reconcileCluster(t, r)
	if len(fw.opened) != 0 || len(api.calls("create")) != 0 {
		t.Fatalf("forwards %v, creates %v", fw.opened, api.calls("create"))
	}
	var s corev1.Secret
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: "prod-operator-token"}, &s); err == nil {
		t.Fatal("made an operator token Secret")
	}
	if got := api.lastServiceCred(t); got != (Credentials{Token: "admin-token"}) {
		t.Fatalf("calls carry %+v, want the admin token alone", got)
	}
}

// Enterprise mode's bootstrap: the first token through a port-forward to a
// Ready server, made with the admin token; every call after it, adopt
// included, carries it with the admin token as the fallback.
func TestOperatorTokenBootstrap(t *testing.T) {
	r, api, fw, cl, now := tokenRig(t, testCluster(), adminSecret(), hostScopedTemplates(t),
		serverPod("prod-server-0", false), serverPod("prod-server-1", true), serverPod("prod-server-2", true))
	c := reconcileCluster(t, r)
	if len(fw.opened) != 1 || fw.opened[0] != testNS+"/prod-server-1:21212" || fw.stopped != 1 {
		t.Fatalf("forwards %v (stopped %d), want one to the Ready server's API port, closed", fw.opened, fw.stopped)
	}
	creates := api.calls("create")
	if len(creates) != 1 || creates[0].base != "http://127.0.0.1:40000" || creates[0].cred != (Credentials{Token: "admin-token"}) ||
		creates[0].expiresIn != "720h0m0s" || !strings.HasPrefix(creates[0].name, "aerolvm-operator-") {
		t.Fatalf("creates = %+v", creates)
	}
	sec := readTokenSecret(t, cl)
	if sec["token"] != "avm_secret_1" || sec["id"] != "tok_1" || sec["created_at"] != now.Format(time.RFC3339) ||
		sec["expires_at"] != now.Add(30*24*time.Hour).Format(time.RFC3339) || sec["previous_id"] != "" {
		t.Fatalf("secret = %v", sec)
	}
	if got := api.lastServiceCred(t); got != (Credentials{Token: "avm_secret_1", Fallback: "admin-token"}) {
		t.Fatalf("adopt carried %+v", got)
	}
	if api.adopted != 1 || !conditionTrue(c, CondBootstrapped) {
		t.Fatalf("adopted %d", api.adopted)
	}
	// Held and taken: checked, not made again.
	reconcileCluster(t, r)
	if len(api.calls("create")) != 1 || len(api.calls("whoami")) != 1 || len(fw.opened) != 1 {
		t.Fatalf("second pass: creates %d, whoami %d, forwards %d", len(api.calls("create")), len(api.calls("whoami")), len(fw.opened))
	}
}

func conditionTrue(c *v1.AerolCluster, cond string) bool {
	for _, x := range c.Status.Conditions {
		if x.Type == cond {
			return x.Status == metav1.ConditionTrue
		}
	}
	return false
}

// The servers' token cap shortens the token; no Ready server yet waits
// (calls keep the admin token, the reconcile does not fail); a port-forward
// that fails waits too.
func TestOperatorTokenWaitsAndCaps(t *testing.T) {
	r, api, fw, cl, _ := tokenRig(t, testCluster(), adminSecret(),
		hostScopedTemplates(t, corev1.EnvVar{Name: "SB_TOKEN_MAX_TTL", Value: "24h"}), serverPod("prod-server-0", false))
	reconcileCluster(t, r)
	if len(fw.opened) != 0 || len(api.calls("create")) != 0 {
		t.Fatalf("made a token with no Ready server: %v %v", fw.opened, api.calls("create"))
	}
	if got := api.lastServiceCred(t); got != (Credentials{Token: "admin-token"}) {
		t.Fatalf("calls carry %+v", got)
	}
	var pod corev1.Pod
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: "prod-server-0"}, &pod); err != nil {
		t.Fatal(err)
	}
	pod.Status.Conditions[0].Status = corev1.ConditionTrue
	if err := cl.Status().Update(context.Background(), &pod); err != nil {
		if err := cl.Update(context.Background(), &pod); err != nil {
			t.Fatal(err)
		}
	}
	fw.err = errors.New("kubelet unreachable")
	reconcileCluster(t, r)
	if len(api.calls("create")) != 0 {
		t.Fatal("made a token without a port-forward")
	}
	fw.err = nil
	reconcileCluster(t, r)
	if creates := api.calls("create"); len(creates) != 1 || creates[0].expiresIn != "24h0m0s" {
		t.Fatalf("creates = %+v, want one capped at 24h", creates)
	}
	// No forwarder at all (an operator built without one): an error, said.
	r2, _, _, _, _ := tokenRig(t, testCluster(), adminSecret(), hostScopedTemplates(t), serverPod("prod-server-0", true))
	r2.Forward = nil
	if _, err := r2.ensureOperatorToken(context.Background(), testCluster()); err == nil || !strings.Contains(err.Error(), "cannot port-forward") {
		t.Fatalf("err = %v", err)
	}
}

func tokenSecret(token, id string, created, expires time.Time, extra ...string) *corev1.Secret {
	data := map[string][]byte{"token": []byte(token), "id": []byte(id),
		"created_at": []byte(created.Format(time.RFC3339)), "expires_at": []byte(expires.Format(time.RFC3339))}
	for i := 0; i+1 < len(extra); i += 2 {
		data[extra[i]] = []byte(extra[i+1])
	}
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "prod-operator-token", Namespace: testNS}, Data: data}
}

// Before a third of its life is left the token is replaced, with itself,
// over the API Service; the old one keeps working five minutes, then is
// revoked with the new one.
func TestOperatorTokenRotation(t *testing.T) {
	start := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	old := tokenSecret("avm_old", "tok_old", start.Add(-21*24*time.Hour), start.Add(9*24*time.Hour))
	r, api, fw, cl, now := tokenRig(t, bootstrapped(testCluster()), adminSecret(), hostScopedTemplates(t), hostServerPod("prod-server-0", true), old)
	reconcileCluster(t, r)
	creates := api.calls("create")
	if len(fw.opened) != 0 || len(creates) != 1 || !strings.HasPrefix(creates[0].base, "http://prod-api.") ||
		creates[0].cred != (Credentials{Token: "avm_old"}) {
		t.Fatalf("forwards %v, creates %+v: want one over the Service with the current token", fw.opened, creates)
	}
	sec := readTokenSecret(t, cl)
	if sec["token"] != "avm_secret_1" || sec["previous_id"] != "tok_old" || sec["previous_revoke_at"] != now.Add(5*time.Minute).Format(time.RFC3339) {
		t.Fatalf("secret = %v", sec)
	}
	if len(api.calls("revoke")) != 0 {
		t.Fatal("revoked the old token at once")
	}
	*now = now.Add(4 * time.Minute)
	reconcileCluster(t, r)
	if len(api.calls("revoke")) != 0 {
		t.Fatal("revoked the old token inside its five minutes")
	}
	*now = now.Add(2 * time.Minute)
	reconcileCluster(t, r)
	revokes := api.calls("revoke")
	if len(revokes) != 1 || revokes[0].id != "tok_old" || revokes[0].cred != (Credentials{Token: "avm_secret_1"}) {
		t.Fatalf("revokes = %+v", revokes)
	}
	if sec := readTokenSecret(t, cl); sec["previous_id"] != "" || sec["previous_revoke_at"] != "" || sec["token"] != "avm_secret_1" {
		t.Fatalf("secret after the revoke = %v", sec)
	}
	// A revoke that fails is tried again on the next pass.
	*now = now.Add(20 * 24 * time.Hour)
	reconcileCluster(t, r) // replaced again: tok_2, tok_1 to revoke
	api.revokeErr = &aerolapi.Error{Status: http.StatusServiceUnavailable, Reason: "no leader"}
	*now = now.Add(6 * time.Minute)
	reconcileCluster(t, r)
	if sec := readTokenSecret(t, cl); sec["previous_id"] != "tok_1" {
		t.Fatalf("a failed revoke dropped the id: %v", sec)
	}
	api.revokeErr = nil
	reconcileCluster(t, r)
	if sec := readTokenSecret(t, cl); sec["previous_id"] != "" {
		t.Fatalf("the retried revoke left %v", sec)
	}
}

// The servers refuse the token (revoked by hand, or a restored cluster that
// never had it): once it has had time to reach them, a new one is made
// through the port-forward, and the refused one goes after the wait. A
// replacement the servers refuse goes the same way. An expired token, or a
// Secret with times that do not parse, is made again at once.
func TestOperatorTokenRefusedOrExpired(t *testing.T) {
	start := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	fresh := tokenSecret("avm_cur", "tok_cur", start.Add(-time.Minute), start.Add(29*24*time.Hour))
	// The servers run the template's settings (an old server's refusal is
	// no verdict: TestOperatorTokenNotReplacedOnAnOldServersWord).
	r, api, fw, cl, now := tokenRig(t, bootstrapped(testCluster()), adminSecret(), hostScopedTemplates(t), hostServerPod("prod-server-0", true), fresh)
	api.whoami = func(c Credentials) error {
		if c.Token == "avm_cur" {
			return &aerolapi.Error{Status: http.StatusUnauthorized, Reason: "unauthorized"}
		}
		return nil
	}
	reconcileCluster(t, r)
	if len(fw.opened) != 0 {
		t.Fatal("made a new token for one a minute old")
	}
	*now = now.Add(2 * time.Minute)
	reconcileCluster(t, r)
	if len(fw.opened) != 1 || len(api.calls("create")) != 1 {
		t.Fatalf("forwards %v, creates %v", fw.opened, api.calls("create"))
	}
	if sec := readTokenSecret(t, cl); sec["token"] != "avm_secret_1" || sec["previous_id"] != "tok_cur" {
		t.Fatalf("secret = %v", sec)
	}

	// A rotation the servers refuse: through the port-forward.
	rot := tokenSecret("avm_cur", "tok_cur", start.Add(-25*24*time.Hour), start.Add(5*24*time.Hour))
	r, api, fw, _, _ = tokenRig(t, bootstrapped(testCluster()), adminSecret(), hostScopedTemplates(t), serverPod("prod-server-0", true), rot)
	api.createErr = &aerolapi.Error{Status: http.StatusUnauthorized, Reason: "unauthorized"}
	if _, err := r.ensureOperatorToken(context.Background(), bootstrapped(testCluster())); err == nil {
		t.Fatal("a refused port-forward create reported success")
	}
	if len(fw.opened) != 1 {
		t.Fatalf("a refused rotation did not go through the port-forward: %v", fw.opened)
	}
	api.createErr = &aerolapi.Error{Status: http.StatusServiceUnavailable, Reason: "no leader"}
	if _, err := r.ensureOperatorToken(context.Background(), bootstrapped(testCluster())); err == nil ||
		len(fw.opened) != 1 || !strings.Contains(err.Error(), "replace the operator's API token") {
		t.Fatalf("a rotation that failed otherwise: %v, forwards %v", err, fw.opened)
	}

	for name, sec := range map[string]*corev1.Secret{
		"expired":   tokenSecret("avm_cur", "tok_cur", start.Add(-31*24*time.Hour), start.Add(-time.Hour)),
		"bad times": {ObjectMeta: metav1.ObjectMeta{Name: "prod-operator-token", Namespace: testNS}, Data: map[string][]byte{"token": []byte("avm_cur"), "expires_at": []byte("soon")}},
	} {
		r, api, fw, cl, _ := tokenRig(t, bootstrapped(testCluster()), adminSecret(), hostScopedTemplates(t), serverPod("prod-server-0", true), sec)
		cred, err := apiCredentials(context.Background(), cl, bootstrapped(testCluster()), r.now())
		if err != nil || cred != (Credentials{Token: "admin-token"}) {
			t.Fatalf("%s: credentials %+v %v, want the admin token alone", name, cred, err)
		}
		reconcileCluster(t, r)
		if len(fw.opened) != 1 || readTokenSecret(t, cl)["token"] != "avm_secret_1" {
			t.Fatalf("%s: forwards %v", name, fw.opened)
		}
		if got := api.lastServiceCred(t); got != (Credentials{Token: "avm_secret_1", Fallback: "admin-token"}) {
			t.Fatalf("%s: calls carry %+v", name, got)
		}
	}
}

// A token the operator cannot store is revoked: nobody else holds it.
func TestOperatorTokenStoreFailureRevokes(t *testing.T) {
	r, api, _, cl, _ := tokenRig(t, testCluster(), adminSecret(), hostScopedTemplates(t), serverPod("prod-server-0", true))
	r.Client = interceptor.NewClient(cl.(client.WithWatch), interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if obj.GetName() == "prod-operator-token" {
				return errors.New("etcd full")
			}
			return c.Create(ctx, obj, opts...)
		},
	})
	_, err := r.ensureOperatorToken(context.Background(), testCluster())
	if err == nil || !strings.Contains(err.Error(), "store the operator's API token") {
		t.Fatalf("err = %v", err)
	}
	if revokes := api.calls("revoke"); len(revokes) != 1 || revokes[0].id != "tok_1" || revokes[0].cred != (Credentials{Token: "avm_secret_1"}) {
		t.Fatalf("revokes = %+v", revokes)
	}
	// The revoke failing too only logs: the token expires on its own.
	api.revokeErr = errors.New("down")
	if _, err := r.ensureOperatorToken(context.Background(), testCluster()); err == nil {
		t.Fatal("want the store error")
	}
}

// The node controller and the join issuer call with the operator's token
// too, the admin token as the fallback.
func TestOperatorTokenReachesEveryCaller(t *testing.T) {
	start := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	sec := tokenSecret("avm_cur", "tok_cur", start, start.Add(30*24*time.Hour))
	cl := newFakeClient(t, testCluster(), adminSecret(), sec)
	want := Credentials{Token: "avm_cur", Fallback: "admin-token"}
	if cred, err := apiCredentials(context.Background(), cl, testCluster(), start.Add(time.Hour)); err != nil || cred != want {
		t.Fatalf("credentials = %+v %v", cred, err)
	}
	if cred, err := apiCredentials(context.Background(), cl, testCluster(), start.Add(31*24*time.Hour)); err != nil || cred != (Credentials{Token: "admin-token"}) {
		t.Fatalf("expired: %+v %v", cred, err)
	}
	if _, err := apiCredentials(context.Background(), newFakeClient(t, testCluster()), testCluster(), start); err == nil {
		t.Fatal("no admin Secret: want an error")
	}
	g := newNodeRig(t, testCluster(), sec, node("prod-server-0", v1.RoleServer, "", "z-a"), machine("m1"))
	g.now = start.Add(time.Hour)
	g.reconcile("prod-server-0")
	if got := g.api.lastServiceCred(t); got != want {
		t.Fatalf("the node controller calls with %+v", got)
	}
	wrk := joiningPod("prod-general-aaaaa", testWorkerNS, "m1")
	ig := newIssuerRig(t, bootstrapped(testCluster()), sec, wrk, node("prod-general-aaaaa", v1.RoleWorker, "general", "z-a"))
	ig.now = start.Add(time.Hour)
	ig.rev.tokens["wrk"] = podToken(wrk, "m1")
	if code, out := ig.ask("wrk", ""); code != http.StatusOK {
		t.Fatalf("join: %d %v", code, out)
	}
	if got := ig.api.lastServiceCred(t); got != want {
		t.Fatalf("the join issuer mints with %+v", got)
	}
}

func TestHostScopedServersAndLife(t *testing.T) {
	spec := func(env ...corev1.EnvVar) corev1.PodTemplateSpec {
		return corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: AgentContainer, Env: env}}}}
	}
	for _, tc := range []struct {
		env  []corev1.EnvVar
		host bool
		life time.Duration
	}{
		{nil, false, 30 * 24 * time.Hour},
		{[]corev1.EnvVar{{Name: "SB_PAT_SCOPE", Value: " HOST "}}, true, 30 * 24 * time.Hour},
		{[]corev1.EnvVar{{Name: "SB_PAT_SCOPE", Value: "host"}, {Name: "SB_PAT_SCOPE", Value: "any"}}, false, 30 * 24 * time.Hour},
		{[]corev1.EnvVar{{Name: "SB_TOKEN_MAX_TTL", Value: "2160h"}}, false, 30 * 24 * time.Hour},
		{[]corev1.EnvVar{{Name: "SB_TOKEN_MAX_TTL", Value: "36h"}}, false, 36 * time.Hour},
		{[]corev1.EnvVar{{Name: "SB_TOKEN_MAX_TTL", Value: "90d"}}, false, 30 * 24 * time.Hour},
	} {
		if got := hostScopedServers(spec(tc.env...)); got != tc.host {
			t.Errorf("%v: host scoped = %v", tc.env, got)
		}
		if got := operatorTokenLifeFor(spec(tc.env...)); got != tc.life {
			t.Errorf("%v: life = %s, want %s", tc.env, got, tc.life)
		}
	}
	tok := operatorToken{Token: "t", Created: time.Unix(0, 0), Expires: time.Unix(300, 0)}
	if tok.rotateDue(time.Unix(200, 0)) || !tok.rotateDue(time.Unix(201, 0)) || !tok.usable(time.Unix(299, 0)) || tok.usable(time.Unix(300, 0)) {
		t.Error("rotation is due after two thirds of the life; usable until it expires")
	}
}

// The real client carries both credentials.
func TestDefaultAPIFactoryCarriesTheFallback(t *testing.T) {
	c, ok := DefaultAPIFactory("http://x", Credentials{Token: "a", Fallback: "b"}).(*aerolapi.Client)
	if !ok || c.BaseURL != "http://x" || c.Token != "a" || c.Fallback != "b" {
		t.Fatalf("client = %+v", c)
	}
}

// The admin token never crosses the network to a server that would refuse
// it (review S1): with every server pod host-scoped, calls carry the
// operator's own token alone, or nothing before it has one. While a server
// pod is not host-scoped (enterprise mode being turned on or off), the
// admin token is the fallback. The bootstrap pass's adopt uses the token
// it just stored, even when the cache has not caught up.
func TestOperatorTokenAdminTokenStaysOnTheServers(t *testing.T) {
	start := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	cur := tokenSecret("avm_cur", "tok_cur", start, start.Add(30*24*time.Hour))
	for _, tc := range []struct {
		name string
		objs []client.Object
		want Credentials
	}{
		{"all host-scoped, no token", []client.Object{hostServerPod("prod-server-0", true)}, Credentials{}},
		{"all host-scoped, a token", []client.Object{hostServerPod("prod-server-0", true), cur}, Credentials{Token: "avm_cur"}},
		{"one old server, a token", []client.Object{hostServerPod("prod-server-0", true), serverPod("prod-server-1", true), cur},
			Credentials{Token: "avm_cur", Fallback: "admin-token"}},
		{"one old server, no token", []client.Object{hostServerPod("prod-server-0", true), serverPod("prod-server-1", true)},
			Credentials{Token: "admin-token"}},
		{"no server pod yet", nil, Credentials{Token: "admin-token"}},
	} {
		cl := newFakeClient(t, append([]client.Object{testCluster(), adminSecret()}, tc.objs...)...)
		if got, err := apiCredentials(context.Background(), cl, testCluster(), start.Add(time.Hour)); err != nil || got != tc.want {
			t.Errorf("%s: credentials %+v %v, want %+v", tc.name, got, err, tc.want)
		}
	}

	// On the wire, with the real client: a refused operator token is not
	// followed by the admin token.
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","reason":"unknown_or_revoked"}`))
	}))
	defer srv.Close()
	r, _, fw, cl, _ := tokenRig(t, bootstrapped(testCluster()), adminSecret(), hostScopedTemplates(t), hostServerPod("prod-server-0", true), cur)
	r.API = func(_ string, cred Credentials) AerolAPI { return DefaultAPIFactory(srv.URL, cred) }
	r.Forward = func(context.Context, string, string, int) (string, func(), error) {
		fw.opened = append(fw.opened, "x")
		return srv.URL, func() {}, nil
	}
	_, _ = r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNS, Name: "prod"}})
	for _, h := range seen {
		if strings.Contains(h, "admin-token") {
			t.Fatalf("the admin token went over the API Service: %q", seen)
		}
	}
	if len(seen) == 0 {
		t.Fatal("no call was made")
	}
	_ = cl

	// Bootstrap: the token is made and stored; a cache that has not caught
	// up (the Secret not found yet) does not send adopt out without it.
	r, api, _, cl, _ := tokenRig(t, testCluster(), adminSecret(), hostScopedTemplates(t), hostServerPod("prod-server-0", true))
	stored := false
	r.Client = interceptor.NewClient(cl.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if key.Name == "prod-operator-token" && stored {
				return apierrors.NewNotFound(corev1.Resource("secrets"), key.Name)
			}
			return c.Get(ctx, key, obj, opts...)
		},
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			err := c.Create(ctx, obj, opts...)
			stored = stored || (err == nil && obj.GetName() == "prod-operator-token")
			return err
		},
	})
	reconcileCluster(t, r)
	if api.adopted != 1 || api.lastServiceCred(t) != (Credentials{Token: "avm_secret_1"}) {
		t.Fatalf("adopt %d time(s), with %+v", api.adopted, api.lastServiceCred(t))
	}
}

// The sweep (review B1): every aerolvm-operator-* token but the current one
// and those still in their wait is revoked, with the servers host-scoped or
// not; other tokens are left alone. It runs at most every ten minutes, and
// at once after a token was made.
func TestOperatorTokenSweep(t *testing.T) {
	start := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	sec := tokenSecret("avm_cur", "tok_cur", start, start.Add(30*24*time.Hour),
		"previous_id", "tok_wait", "previous_revoke_at", start.Add(5*time.Minute).Format(time.RFC3339))
	for _, hostScoped := range []bool{true, false} {
		tpl := templates(t)
		pod := serverPod("prod-server-0", true)
		if hostScoped {
			tpl, pod = hostScopedTemplates(t), hostServerPod("prod-server-0", true)
		}
		r, api, _, _, now := tokenRig(t, bootstrapped(testCluster()), adminSecret(), tpl, pod, sec)
		api.liveTokens = map[string]string{"tok_cur": "aerolvm-operator-1", "tok_wait": "aerolvm-operator-2",
			"tok_crash": "aerolvm-operator-3", "tok_ci": "ci", "tok_mine": "my-operator-token"}
		reconcileCluster(t, r)
		if got := revoked(api); len(got) != 1 || !got["tok_crash"] {
			t.Fatalf("host-scoped %v: revoked %v, want the crash orphan alone", hostScoped, got)
		}
		lists := len(api.calls("list"))
		*now = now.Add(time.Minute)
		reconcileCluster(t, r)
		if len(api.calls("list")) != lists {
			t.Fatalf("host-scoped %v: swept again a minute later", hostScoped)
		}
		*now = now.Add(10 * time.Minute)
		reconcileCluster(t, r)
		if got := revoked(api); !got["tok_wait"] || got["tok_cur"] || got["tok_ci"] || got["tok_mine"] {
			t.Fatalf("host-scoped %v: after the wait, revoked %v", hostScoped, got)
		}
	}
	// A list that fails is tried again on the next pass.
	r, api, _, _, now := tokenRig(t, bootstrapped(testCluster()), adminSecret(), hostScopedTemplates(t), hostServerPod("prod-server-0", true), sec)
	api.listErr = errors.New("no leader")
	reconcileCluster(t, r)
	api.listErr = nil
	api.liveTokens = map[string]string{"tok_crash": "aerolvm-operator-3"}
	*now = now.Add(time.Minute)
	reconcileCluster(t, r)
	if !revoked(api)["tok_crash"] {
		t.Fatal("a failed sweep was not retried")
	}
}

// A token the Service refuses is checked on a server through the
// port-forward first (review B1): if that server takes it, nothing is made.
func TestOperatorTokenRecheckedBeforeANewOne(t *testing.T) {
	start := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	sec := tokenSecret("avm_cur", "tok_cur", start.Add(-time.Hour), start.Add(29*24*time.Hour))
	listen := corev1.EnvVar{Name: "SB_PAT_LOCAL_LISTEN", Value: "127.0.0.1:21219"}
	pod := hostServerPod("prod-server-0", true)
	pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, listen)
	r, api, fw, _, _ := tokenRig(t, bootstrapped(testCluster()), adminSecret(), hostScopedTemplates(t, listen), pod, sec)
	var services int
	r.API = func(base string, cred Credentials) AerolAPI {
		b := api.factory(base, cred).(*fakeBound)
		if strings.HasPrefix(base, "http://prod-api.") {
			services++
			return &refusingWhoAmI{fakeBound: b}
		}
		return b
	}
	reconcileCluster(t, r)
	if len(fw.opened) != 1 || fw.opened[0] != testNS+"/prod-server-0:21219" || len(api.calls("create")) != 0 {
		t.Fatalf("forwards %v (want the local API port), creates %v", fw.opened, api.calls("create"))
	}
	if services == 0 {
		t.Fatal("the token was never checked over the Service")
	}
}

// refusingWhoAmI is a server behind the Service that refuses every token.
type refusingWhoAmI struct{ *fakeBound }

func (r *refusingWhoAmI) WhoAmI(context.Context) error {
	return &aerolapi.Error{Status: http.StatusUnauthorized, Reason: "unauthorized"}
}

func TestLocalAPIPort(t *testing.T) {
	spec := func(v string) *corev1.PodSpec {
		return &corev1.PodSpec{Containers: []corev1.Container{{Name: AgentContainer,
			Env: []corev1.EnvVar{{Name: "SB_PAT_LOCAL_LISTEN", Value: v}}}}}
	}
	for v, want := range map[string]int{"": APIPort, "127.0.0.1:21219": 21219, "[::1]:9000": 9000, "junk": APIPort, "127.0.0.1:0": APIPort} {
		if got := localAPIPort(spec(v)); got != want {
			t.Errorf("%q: %d, want %d", v, got, want)
		}
	}
}

// A sweep whose revoke failed is tried again on the next pass, not ten
// minutes later; a host-scoped server is the one forwarded to.
func TestOperatorTokenSweepRetriesAndPrefersHostScopedServers(t *testing.T) {
	start := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	sec := tokenSecret("avm_cur", "tok_cur", start, start.Add(30*24*time.Hour))
	r, api, _, _, now := tokenRig(t, bootstrapped(testCluster()), adminSecret(), hostScopedTemplates(t), hostServerPod("prod-server-0", true), sec)
	api.liveTokens = map[string]string{"tok_crash": "aerolvm-operator-3"}
	api.revokeErr = errors.New("no leader")
	reconcileCluster(t, r)
	api.revokeErr = nil
	*now = now.Add(time.Minute)
	reconcileCluster(t, r)
	if _, live := api.liveTokens["tok_crash"]; live {
		t.Fatal("a sweep whose revoke failed was not tried again on the next pass")
	}

	r, _, fw, _, _ := tokenRig(t, testCluster(), adminSecret(), hostScopedTemplates(t),
		serverPod("prod-server-0", true), hostServerPod("prod-server-1", true))
	reconcileCluster(t, r)
	if len(fw.opened) != 1 || fw.opened[0] != testNS+"/prod-server-1:21212" {
		t.Fatalf("forwards %v, want the host-scoped server", fw.opened)
	}
}

// While enterprise mode is being turned on, the template has the admin
// listener and the running servers do not: the token is made through a
// running server's own port, the API port, at once (the first kind run
// forwarded to the template's port, which no running server had, for eight
// minutes).
func TestOperatorTokenMadeThroughTheRunningServersPort(t *testing.T) {
	listen := corev1.EnvVar{Name: "SB_PAT_LOCAL_LISTEN", Value: "127.0.0.1:21219"}
	r, api, fw, _, _ := tokenRig(t, bootstrapped(testCluster()), adminSecret(), hostScopedTemplates(t, listen),
		serverPod("prod-server-0", true))
	reconcileCluster(t, r)
	if len(fw.opened) != 1 || fw.opened[0] != testNS+"/prod-server-0:"+strconv.Itoa(APIPort) || len(api.calls("create")) != 1 {
		t.Fatalf("forwards %v (want the old server's API port), creates %v", fw.opened, api.calls("create"))
	}

	// Once the server is replaced, its own listener is the one used.
	pod := hostServerPod("prod-server-1", true)
	pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, listen)
	r, api, fw, _, _ = tokenRig(t, bootstrapped(testCluster()), adminSecret(), hostScopedTemplates(t, listen),
		serverPod("prod-server-0", true), pod)
	reconcileCluster(t, r)
	if len(fw.opened) != 1 || fw.opened[0] != testNS+"/prod-server-1:21219" || len(api.calls("create")) != 1 {
		t.Fatalf("forwards %v (want the replaced server's admin listener), creates %v", fw.opened, api.calls("create"))
	}
}

// While enterprise mode is being turned on, a token the Service refuses is
// not replaced on the word of an old server (one that is not host-scoped,
// perhaps with API tokens off): the first kind run made a new token every
// two minutes until the pods were replaced. Once a host-scoped server
// refuses it too, another is made.
func TestOperatorTokenNotReplacedOnAnOldServersWord(t *testing.T) {
	start := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	sec := tokenSecret("avm_cur", "tok_cur", start.Add(-time.Hour), start.Add(29*24*time.Hour))
	refuse := func(r *ClusterReconciler, api *fakeAPI) {
		r.API = func(base string, cred Credentials) AerolAPI {
			return &refusingWhoAmI{fakeBound: api.factory(base, cred).(*fakeBound)}
		}
	}
	r, api, fw, _, _ := tokenRig(t, bootstrapped(testCluster()), adminSecret(), hostScopedTemplates(t), serverPod("prod-server-0", true), sec)
	refuse(r, api)
	reconcileCluster(t, r)
	if len(api.calls("create")) != 0 || len(fw.opened) != 0 {
		t.Fatalf("an old server's refusal made a token: creates %v, forwards %v", api.calls("create"), fw.opened)
	}

	r, api, fw, _, _ = tokenRig(t, bootstrapped(testCluster()), adminSecret(), hostScopedTemplates(t),
		serverPod("prod-server-0", true), hostServerPod("prod-server-1", true), sec)
	refuse(r, api)
	reconcileCluster(t, r)
	if len(api.calls("create")) != 1 || len(fw.opened) != 1 || fw.opened[0] != testNS+"/prod-server-1:"+strconv.Itoa(APIPort) {
		t.Fatalf("a host-scoped server refused it too: creates %v, forwards %v", api.calls("create"), fw.opened)
	}
}

// The sweep leaves an operator token younger than the grace (15 minutes):
// another replica may have just made it and still be storing it (round-2
// review). The server's created_at counts, else the time in the name; a
// leftover goes on a sweep once it is older.
func TestOperatorTokenSweepLeavesYoungTokens(t *testing.T) {
	start := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	sec := tokenSecret("avm_cur", "tok_cur", start.Add(-time.Hour), start.Add(29*24*time.Hour))
	r, api, _, _, now := tokenRig(t, bootstrapped(testCluster()), adminSecret(), hostScopedTemplates(t), hostServerPod("prod-server-0", true), sec)
	api.liveTokens = map[string]string{
		"tok_cur":     "aerolvm-operator-1",
		"tok_young":   "aerolvm-operator-x",                       // created_at a minute ago
		"tok_old":     "aerolvm-operator-y",                       // created_at 20 minutes ago
		"tok_named":   operatorTokenName(start.Add(-time.Minute)), // no created_at: the name's time
		"tok_unknown": "aerolvm-operator-z",                       // neither: old enough
	}
	api.liveCreated = map[string]time.Time{"tok_young": start.Add(-time.Minute), "tok_old": start.Add(-20 * time.Minute)}
	reconcileCluster(t, r)
	if got := revoked(api); len(got) != 2 || !got["tok_old"] || !got["tok_unknown"] {
		t.Fatalf("first sweep revoked %v, want tok_old and tok_unknown", got)
	}
	// Twenty minutes on (two sweep periods), the young ones are leftovers.
	*now = now.Add(20 * time.Minute)
	reconcileCluster(t, r)
	if got := revoked(api); !got["tok_young"] || !got["tok_named"] || got["tok_cur"] {
		t.Fatalf("a later sweep revoked %v, want the two leftovers too", got)
	}
}
