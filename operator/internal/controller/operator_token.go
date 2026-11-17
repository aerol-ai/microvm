package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
	"github.com/aerol-ai/microvm/operator/internal/aerolapi"
	"github.com/aerol-ai/microvm/pkg/identitywire"
)

// The operator's own admin API token (issue #1349). In enterprise mode every
// server takes the admin token (SB_PAT_SCOPE=host) only from inside its own
// pod and from the cluster's own nodes, so the operator's calls over the API
// Service are refused with it. The operator calls with an API token of its
// own instead: role admin, every team.
//
// It makes one through a port-forward to a Ready server pod, the one way in
// that a server counts as its own pod (the kubelet connects on the pod's
// loopback), with the admin token, which never leaves the pod that way.
// Later tokens are made with the current one over the API Service, before a
// third of its life is left. A token the servers refuse is checked again on
// a server through the port-forward before another is made: one lagging or
// older server refusing it proves nothing.
//
// Every token it replaced is revoked after operatorTokenRevokeAfter (a call
// another controller started with it still lands), however many were
// replaced in that time. And a sweep revokes every other token named
// aerolvm-operator-*, whether the servers are host-scoped or not: one left
// by a crash between its create and the Secret write, or by a replacement
// whose revoke failed. The token lives in a Secret next to the admin
// token's, which only the operator reads.
//
// The admin token goes over the API Service only while some server pod is
// not host-scoped, and so takes it (apiCredentials): while enterprise mode
// is turned on, or off, until the last old server is replaced.

const (
	// operatorTokenLife is the most a token lives. The server's cap
	// (SB_TOKEN_MAX_TTL) shortens it.
	operatorTokenLife = 30 * 24 * time.Hour
	// operatorTokenRevokeAfter is how long a replaced token keeps working:
	// a call another controller started with it just before the
	// replacement still lands.
	operatorTokenRevokeAfter = 5 * time.Minute
	// operatorTokenSettle is how long a new token may be refused before
	// the operator checks it on a server itself: a server catches up on new
	// tokens through Raft.
	operatorTokenSettle = 2 * time.Minute
	// operatorTokenSweepEvery spaces the sweeps: one token list read per
	// cluster per period, and one after anything was made.
	operatorTokenSweepEvery = 10 * time.Minute
	// operatorTokenSweepGrace: the sweep leaves a token younger than this.
	// Another operator replica may have just made it and still be writing
	// it to the Secret (a leader change, a slow write), so this replica's
	// view does not hold it yet. Past the revoke wait with room to spare;
	// a crash's leftover goes on a later sweep.
	operatorTokenSweepGrace = 15 * time.Minute
	// operatorTokenPrefix names the operator's tokens: only servers take
	// them, and only the admin token or the current one makes one.
	operatorTokenPrefix = identitywire.OperatorTokenPrefix
)

// Keys of the operator token's Secret.
const (
	opTokenKey        = "token"
	opTokenIDKey      = "id"
	opTokenCreatedKey = "created_at"
	opTokenExpiresKey = "expires_at"
	// The token the current one replaced, revoked once opTokenRevokeKey
	// has passed.
	opTokenPrevIDKey = "previous_id"
	opTokenRevokeKey = "previous_revoke_at"
	// Older replaced tokens still in their wait: a JSON object of id to
	// revoke time. A token replaced twice inside the wait keeps both.
	opTokenEarlierKey = "earlier_revokes"
	opTokenTimeFormat = time.RFC3339
)

// OperatorTokenSecret is the Secret that holds the operator's own admin
// API token for cluster.
func OperatorTokenSecret(cluster string) string { return cluster + "-operator-token" }

// operatorToken is the Secret's content.
type operatorToken struct {
	Token, ID        string
	Created, Expires time.Time
	PrevID           string
	PrevRevoke       time.Time
	// Earlier are replaced tokens older than PrevID, by id, with their
	// revoke times.
	Earlier map[string]time.Time
}

func (t operatorToken) usable(now time.Time) bool {
	return t.Token != "" && now.Before(t.Expires)
}

// rotateDue reports whether less than a third of the token's life is left.
func (t operatorToken) rotateDue(now time.Time) bool {
	life := t.Expires.Sub(t.Created)
	return now.After(t.Created.Add(life * 2 / 3))
}

// pending is every replaced token not yet revoked, with its revoke time.
func (t operatorToken) pending() map[string]time.Time {
	out := map[string]time.Time{}
	for id, at := range t.Earlier {
		out[id] = at
	}
	if t.PrevID != "" {
		out[t.PrevID] = t.PrevRevoke
	}
	return out
}

func readOperatorToken(ctx context.Context, r client.Reader, c *v1.AerolCluster) (operatorToken, error) {
	var s corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: OperatorTokenSecret(c.Name)}, &s)
	if apierrors.IsNotFound(err) {
		return operatorToken{}, nil
	}
	if err != nil {
		return operatorToken{}, err
	}
	return parseOperatorToken(s.Data), nil
}

func parseOperatorToken(data map[string][]byte) operatorToken {
	t := operatorToken{Token: string(data[opTokenKey]), ID: string(data[opTokenIDKey]),
		PrevID: string(data[opTokenPrevIDKey])}
	// A time that does not parse is the zero time: the token counts as
	// expired and is made again, a replaced one is revoked at once.
	t.Created, _ = time.Parse(opTokenTimeFormat, string(data[opTokenCreatedKey]))
	t.Expires, _ = time.Parse(opTokenTimeFormat, string(data[opTokenExpiresKey]))
	t.PrevRevoke, _ = time.Parse(opTokenTimeFormat, string(data[opTokenRevokeKey]))
	var earlier map[string]string
	if json.Unmarshal(data[opTokenEarlierKey], &earlier) == nil && len(earlier) > 0 {
		t.Earlier = map[string]time.Time{}
		for id, at := range earlier {
			t.Earlier[id], _ = time.Parse(opTokenTimeFormat, at)
		}
	}
	return t
}

func (t operatorToken) data() map[string][]byte {
	d := map[string][]byte{
		opTokenKey:        []byte(t.Token),
		opTokenIDKey:      []byte(t.ID),
		opTokenCreatedKey: []byte(t.Created.UTC().Format(opTokenTimeFormat)),
		opTokenExpiresKey: []byte(t.Expires.UTC().Format(opTokenTimeFormat)),
	}
	if t.PrevID != "" {
		d[opTokenPrevIDKey] = []byte(t.PrevID)
		d[opTokenRevokeKey] = []byte(t.PrevRevoke.UTC().Format(opTokenTimeFormat))
	}
	if len(t.Earlier) > 0 {
		earlier := map[string]string{}
		for id, at := range t.Earlier {
			earlier[id] = at.UTC().Format(opTokenTimeFormat)
		}
		d[opTokenEarlierKey], _ = json.Marshal(earlier)
	}
	return d
}

// apiCredentials is what the operator calls cluster c's servers with. See
// credentialsFor.
func apiCredentials(ctx context.Context, r client.Reader, c *v1.AerolCluster, now time.Time) (Credentials, error) {
	tok, err := readOperatorToken(ctx, r, c)
	if err != nil {
		return Credentials{}, err
	}
	return credentialsFor(ctx, r, c, now, tok)
}

// credentialsFor: its own token when current; the admin token only while
// some server pod is not host-scoped and so takes it over the network
// (first, without a token of its own; as the fallback, with one). With
// every server host-scoped and no token yet, nothing: the admin token
// would only be refused, after crossing the network.
func credentialsFor(ctx context.Context, r client.Reader, c *v1.AerolCluster, now time.Time, tok operatorToken) (Credentials, error) {
	takesPAT, err := someServerTakesPAT(ctx, r, c)
	if err != nil {
		return Credentials{}, err
	}
	var pat string
	if takesPAT {
		if pat, err = adminToken(ctx, r, c); err != nil {
			return Credentials{}, err
		}
	}
	if tok.usable(now) {
		return Credentials{Token: tok.Token, Fallback: pat}, nil
	}
	return Credentials{Token: pat}, nil
}

// someServerTakesPAT reports whether a server pod of c takes the admin
// token from the network: one that is not host-scoped, or none at all yet
// (there is then no server to send anything to).
func someServerTakesPAT(ctx context.Context, r client.Reader, c *v1.AerolCluster) (bool, error) {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(c.Namespace),
		client.MatchingLabels{LabelCluster: c.Name, LabelComponent: v1.RoleServer}); err != nil {
		return false, err
	}
	for i := range pods.Items {
		if !hostScopedPod(&pods.Items[i]) {
			return true, nil
		}
	}
	return len(pods.Items) == 0, nil
}

func hostScopedPod(p *corev1.Pod) bool {
	return strings.EqualFold(strings.TrimSpace(agentEnvValue(&p.Spec, "SB_PAT_SCOPE")), "host")
}

// hostScopedServers reports whether the server template takes the admin
// token only from the server's own pod (SB_PAT_SCOPE=host): the operator
// then needs a token of its own.
func hostScopedServers(t corev1.PodTemplateSpec) bool {
	return strings.EqualFold(strings.TrimSpace(agentEnvValue(&t.Spec, "SB_PAT_SCOPE")), "host")
}

// localAPIPort is the port the admin token works on inside a server pod:
// SB_PAT_LOCAL_LISTEN's when the pod sets it (the chart does in enterprise
// mode), else the API port. The pod's own, not the template's: while
// enterprise mode is being turned on, the running servers are still the
// old ones, with no such listener, and they take the admin token on the
// API port (the first kind run forwarded to the template's port for eight
// minutes and got nothing).
func localAPIPort(spec *corev1.PodSpec) int {
	if raw := strings.TrimSpace(agentEnvValue(spec, "SB_PAT_LOCAL_LISTEN")); raw != "" {
		if _, port, err := net.SplitHostPort(raw); err == nil {
			if n, err := strconv.Atoi(port); err == nil && n > 0 {
				return n
			}
		}
	}
	return APIPort
}

// operatorTokenLifeFor is the life to ask for: operatorTokenLife, or the
// servers' cap (SB_TOKEN_MAX_TTL) when that is shorter.
func operatorTokenLifeFor(t corev1.PodTemplateSpec) time.Duration {
	life := operatorTokenLife
	if raw := strings.TrimSpace(agentEnvValue(&t.Spec, "SB_TOKEN_MAX_TTL")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 && d < life {
			life = d
		}
	}
	return life
}

// errNoReadyServer: no server pod to make the first token through yet.
var errNoReadyServer = errors.New("no Ready server pod to make the operator's API token through yet")

// ensureOperatorToken keeps the operator's own token current while the
// server template is host-scoped, and revokes replaced and stray tokens
// either way. It returns the token it holds at the end, which the pass's
// calls use as they are (never re-read from the cache, which may not have
// the write yet).
func (r *ClusterReconciler) ensureOperatorToken(ctx context.Context, c *v1.AerolCluster) (operatorToken, error) {
	cur, err := readOperatorToken(ctx, r.Client, c)
	if err != nil {
		return cur, err
	}
	tpl, ok, err := r.serverTemplate(ctx, c)
	if err != nil {
		return cur, err
	}
	now := r.now()
	changed := false
	if ok && hostScopedServers(tpl) {
		next, made, err := r.keepOperatorToken(ctx, c, tpl, cur, now)
		if err != nil {
			return cur, err
		}
		cur, changed = next, made
	}
	// Revoke and sweep with whatever the servers take, host-scoped or not.
	cur, err = r.revokeReplaced(ctx, c, cur, now)
	if err != nil {
		log.FromContext(ctx).Info("revoking the operator's replaced API tokens failed; retrying", "err", err.Error())
	}
	if err := r.sweepOperatorTokens(ctx, c, cur, now, changed); err != nil {
		log.FromContext(ctx).Info("sweeping the operator's stray API tokens failed; retrying", "err", err.Error())
	}
	return cur, nil
}

// keepOperatorToken makes, replaces or re-checks the token. made reports a
// new one.
func (r *ClusterReconciler) keepOperatorToken(ctx context.Context, c *v1.AerolCluster, tpl corev1.PodTemplateSpec, cur operatorToken, now time.Time) (operatorToken, bool, error) {
	life := operatorTokenLifeFor(tpl)
	logger := log.FromContext(ctx)
	switch {
	case !cur.usable(now):
		next, err := r.mintOperatorToken(ctx, c, "", life, cur, "none held")
		return next, err == nil, err
	case cur.rotateDue(now):
		created, err := r.API(apiURL(c), Credentials{Token: cur.Token}).CreateToken(ctx, operatorTokenName(now), "admin", "*", life.String())
		if aerolapi.IsStatus(err, http.StatusUnauthorized) {
			next, err := r.mintOperatorToken(ctx, c, "", life, cur, "the current one was refused")
			return next, err == nil, err
		}
		if err != nil {
			return cur, false, fmt.Errorf("replace the operator's API token: %w", err)
		}
		logger.Info("replaced the operator's API token", "id", created.ID, "expires_at", created.ExpiresAt)
		next, err := r.storeOperatorToken(ctx, c, created, cur)
		return next, err == nil, err
	default:
		err := r.API(apiURL(c), Credentials{Token: cur.Token}).WhoAmI(ctx)
		if !aerolapi.IsStatus(err, http.StatusUnauthorized) || now.Sub(cur.Created) <= operatorTokenSettle {
			return cur, false, nil
		}
		// Refused over the Service. Ask a server itself before making
		// another: an older or lagging server behind the Service refusing
		// it says nothing about the token.
		return r.recheckOperatorToken(ctx, c, life, cur)
	}
}

// recheckOperatorToken asks a Ready server, through the port-forward,
// whether it takes the token; only if it does not is another made, through
// the same port-forward.
func (r *ClusterReconciler) recheckOperatorToken(ctx context.Context, c *v1.AerolCluster, life time.Duration, cur operatorToken) (operatorToken, bool, error) {
	if r.Forward == nil {
		return cur, false, errors.New("the servers refuse the operator's API token, and this operator cannot port-forward to check it")
	}
	pod, port, scoped, err := r.readyServerPod(ctx, c)
	if err != nil {
		return cur, false, err
	}
	if !scoped {
		// No server runs the new settings yet (enterprise mode is being
		// turned on, the old pods still serve, perhaps with API tokens off):
		// an old server refusing the token says nothing about it, and they
		// all take the admin token meanwhile. The first kind run made a new
		// token every two minutes here until the pods were replaced.
		return cur, false, nil
	}
	base, stop, err := r.Forward(ctx, c.Namespace, pod, port)
	if err != nil {
		return cur, false, fmt.Errorf("port-forward to %s to check the operator's API token: %w", pod, err)
	}
	defer stop()
	err = r.API(base, Credentials{Token: cur.Token}).WhoAmI(ctx)
	if err == nil {
		log.FromContext(ctx).Info("a server behind the API Service refuses the operator's API token, but its own server takes it; keeping it", "server", pod, "id", cur.ID)
		return cur, false, nil
	}
	if !aerolapi.IsStatus(err, http.StatusUnauthorized) {
		return cur, false, fmt.Errorf("check the operator's API token on %s: %w", pod, err)
	}
	next, err := r.mintOperatorToken(ctx, c, base, life, cur, "the servers refuse it")
	return next, err == nil, err
}

// mintOperatorToken makes a token with the admin token, through a
// port-forward to a Ready server pod (base, when one is already open).
func (r *ClusterReconciler) mintOperatorToken(ctx context.Context, c *v1.AerolCluster, base string, life time.Duration, cur operatorToken, why string) (operatorToken, error) {
	pat, err := adminToken(ctx, r.Client, c)
	if err != nil {
		return cur, err
	}
	pod := "the server"
	if base == "" {
		if r.Forward == nil {
			return cur, errors.New("the servers take the admin token only from their own pod, and this operator cannot port-forward to them")
		}
		var port int
		if pod, port, _, err = r.readyServerPod(ctx, c); err != nil {
			return cur, err
		}
		var stop func()
		base, stop, err = r.Forward(ctx, c.Namespace, pod, port)
		if err != nil {
			return cur, fmt.Errorf("port-forward to %s for the operator's API token: %w", pod, err)
		}
		defer stop()
	}
	created, err := r.API(base, Credentials{Token: pat}).CreateToken(ctx, operatorTokenName(r.now()), "admin", "*", life.String())
	if err != nil {
		return cur, fmt.Errorf("make the operator's API token on %s: %w", pod, err)
	}
	log.FromContext(ctx).Info("made the operator's API token", "reason", why, "server", pod, "id", created.ID, "expires_at", created.ExpiresAt)
	return r.storeOperatorToken(ctx, c, created, cur)
}

// storeOperatorToken saves created as the current token. The one it
// replaces, and any still waiting, are kept for revocation after their
// wait. A store that fails revokes created, which nobody else holds (and
// the sweep catches it if that fails too).
func (r *ClusterReconciler) storeOperatorToken(ctx context.Context, c *v1.AerolCluster, created aerolapi.CreatedAPIToken, cur operatorToken) (operatorToken, error) {
	now := r.now()
	next := operatorToken{Token: created.Token, ID: created.ID,
		Created: nonZero(created.CreatedAt, now), Expires: created.ExpiresAt}
	pending := cur.pending()
	if cur.ID != "" && cur.ID != created.ID {
		pending[cur.ID] = now.Add(operatorTokenRevokeAfter)
	}
	next.setPending(pending)
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: OperatorTokenSecret(c.Name), Namespace: c.Namespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, s, func() error {
		s.Labels = clusterLabels(c)
		s.Type = corev1.SecretTypeOpaque
		s.Data = next.data()
		return controllerutil.SetControllerReference(c, s, r.Scheme)
	})
	if err != nil {
		if rerr := r.API(apiURL(c), Credentials{Token: created.Token}).RevokeToken(ctx, created.ID); rerr != nil {
			log.FromContext(ctx).Info("could not revoke a token the operator failed to store; the sweep revokes it later",
				"id", created.ID, "expires_at", created.ExpiresAt, "error", rerr.Error())
		}
		return cur, fmt.Errorf("store the operator's API token: %w", err)
	}
	return next, nil
}

// setPending files pending as the latest replaced (PrevID) and the rest.
func (t *operatorToken) setPending(pending map[string]time.Time) {
	t.PrevID, t.PrevRevoke, t.Earlier = "", time.Time{}, nil
	for id, at := range pending {
		if id == t.ID {
			continue
		}
		if t.PrevID == "" || at.After(t.PrevRevoke) || (at.Equal(t.PrevRevoke) && id > t.PrevID) {
			if t.PrevID != "" {
				if t.Earlier == nil {
					t.Earlier = map[string]time.Time{}
				}
				t.Earlier[t.PrevID] = t.PrevRevoke
			}
			t.PrevID, t.PrevRevoke = id, at
			continue
		}
		if t.Earlier == nil {
			t.Earlier = map[string]time.Time{}
		}
		t.Earlier[id] = at
	}
}

// revokeReplaced revokes every replaced token whose wait is over, and
// keeps the rest.
func (r *ClusterReconciler) revokeReplaced(ctx context.Context, c *v1.AerolCluster, cur operatorToken, now time.Time) (operatorToken, error) {
	pending := cur.pending()
	due := false
	for _, at := range pending {
		due = due || !now.Before(at)
	}
	if !due {
		return cur, nil
	}
	api, ok, err := r.revokeClient(ctx, c, cur, now)
	if err != nil || !ok {
		return cur, err
	}
	var firstErr error
	for id, at := range pending {
		if now.Before(at) {
			continue
		}
		if err := api.RevokeToken(ctx, id); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("revoke the operator's replaced API token %s: %w", id, err)
			}
			continue
		}
		delete(pending, id)
		log.FromContext(ctx).Info("revoked the operator's replaced API token", "id", id)
	}
	next := cur
	next.setPending(pending)
	if err := r.writeOperatorToken(ctx, c, next); err != nil {
		return cur, err
	}
	return next, firstErr
}

// writeOperatorToken writes t over the Secret, when there is one.
func (r *ClusterReconciler) writeOperatorToken(ctx context.Context, c *v1.AerolCluster, t operatorToken) error {
	var s corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: OperatorTokenSecret(c.Name)}, &s); err != nil {
		return client.IgnoreNotFound(err)
	}
	s.Data = t.data()
	return r.Update(ctx, &s)
}

// revokeClient is a client for token writes: the operator's own token
// when current, else the admin token while some server takes it. ok is
// false when there is nothing the servers would take.
func (r *ClusterReconciler) revokeClient(ctx context.Context, c *v1.AerolCluster, cur operatorToken, now time.Time) (AerolAPI, bool, error) {
	cred, err := credentialsFor(ctx, r.Client, c, now, cur)
	if err != nil || cred.Token == "" {
		return nil, false, err
	}
	return r.API(apiURL(c), cred), true, nil
}

// sweepOperatorTokens revokes every aerolvm-operator-* token but the
// current one and those still in their wait: tokens a crash orphaned
// between their create and the Secret write, or whose revoke never
// happened. Once per operatorTokenSweepEvery per cluster, and at once
// after a token was made.
func (r *ClusterReconciler) sweepOperatorTokens(ctx context.Context, c *v1.AerolCluster, cur operatorToken, now time.Time, force bool) error {
	r.sweepMu.Lock()
	last, seen := r.sweptAt[c.UID]
	r.sweepMu.Unlock()
	if seen && !force && now.Sub(last) < operatorTokenSweepEvery {
		return nil
	}
	api, ok, err := r.revokeClient(ctx, c, cur, now)
	if err != nil || !ok {
		return err
	}
	tokens, err := api.ListTokens(ctx)
	if err != nil {
		return fmt.Errorf("list API tokens: %w", err)
	}
	keep := cur.pending()
	var firstErr error
	for _, t := range tokens {
		if !strings.HasPrefix(t.Name, operatorTokenPrefix) || t.ID == cur.ID {
			continue
		}
		if at, waiting := keep[t.ID]; waiting && now.Before(at) {
			continue
		}
		if made, ok := operatorTokenMadeAt(t); ok && now.Sub(made) < operatorTokenSweepGrace {
			continue
		}
		if err := api.RevokeToken(ctx, t.ID); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("revoke stray operator API token %s: %w", t.ID, err)
			}
			continue
		}
		log.FromContext(ctx).Info("revoked a stray operator API token", "id", t.ID, "name", t.Name)
	}
	if firstErr == nil {
		r.sweepMu.Lock()
		if r.sweptAt == nil {
			r.sweptAt = map[types.UID]time.Time{}
		}
		r.sweptAt[c.UID] = now
		r.sweepMu.Unlock()
	}
	return firstErr
}

// readyServerPod is a Ready server pod of c, by name, a host-scoped one
// first (while enterprise mode is being turned on, an older server may not
// take API tokens at all), the port its admin token works on, and whether
// it is host-scoped.
func (r *ClusterReconciler) readyServerPod(ctx context.Context, c *v1.AerolCluster) (string, int, bool, error) {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(c.Namespace),
		client.MatchingLabels{LabelCluster: c.Name, LabelComponent: v1.RoleServer}); err != nil {
		return "", 0, false, err
	}
	var scoped, other []*corev1.Pod
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning || !podIsReady(p) {
			continue
		}
		if hostScopedPod(p) {
			scoped = append(scoped, p)
		} else {
			other = append(other, p)
		}
	}
	byName := func(ps []*corev1.Pod) { sort.Slice(ps, func(i, j int) bool { return ps[i].Name < ps[j].Name }) }
	byName(scoped)
	byName(other)
	if ready := append(scoped, other...); len(ready) > 0 {
		return ready[0].Name, localAPIPort(&ready[0].Spec), len(scoped) > 0, nil
	}
	return "", 0, false, errNoReadyServer
}

func podIsReady(p *corev1.Pod) bool {
	for _, cond := range p.Status.Conditions {
		if cond.Type == corev1.PodReady {
			return cond.Status == corev1.ConditionTrue
		}
	}
	return false
}

// serverTemplate is the chart's server template, if there is one to read.
func (r *ClusterReconciler) serverTemplate(ctx context.Context, c *v1.AerolCluster) (corev1.PodTemplateSpec, bool, error) {
	if r.Templates == "" {
		return corev1.PodTemplateSpec{}, false, nil
	}
	var cm corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: r.Templates}, &cm); err != nil {
		return corev1.PodTemplateSpec{}, false, client.IgnoreNotFound(err)
	}
	tpl, err := ParsePodTemplate(cm.Data[TemplateServer])
	if err != nil {
		return corev1.PodTemplateSpec{}, false, nil
	}
	return tpl, true, nil
}

func operatorTokenName(now time.Time) string {
	return fmt.Sprintf("%s%d", operatorTokenPrefix, now.UnixNano())
}

// operatorTokenMadeAt is when an operator token was made: the server's
// created_at, else the time its name carries (operatorTokenName). A token
// with neither is old enough to sweep.
func operatorTokenMadeAt(t aerolapi.APIToken) (time.Time, bool) {
	if !t.CreatedAt.IsZero() {
		return t.CreatedAt, true
	}
	if n, err := strconv.ParseInt(strings.TrimPrefix(t.Name, operatorTokenPrefix), 10, 64); err == nil && n > 0 {
		return time.Unix(0, n), true
	}
	return time.Time{}, false
}

func nonZero(t, def time.Time) time.Time {
	if t.IsZero() {
		return def
	}
	return t
}
