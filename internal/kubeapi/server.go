package kubeapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/kubeview"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The server: discovery, then every verb on sandboxes, namespaced and
// across namespaces, read from the gateway's hub (internal/kubeview) and
// written through the Backend, which is AerolVM's own API path.
//
//	GET  /apis/agents.x-k8s.io/v1beta1                                discovery
//	GET  /apis/agents.x-k8s.io/v1beta1/[namespaces/{ns}/]sandboxes     list, or watch with ?watch=true
//	POST /apis/agents.x-k8s.io/v1beta1/namespaces/{ns}/sandboxes       create
//	GET, DELETE, PATCH .../namespaces/{ns}/sandboxes/{name}            get, delete, operatingMode

// Backend is the write side and the spec reads, implemented over
// AerolVM's own create, delete, stop and start (pkg/api wiring).
type Backend interface {
	// Create makes a sandbox for owner and returns its ID. key is an
	// Idempotency-Key: a retried POST for the same name finds the first
	// one's sandbox.
	Create(ctx context.Context, owner string, req models.CreateSandboxRequest, key string) (string, error)
	Delete(ctx context.Context, owner, sandboxID string) error
	// SetRunning starts (true) or stops (false) a sandbox.
	SetRunning(ctx context.Context, owner, sandboxID string, running bool) error
	// Specs summarizes the given sandboxes' specs; missing ones render
	// without a spec.
	Specs(ctx context.Context, ids []string) map[string]SpecSummary
}

// StatusError is an error with the Kubernetes status to answer it with. A
// Backend returns one to choose the answer; any other error is a 500.
type StatusError struct {
	Code    int
	Reason  string
	Message string
}

func (e *StatusError) Error() string { return e.Message }

// OwnerMap maps namespaces onto AerolVM owners (decision C17: a namespace
// is an owner, and shows and deletes all of that owner's sandboxes). By
// default namespace N is team N ("team:N"); Explicit maps other owners
// (an account key, or a team whose name differs). Mappings come from the
// cluster admin's settings, never from a namespace's own labels: anyone
// who can make a namespace could otherwise claim a team's sandboxes.
type OwnerMap struct {
	Explicit map[string]string // namespace -> owner
}

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// Owner is a namespace's owner.
func (m OwnerMap) Owner(ns string) (string, bool) {
	if o, ok := m.Explicit[ns]; ok {
		return o, true
	}
	if len(ns) <= 63 && dnsLabel.MatchString(ns) {
		return "team:" + ns, true
	}
	return "", false
}

// Namespace is an owner's namespace.
func (m OwnerMap) Namespace(owner string) (string, bool) {
	for ns, o := range m.Explicit {
		if o == owner {
			return ns, true
		}
	}
	if ns, ok := strings.CutPrefix(owner, "team:"); ok && len(ns) <= 63 && dnsLabel.MatchString(ns) {
		if _, taken := m.Explicit[ns]; !taken {
			return ns, true
		}
	}
	return "", false
}

// Server is the agent-sandbox API on one gateway.
type Server struct {
	Hub     *kubeview.Hub
	Auth    Authenticator
	Authz   Authorizer
	Backend Backend
	// Store keeps templates and warm pools (objects.go); nil serves the
	// extensions group as unavailable.
	Store  ObjectStore
	Owners OwnerMap
	// Now and Random are the clock and the generateName suffix; tests set
	// them.
	Now    func() time.Time
	Random func() string
	// BookmarkEvery is how often an idle watch gets a bookmark, so its
	// resourceVersion stays inside the hub's ring.
	BookmarkEvery time.Duration
	// CreateWait bounds how long a create waits to see its sandbox in the
	// hub before answering.
	CreateWait time.Duration
}

const (
	maxPageLimit       = 500
	defaultWatchLength = 30 * time.Minute
	initialEventsEnd   = "k8s.io/initial-events-end"
)

var errNoNamespace = &StatusError{Code: http.StatusNotFound, Reason: "NotFound", Message: "this namespace maps to no AerolVM owner"}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	switch path {
	case "/healthz", "/livez":
		_, _ = io.WriteString(w, "ok")
		return
	case "/readyz":
		if _, err := s.Hub.Position(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok")
		return
	}
	u, err := s.Auth.Authenticate(r)
	if err != nil && !(errors.Is(err, ErrNoUser) && discoveryPath(path)) {
		writeStatus(w, &StatusError{Code: http.StatusUnauthorized, Reason: "Unauthorized", Message: err.Error()})
		return
	}
	r = r.WithContext(ContextWithUser(r.Context(), u))
	switch path {
	case "/apis":
		writeJSON(w, http.StatusOK, apiGroupList())
		return
	case "/apis/" + Group:
		writeJSON(w, http.StatusOK, apiGroup(Group))
		return
	case "/apis/" + Group + "/" + Version:
		writeJSON(w, http.StatusOK, resourceList())
		return
	case "/apis/" + ExtensionsGroup:
		writeJSON(w, http.StatusOK, apiGroup(ExtensionsGroup))
		return
	case "/apis/" + ExtensionsGroup + "/" + Version:
		writeJSON(w, http.StatusOK, extensionsResourceList())
		return
	case "/openapi/v2":
		writeJSON(w, http.StatusOK, map[string]any{"swagger": "2.0", "info": map[string]string{"title": "AerolVM agent-sandbox API", "version": UpstreamRelease}, "paths": map[string]any{}})
		return
	case "/openapi/v3":
		writeJSON(w, http.StatusOK, map[string]any{"paths": map[string]any{}})
		return
	}
	group, resource, ns, name, sub, ok := parseResourcePath(path)
	if !ok {
		writeStatus(w, &StatusError{Code: http.StatusNotFound, Reason: "NotFound", Message: "no such path: " + r.URL.Path})
		return
	}
	if sub != "" {
		writeStatus(w, &StatusError{Code: http.StatusMethodNotAllowed, Reason: "MethodNotAllowed", Message: "the " + sub + " subresource is not served"})
		return
	}
	q := r.URL.Query()
	verb, err := verbOf(r.Method, name, q.Get("watch"), group == ExtensionsGroup)
	if err != nil {
		writeStatus(w, err)
		return
	}
	allowed, reason, err := s.Authz.Authorize(r.Context(), u, Attributes{Verb: verb, Group: group, Resource: resource, Namespace: ns, Name: name})
	if err != nil {
		writeStatus(w, &StatusError{Code: http.StatusInternalServerError, Reason: "InternalError", Message: "authorization check failed: " + err.Error()})
		return
	}
	if !allowed {
		msg := fmt.Sprintf("%s cannot %s %s.%s in namespace %q", u.Name, verb, resource, group, ns)
		if reason != "" {
			msg += ": " + reason
		}
		writeStatus(w, &StatusError{Code: http.StatusForbidden, Reason: "Forbidden", Message: msg})
		return
	}
	if group == ExtensionsGroup && resource == SandboxClaimsResource {
		if err := s.serveClaims(w, r, verb, ns, name); err != nil {
			writeStatus(w, err)
		}
		return
	}
	if group == ExtensionsGroup {
		if err := s.serveStored(w, r, verb, resource, ns, name); err != nil {
			writeStatus(w, err)
		}
		return
	}
	switch verb {
	case "list":
		err = s.list(w, r.Context(), ns, q)
	case "watch":
		err = s.watch(w, r, ns, q)
	case "get":
		err = s.get(w, r.Context(), ns, name)
	case "create":
		err = s.create(w, r, ns)
	case "delete":
		err = s.delete(w, r.Context(), ns, name)
	case "patch":
		err = s.patch(w, r, ns, name)
	}
	if err != nil {
		writeStatus(w, err)
	}
}

// parseResourcePath reads
// /apis/{group}/v1beta1/[namespaces/{ns}/]{resource}[/{name}[/{sub}]] for
// the resources this server serves.
func parseResourcePath(path string) (group, resource, ns, name, sub string, ok bool) {
	for _, g := range []string{Group, ExtensionsGroup} {
		if rest, found := strings.CutPrefix(path, "/apis/"+g+"/"+Version+"/"); found {
			group, path = g, rest
			break
		}
	}
	if group == "" {
		return "", "", "", "", "", false
	}
	parts := strings.Split(path, "/")
	if len(parts) >= 3 && parts[0] == "namespaces" {
		ns, parts = parts[1], parts[2:]
		if ns == "" {
			return "", "", "", "", "", false
		}
	}
	if len(parts) == 0 || len(parts) > 3 {
		return "", "", "", "", "", false
	}
	resource = parts[0]
	served := resource == SandboxesResource
	if group == ExtensionsGroup {
		_, served = storedKinds[resource]
		served = served || resource == SandboxClaimsResource
	}
	if !served {
		return "", "", "", "", "", false
	}
	if len(parts) >= 2 {
		name = parts[1]
		if name == "" || ns == "" {
			return "", "", "", "", "", false
		}
	}
	if len(parts) == 3 {
		sub = parts[2]
	}
	return group, resource, ns, name, sub, true
}

func verbOf(method, name, watch string, updatable bool) (string, error) {
	switch {
	case method == http.MethodPut && name != "" && updatable:
		return "update", nil
	case method == http.MethodGet && name == "" && (watch == "true" || watch == "1"):
		return "watch", nil
	case method == http.MethodGet && name == "":
		return "list", nil
	case method == http.MethodGet:
		return "get", nil
	case method == http.MethodPost && name == "":
		return "create", nil
	case method == http.MethodDelete && name != "":
		return "delete", nil
	case method == http.MethodPatch && name != "":
		return "patch", nil
	}
	return "", &StatusError{Code: http.StatusMethodNotAllowed, Reason: "MethodNotAllowed", Message: method + " is not supported here"}
}

// hubError turns the hub's errors into Kubernetes answers.
func hubError(err error) error {
	switch {
	case errors.Is(err, kubeview.ErrNotReady):
		return &StatusError{Code: http.StatusServiceUnavailable, Reason: "ServiceUnavailable", Message: err.Error()}
	case errors.Is(err, kubeview.ErrExpired):
		return &StatusError{Code: http.StatusGone, Reason: "Expired", Message: err.Error()}
	case errors.Is(err, kubeview.ErrTooNew):
		return &StatusError{Code: http.StatusGatewayTimeout, Reason: "Timeout", Message: "Too large resource version: " + err.Error()}
	}
	return err
}

// selector is a label selector of equalities and inequalities: the forms
// AerolVM tags can answer.
type selector struct {
	eq, ne map[string]string
}

func parseSelector(raw string) (selector, error) {
	sel := selector{eq: map[string]string{}, ne: map[string]string{}}
	for _, term := range strings.Split(raw, ",") {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		if k, v, ok := strings.Cut(term, "!="); ok {
			sel.ne[strings.TrimSpace(k)] = strings.TrimSpace(v)
			continue
		}
		k, v, ok := strings.Cut(strings.Replace(term, "==", "=", 1), "=")
		if !ok || strings.ContainsAny(k, "() ") {
			return selector{}, &StatusError{Code: http.StatusBadRequest, Reason: "BadRequest", Message: fmt.Sprintf("label selector %q: only key=value and key!=value are supported", term)}
		}
		sel.eq[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return sel, nil
}

func (s selector) matches(labels map[string]string) bool {
	for k, v := range s.eq {
		if labels[k] != v {
			return false
		}
	}
	for k, v := range s.ne {
		if labels[k] == v {
			return false
		}
	}
	return true
}

// listQuery is a list's or watch's filters.
type listQuery struct {
	labels selector
	name   string // fieldSelector metadata.name
}

func parseListQuery(q map[string][]string) (listQuery, error) {
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	sel, err := parseSelector(get("labelSelector"))
	if err != nil {
		return listQuery{}, err
	}
	out := listQuery{labels: sel}
	for _, term := range strings.Split(get("fieldSelector"), ",") {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		k, v, _ := strings.Cut(strings.Replace(term, "==", "=", 1), "=")
		switch strings.TrimSpace(k) {
		case "metadata.name":
			out.name = strings.TrimSpace(v)
		case "metadata.namespace":
			// The path already chooses the namespace.
		default:
			return listQuery{}, &StatusError{Code: http.StatusBadRequest, Reason: "BadRequest", Message: fmt.Sprintf("field selector %q: only metadata.name and metadata.namespace are supported", term)}
		}
	}
	return out, nil
}

func (lq listQuery) keep(sb Sandbox) bool {
	return (lq.name == "" || sb.Metadata.Name == lq.name) && lq.labels.matches(sb.Metadata.Labels)
}

// continueToken pages a list: the first page's position, and the last
// (namespace, object) it returned.
type continueToken struct {
	RV    uint64 `json:"rv"`
	After string `json:"after"`
}

func encodeContinue(t continueToken) string {
	raw, _ := json.Marshal(t)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeContinue(s string) (continueToken, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	var t continueToken
	if err == nil {
		err = json.Unmarshal(raw, &t)
	}
	if err != nil {
		return t, &StatusError{Code: http.StatusBadRequest, Reason: "BadRequest", Message: "continue: not a token this server issued"}
	}
	return t, nil
}

// owned is one owner's sandboxes, or every mapped owner's when ns is "".
func (s *Server) owned(ns string) (map[string]string, error) {
	if ns != "" {
		owner, ok := s.Owners.Owner(ns)
		if !ok {
			return nil, errNoNamespace
		}
		return map[string]string{owner: ns}, nil
	}
	owners, err := s.Hub.Owners()
	if err != nil {
		return nil, hubError(err)
	}
	out := map[string]string{}
	for _, o := range owners {
		if n, ok := s.Owners.Namespace(o); ok {
			out[o] = n
		}
	}
	return out, nil
}

// render turns hub items into objects, with spec summaries from the
// backend.
func (s *Server) render(ctx context.Context, items []kubeview.Item, nsOf func(owner string) string) []Sandbox {
	ids := make([]string, len(items))
	for i, it := range items {
		ids[i] = it.Placement.SandboxID
	}
	specs := map[string]SpecSummary{}
	if len(ids) > 0 {
		specs = s.Backend.Specs(ctx, ids)
	}
	out := make([]Sandbox, 0, len(items))
	for _, it := range items {
		var spec *SpecSummary
		if sm, ok := specs[it.Placement.SandboxID]; ok {
			spec = &sm
		}
		out = append(out, SandboxFrom(it, nsOf(it.Placement.OwnerRef), spec))
	}
	return out
}

func (s *Server) list(w http.ResponseWriter, ctx context.Context, ns string, q map[string][]string) error {
	lq, err := parseListQuery(q)
	if err != nil {
		return err
	}
	limit := 0
	if v := firstOf(q["limit"]); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return &StatusError{Code: http.StatusBadRequest, Reason: "BadRequest", Message: "limit: not a count"}
		}
		limit = min(n, maxPageLimit)
	}
	var tok continueToken
	if c := firstOf(q["continue"]); c != "" {
		if tok, err = decodeContinue(c); err != nil {
			return err
		}
	}
	pos, err := s.Hub.Position()
	if err != nil {
		return hubError(err)
	}
	if rv := firstOf(q["resourceVersion"]); rv != "" && rv != "0" && tok.RV == 0 {
		want, err := strconv.ParseUint(rv, 10, 64)
		if err != nil {
			return &StatusError{Code: http.StatusBadRequest, Reason: "BadRequest", Message: "resourceVersion: not a number"}
		}
		if firstOf(q["resourceVersionMatch"]) == "Exact" && want != pos {
			return &StatusError{Code: http.StatusGone, Reason: "Expired", Message: "an exact list at an older resourceVersion is not kept"}
		}
	}
	if tok.RV != 0 && tok.RV > pos {
		// The first page came from a gateway further ahead: this one's
		// view could hand back rows older than that page.
		return &StatusError{Code: http.StatusGatewayTimeout, Reason: "Timeout", Message: "this gateway has not caught up with the first page; retry"}
	}
	owners, err := s.owned(ns)
	if err != nil {
		return err
	}
	type keyed struct {
		key  string
		item kubeview.Item
	}
	var all []keyed
	for owner, n := range owners {
		items, _, _, err := s.Hub.List(owner, "", 0)
		if err != nil {
			return hubError(err)
		}
		for _, it := range items {
			k := n + "/" + ObjectName(it.Placement)
			if k > tok.After {
				all = append(all, keyed{key: k, item: it})
			}
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].key < all[j].key })
	nsOf := func(owner string) string { return owners[owner] }
	out := SandboxList{TypeMeta: TypeMeta{APIVersion: GroupVersion(), Kind: SandboxListKind}, Items: []Sandbox{}}
	listRV := pos
	if tok.RV != 0 {
		listRV = tok.RV
	}
	out.Metadata.ResourceVersion = strconv.FormatUint(listRV, 10)
	// Render in pages so a label filter can still fill a page.
	for i := 0; i < len(all); i += maxPageLimit {
		end := min(i+maxPageLimit, len(all))
		chunk := make([]kubeview.Item, 0, end-i)
		for _, k := range all[i:end] {
			chunk = append(chunk, k.item)
		}
		for j, sb := range s.render(ctx, chunk, nsOf) {
			if !lq.keep(sb) {
				continue
			}
			out.Items = append(out.Items, sb)
			if limit > 0 && len(out.Items) == limit {
				if i+j+1 < len(all) {
					out.Metadata.Continue = encodeContinue(continueToken{RV: listRV, After: all[i+j].key})
				}
				writeJSON(w, http.StatusOK, out)
				return nil
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func firstOf(v []string) string {
	if len(v) > 0 {
		return v[0]
	}
	return ""
}

// find is the sandbox named name in owner's namespace.
func (s *Server) find(owner, name string) (kubeview.Item, error) {
	items, _, _, err := s.Hub.List(owner, "", 0)
	if err != nil {
		return kubeview.Item{}, hubError(err)
	}
	for _, it := range items {
		if ObjectName(it.Placement) == name {
			return it, nil
		}
	}
	return kubeview.Item{}, notFound(name)
}

func notFound(name string) error {
	return &StatusError{Code: http.StatusNotFound, Reason: "NotFound", Message: fmt.Sprintf("sandboxes.%s %q not found", Group, name)}
}

func (s *Server) get(w http.ResponseWriter, ctx context.Context, ns, name string) error {
	owner, ok := s.Owners.Owner(ns)
	if !ok {
		return errNoNamespace
	}
	it, err := s.find(owner, name)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, s.render(ctx, []kubeview.Item{it}, func(string) string { return ns })[0])
	return nil
}

func (s *Server) create(w http.ResponseWriter, r *http.Request, ns string) error {
	owner, ok := s.Owners.Owner(ns)
	if !ok {
		return errNoNamespace
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return &StatusError{Code: http.StatusBadRequest, Reason: "BadRequest", Message: err.Error()}
	}
	random := s.Random
	if random == nil {
		random = randomSuffix
	}
	req, sb, err := CreateFrom(body, s.now(), random)
	var fe *FieldError
	switch {
	case errors.As(err, &fe):
		return &StatusError{Code: http.StatusUnprocessableEntity, Reason: "Invalid", Message: fmt.Sprintf("Sandbox %q is invalid: %s", sb.Metadata.Name, fe.Error())}
	case err != nil:
		return &StatusError{Code: http.StatusBadRequest, Reason: "BadRequest", Message: err.Error()}
	}
	if sb.Metadata.Namespace != "" && sb.Metadata.Namespace != ns {
		return &StatusError{Code: http.StatusBadRequest, Reason: "BadRequest", Message: "metadata.namespace does not match the request's namespace"}
	}
	if _, err := s.find(owner, req.Name); err == nil {
		return &StatusError{Code: http.StatusConflict, Reason: "AlreadyExists", Message: fmt.Sprintf("sandboxes.%s %q already exists", Group, req.Name)}
	}
	if r.URL.Query().Get("dryRun") != "" {
		writeJSON(w, http.StatusCreated, sb)
		return nil
	}
	id, err := s.Backend.Create(r.Context(), owner, req, "kubeapi/"+ns+"/"+req.Name)
	if err != nil {
		return err
	}
	it, ok := s.waitFor(r.Context(), owner, id)
	if !ok {
		// Created, not yet in this gateway's view: answer with what is
		// known; a watch shows the rest.
		pos, _ := s.Hub.Position()
		it = kubeview.Item{RV: pos}
		it.Placement.SandboxID, it.Placement.Name, it.Placement.OwnerRef = id, req.Name, owner
		it.Placement.CreatedUnix = s.now().Unix()
	}
	writeJSON(w, http.StatusCreated, s.render(r.Context(), []kubeview.Item{it}, func(string) string { return ns })[0])
	return nil
}

// waitFor waits a little for a new sandbox to reach this gateway's view.
func (s *Server) waitFor(ctx context.Context, owner, id string) (kubeview.Item, bool) {
	wait := s.CreateWait
	if wait <= 0 {
		wait = 5 * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		if it, ok, err := s.Hub.Get(owner, id); err == nil && ok {
			return it, true
		}
		if time.Now().After(deadline) {
			return kubeview.Item{}, false
		}
		select {
		case <-ctx.Done():
			return kubeview.Item{}, false
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (s *Server) delete(w http.ResponseWriter, ctx context.Context, ns, name string) error {
	owner, ok := s.Owners.Owner(ns)
	if !ok {
		return errNoNamespace
	}
	it, err := s.find(owner, name)
	if err != nil {
		return err
	}
	if err := s.Backend.Delete(ctx, owner, it.Placement.SandboxID); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, Status{TypeMeta: TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Success", Code: http.StatusOK,
		Message: fmt.Sprintf("sandboxes.%s %q deleted", Group, name)})
	return nil
}

// patch changes spec.operatingMode, the one field a sandbox can change in
// place: Suspended stops it, Running starts it.
func (s *Server) patch(w http.ResponseWriter, r *http.Request, ns, name string) error {
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/merge-patch+json") && !strings.HasPrefix(ct, "application/strategic-merge-patch+json") {
		return &StatusError{Code: http.StatusUnsupportedMediaType, Reason: "UnsupportedMediaType", Message: "only merge patches are supported, of spec.operatingMode"}
	}
	owner, ok := s.Owners.Owner(ns)
	if !ok {
		return errNoNamespace
	}
	var raw map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&raw); err != nil {
		return &StatusError{Code: http.StatusBadRequest, Reason: "BadRequest", Message: "the patch is not a JSON object"}
	}
	var refused []string
	refusedFields(raw, map[string]any{"spec": map[string]any{"operatingMode": true}, "metadata": map[string]any{"name": true, "namespace": true}}, "", &refused)
	if len(refused) > 0 {
		return &StatusError{Code: http.StatusUnprocessableEntity, Reason: "Invalid", Message: "only spec.operatingMode can change; not: " + strings.Join(refused, "; ")}
	}
	it, err := s.find(owner, name)
	if err != nil {
		return err
	}
	if spec, _ := raw["spec"].(map[string]any); spec != nil {
		switch spec["operatingMode"] {
		case nil:
		case OperatingModeRunning:
			err = s.Backend.SetRunning(r.Context(), owner, it.Placement.SandboxID, true)
		case OperatingModeSuspended:
			err = s.Backend.SetRunning(r.Context(), owner, it.Placement.SandboxID, false)
		default:
			return &StatusError{Code: http.StatusUnprocessableEntity, Reason: "Invalid", Message: "spec.operatingMode: must be Running or Suspended"}
		}
		if err != nil {
			return err
		}
	}
	writeJSON(w, http.StatusOK, s.render(r.Context(), []kubeview.Item{it}, func(string) string { return ns })[0])
	return nil
}

// watch streams events as Kubernetes does: one JSON WatchEvent per line.
func (s *Server) watch(w http.ResponseWriter, r *http.Request, ns string, q map[string][]string) error {
	lq, err := parseListQuery(q)
	if err != nil {
		return err
	}
	owner := kubeview.AllOwners
	var nsOf func(string) string
	if ns != "" {
		o, ok := s.Owners.Owner(ns)
		if !ok {
			return errNoNamespace
		}
		owner, nsOf = o, func(string) string { return ns }
	} else {
		nsOf = func(o string) string { n, _ := s.Owners.Namespace(o); return n }
	}
	var from uint64
	initial := firstOf(q["sendInitialEvents"]) == "true"
	if rv := firstOf(q["resourceVersion"]); rv != "" && rv != "0" && !initial {
		if from, err = strconv.ParseUint(rv, 10, 64); err != nil {
			return &StatusError{Code: http.StatusBadRequest, Reason: "BadRequest", Message: "resourceVersion: not a number"}
		}
	}
	length := defaultWatchLength
	if v := firstOf(q["timeoutSeconds"]); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			length = time.Duration(n) * time.Second
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), length)
	defer cancel()
	events, err := s.Hub.Watch(ctx, owner, from)
	if err != nil {
		return hubError(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		// Headers now: a quiet watch must not leave the client waiting for
		// its response.
		flusher.Flush()
	}
	enc := json.NewEncoder(w)
	send := func(ev WatchEvent) bool {
		if err := enc.Encode(ev); err != nil {
			return false
		}
		if flusher != nil {
			flusher.Flush()
		}
		return true
	}
	bookmarks := firstOf(q["allowWatchBookmarks"]) == "true"
	every := s.BookmarkEvery
	if every <= 0 {
		every = kubeview.DefaultBookmarkTick
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	pendingInitial := initial
	bookmark := func(end bool) bool {
		pos, err := s.Hub.Position()
		if err != nil {
			return true
		}
		obj := Sandbox{TypeMeta: TypeMeta{APIVersion: GroupVersion(), Kind: SandboxKind}, Metadata: ObjectMeta{ResourceVersion: strconv.FormatUint(pos, 10)}}
		if end {
			obj.Metadata.Annotations = map[string]string{initialEventsEnd: "true"}
		}
		return send(WatchEvent{Type: "BOOKMARK", Object: obj})
	}
	for {
		var ev kubeview.Event
		var ok bool
		if pendingInitial {
			// With sendInitialEvents the backlog (every sandbox, from 0)
			// is followed by a bookmark marking its end.
			select {
			case ev, ok = <-events:
			case <-time.After(10 * time.Millisecond):
				pendingInitial = false
				if !bookmark(true) {
					return nil
				}
				continue
			}
		} else {
			select {
			case ev, ok = <-events:
			case <-tick.C:
				if bookmarks && !bookmark(false) {
					return nil
				}
				continue
			}
		}
		if !ok {
			return nil
		}
		switch ev.Type {
		case kubeview.Closed:
			st := hubError(ev.Err)
			se, isStatus := st.(*StatusError)
			if !isStatus {
				return nil
			}
			send(WatchEvent{Type: "ERROR", Object: statusOf(se)})
			return nil
		case kubeview.Added, kubeview.Modified, kubeview.Deleted:
			sb := s.render(ctx, []kubeview.Item{ev.Item}, nsOf)[0]
			if sb.Metadata.Namespace == "" || !lq.keep(sb) {
				continue
			}
			if !send(WatchEvent{Type: string(ev.Type), Object: sb}) {
				return nil
			}
		}
	}
}

func statusOf(e *StatusError) Status {
	return Status{TypeMeta: TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Failure", Message: e.Message, Reason: e.Reason, Code: e.Code}
}

func writeStatus(w http.ResponseWriter, err error) {
	var se *StatusError
	if !errors.As(err, &se) {
		se = &StatusError{Code: http.StatusInternalServerError, Reason: "InternalError", Message: err.Error()}
	}
	writeJSON(w, se.Code, statusOf(se))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// The discovery documents.
func resourceList() APIResourceList {
	return APIResourceList{
		TypeMeta:     TypeMeta{APIVersion: "v1", Kind: "APIResourceList"},
		GroupVersion: GroupVersion(),
		APIResources: []APIResource{{
			Name: SandboxesResource, SingularName: "sandbox", Namespaced: true, Kind: SandboxKind,
			Verbs: []string{"create", "delete", "get", "list", "patch", "watch"},
		}},
	}
}

type groupVersion struct {
	GroupVersion string `json:"groupVersion"`
	Version      string `json:"version"`
}

type apiGroupDoc struct {
	TypeMeta         `json:",inline"`
	Name             string         `json:"name"`
	Versions         []groupVersion `json:"versions"`
	PreferredVersion groupVersion   `json:"preferredVersion"`
}

func apiGroup(name string) apiGroupDoc {
	gv := groupVersion{GroupVersion: name + "/" + Version, Version: Version}
	return apiGroupDoc{TypeMeta: TypeMeta{APIVersion: "v1", Kind: "APIGroup"}, Name: name, Versions: []groupVersion{gv}, PreferredVersion: gv}
}

func apiGroupList() map[string]any {
	var groups []apiGroupDoc
	for _, name := range []string{Group, ExtensionsGroup} {
		g := apiGroup(name)
		g.TypeMeta = TypeMeta{}
		groups = append(groups, g)
	}
	return map[string]any{"kind": "APIGroupList", "apiVersion": "v1", "groups": groups}
}

const suffixAlphabet = "bcdfghjklmnpqrstvwxz2456789"

// randomSuffix is generateName's suffix, as Kubernetes makes it.
func randomSuffix() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = suffixAlphabet[int(b[i])%len(suffixAlphabet)]
	}
	return string(b)
}

// discoveryPath is a discovery or OpenAPI document: what the
// kube-apiserver's health check of the APIService reads, sent with its
// front-proxy certificate and no user.
func discoveryPath(path string) bool {
	switch path {
	case "/apis", "/apis/" + Group, "/apis/" + Group + "/" + Version,
		"/apis/" + ExtensionsGroup, "/apis/" + ExtensionsGroup + "/" + Version,
		"/openapi/v2", "/openapi/v3":
		return true
	}
	return false
}
