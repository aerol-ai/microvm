package kubeapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/kubeview"
	"github.com/aerol-ai/microvm/pkg/models"
)

// SandboxClaims (extensions.agents.x-k8s.io/v1beta1): a claim takes a
// sandbox from a warm pool, whose template says what to run. Upstream keeps
// one claim object per sandbox in etcd; here a claim is the sandbox it
// made, marked by two tags, so nothing per sandbox is stored in etcd (K5).
//
//	POST claim ──▶ warm pool (store) ──▶ template (store) ──▶ create from the
//	               template's podTemplate + the claim's env and labels, named
//	               after the claim, tagged as a claim ──▶ Backend.Create
//	GET / LIST / WATCH claims ──▶ the hub's sandboxes whose tags mark a claim

const (
	SandboxClaimsResource = "sandboxclaims"
	SandboxClaimKind      = "SandboxClaim"
	// TagClaim and TagWarmPool mark a sandbox made by a claim.
	TagClaim    = cluster.KubeClaimTag
	TagWarmPool = "agents.x-k8s.io/warm-pool"
)

var claimTable = map[string]any{
	"apiVersion": true, "kind": true, "status": "*",
	"metadata": map[string]any{"name": true, "generateName": true, "namespace": true, "labels": "*", "annotations": "*"},
	"spec": map[string]any{
		"warmPoolRef": map[string]any{"name": true},
		"lifecycle":   map[string]any{"shutdownTime": true, "shutdownPolicy": true},
		"env":         []any{map[string]any{"name": true, "value": true, "containerName": true}},
		"additionalPodMetadata": map[string]any{
			"labels": "*", "annotations": "*",
		},
	},
}

// claimSpec is the part of a claim this server reads.
type claimSpec struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		WarmPoolRef struct {
			Name string `json:"name"`
		} `json:"warmPoolRef"`
		Lifecycle *struct {
			ShutdownTime   string `json:"shutdownTime"`
			ShutdownPolicy string `json:"shutdownPolicy"`
		} `json:"lifecycle"`
		Env                   []EnvVar    `json:"env"`
		AdditionalPodMetadata PodMetadata `json:"additionalPodMetadata"`
	} `json:"spec"`
}

// claimFromStore builds the create a claim asks for, from its warm pool's
// template.
func (s *Server) claimRequest(ctx context.Context, ns string, body []byte) (models.CreateSandboxRequest, claimSpec, error) {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return models.CreateSandboxRequest{}, claimSpec{}, &StatusError{Code: http.StatusBadRequest, Reason: "BadRequest", Message: "the body is not a JSON object"}
	}
	var c claimSpec
	_ = json.Unmarshal(body, &c)
	var refused []string
	refusedFields(raw, claimTable, "", &refused)
	if k, _ := raw["kind"].(string); k != "" && k != SandboxClaimKind {
		refused = append(refused, "kind: must be "+SandboxClaimKind)
	}
	pool := strings.TrimSpace(c.Spec.WarmPoolRef.Name)
	if pool == "" {
		refused = append(refused, "spec.warmPoolRef.name: required")
	}
	if c.Metadata.Namespace != "" && c.Metadata.Namespace != ns {
		return models.CreateSandboxRequest{}, c, &StatusError{Code: http.StatusBadRequest, Reason: "BadRequest", Message: "metadata.namespace does not match the request's namespace"}
	}
	if len(refused) > 0 {
		return models.CreateSandboxRequest{}, c, invalidClaim(c.Metadata.Name, refused)
	}
	wp, err := s.Store.Get(ctx, SandboxWarmPoolsResource, ns, pool)
	if err != nil {
		return models.CreateSandboxRequest{}, c, notFoundAs(err, "the warm pool "+pool)
	}
	ref, _ := mapAt(wp, "spec", "sandboxTemplateRef")["name"].(string)
	tpl, err := s.Store.Get(ctx, SandboxTemplatesResource, ns, ref)
	if err != nil {
		return models.CreateSandboxRequest{}, c, notFoundAs(err, "the template "+ref+" of the warm pool "+pool)
	}
	// The template's pod template, under the claim's name and lifecycle,
	// through the same field table as a Sandbox create.
	sandbox := map[string]any{
		"metadata": map[string]any{"name": c.Metadata.Name, "generateName": c.Metadata.GenerateName},
		"spec":     blueprint(mapAt(tpl, "spec")),
	}
	if lc := c.Spec.Lifecycle; lc != nil {
		sandbox["spec"].(map[string]any)["shutdownTime"] = lc.ShutdownTime
		policy := lc.ShutdownPolicy
		if policy == "DeleteForeground" {
			// A claim's own value (upstream: delete the claim, waiting for
			// its sandbox). A claim is its sandbox, so it is Delete.
			policy = ShutdownPolicyDelete
		}
		sandbox["spec"].(map[string]any)["shutdownPolicy"] = policy
	}
	probe, _ := json.Marshal(sandbox)
	random := s.Random
	if random == nil {
		random = randomSuffix
	}
	req, made, err := CreateFrom(probe, s.now(), random)
	var fe *FieldError
	if errors.As(err, &fe) {
		return req, c, invalidClaim(c.Metadata.Name, fe.Fields)
	} else if err != nil {
		return req, c, err
	}
	c.Metadata.Name = made.Metadata.Name
	if len(c.Spec.Env) > 0 {
		policy, _ := mapAt(tpl, "spec")["envVarsInjectionPolicy"].(string)
		// Unset is Disallowed, as upstream: a template must opt in before a
		// claim may set env on its sandboxes.
		if policy == "" || policy == "Disallowed" {
			return req, c, invalidClaim(c.Metadata.Name, []string{"spec.env: the template's envVarsInjectionPolicy is Disallowed"})
		}
		if req.Env == nil {
			req.Env = map[string]string{}
		}
		for i, e := range c.Spec.Env {
			if strings.TrimSpace(e.Name) == "" {
				return req, c, invalidClaim(c.Metadata.Name, []string{fmt.Sprintf("spec.env[%d].name: required", i)})
			}
			if _, set := req.Env[e.Name]; set && policy != "Overrides" {
				return req, c, invalidClaim(c.Metadata.Name, []string{fmt.Sprintf("spec.env[%d]: %q is the template's; its envVarsInjectionPolicy is not Overrides", i, e.Name)})
			}
			req.Env[e.Name] = e.Value
		}
	}
	tags := map[string]string{}
	for k, v := range req.Tags {
		tags[k] = v
	}
	for k, v := range c.Spec.AdditionalPodMetadata.Labels {
		tags[k] = v
	}
	for k, v := range c.Metadata.Labels {
		tags[k] = v
	}
	tags[TagClaim], tags[TagWarmPool] = "true", pool
	req.Tags = tags
	return req, c, nil
}

func invalidClaim(name string, fields []string) error {
	return &StatusError{Code: http.StatusUnprocessableEntity, Reason: "Invalid",
		Message: fmt.Sprintf("SandboxClaim %q is invalid: not supported by AerolVM: %s", name, strings.Join(fields, "; "))}
}

// notFoundAs names what a claim referred to when the store has no such
// object.
func notFoundAs(err error, what string) error {
	var se *StatusError
	if errors.As(err, &se) && se.Code == http.StatusNotFound {
		return &StatusError{Code: http.StatusUnprocessableEntity, Reason: "Invalid", Message: what + " does not exist"}
	}
	return err
}

func mapAt(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		next, _ := m[k].(map[string]any)
		m = next
	}
	if m == nil {
		return map[string]any{}
	}
	return m
}

// claimFrom renders a claim-made sandbox as its claim.
func claimFrom(it kubeview.Item, ns string, spec *SpecSummary) map[string]any {
	sb := SandboxFrom(it, ns, spec)
	pool := ""
	if spec != nil {
		pool = spec.Tags[TagWarmPool]
	}
	return map[string]any{
		"apiVersion": ExtensionsAPIVersion(),
		"kind":       SandboxClaimKind,
		"metadata": map[string]any{
			"name": sb.Metadata.Name, "namespace": ns, "uid": sb.Metadata.UID, "resourceVersion": sb.Metadata.ResourceVersion,
			"generation": 1, "creationTimestamp": sb.Metadata.CreationTimestamp, "annotations": sb.Metadata.Annotations,
			"labels": sb.Metadata.Labels,
		},
		"spec": map[string]any{"warmPoolRef": map[string]any{"name": pool}},
		"status": map[string]any{
			"conditions": sb.Status.Conditions,
			"sandbox":    map[string]any{"name": sb.Metadata.Name},
		},
	}
}

func isClaim(spec SpecSummary, ok bool) bool { return ok && spec.Tags[TagClaim] == "true" }

// patchClaim answers a patch of a claim, which cannot change: a second
// `kubectl apply` of it passes when what it shows is as it was (apply.go).
func (s *Server) patchClaim(w http.ResponseWriter, r *http.Request, it kubeview.Item, ns string, sp SpecSummary) error {
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/merge-patch+json") && !strings.HasPrefix(ct, "application/strategic-merge-patch+json") {
		return &StatusError{Code: http.StatusUnsupportedMediaType, Reason: "UnsupportedMediaType", Message: "only merge patches are supported"}
	}
	var raw map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&raw); err != nil {
		return &StatusError{Code: http.StatusBadRequest, Reason: "BadRequest", Message: "the patch is not a JSON object"}
	}
	cur := claimFrom(it, ns, &sp)
	warnings, err := mergeClaimPatch(cur, sp.Tags[TagWarmPool], sp.Tags, raw)
	if err != nil {
		return err
	}
	warn(w, warnings)
	writeJSON(w, http.StatusOK, cur)
	return nil
}

// keepClaim applies a list's or watch's selectors to a rendered claim, as
// keep does to a sandbox: kubectl wait finds its one object by
// fieldSelector metadata.name.
func (lq listQuery) keepClaim(c map[string]any) bool {
	md, _ := c["metadata"].(map[string]any)
	name, _ := md["name"].(string)
	labels, _ := md["labels"].(map[string]string)
	return (lq.name == "" || name == lq.name) && lq.labels.matches(labels)
}

// claims are owner's claim-made sandboxes that lq keeps, in name order.
func (s *Server) claims(ctx context.Context, owner, ns string, lq listQuery) ([]map[string]any, uint64, error) {
	items, pos, _, err := s.Hub.List(owner, "", 0)
	if err != nil {
		return nil, 0, hubError(err)
	}
	// Rows marked not a claim are skipped without a spec read; only
	// claims, and rows an older build left unmarked, need one.
	maybe := make([]kubeview.Item, 0, len(items))
	for _, it := range items {
		if it.Placement.KubeClaim != cluster.KubeClaimNo {
			maybe = append(maybe, it)
		}
	}
	var out []map[string]any
	for i := 0; i < len(maybe); i += maxPageLimit {
		chunk := maybe[i:min(i+maxPageLimit, len(maybe))]
		specs := s.Backend.Specs(ctx, specRefs(chunk...))
		for _, it := range chunk {
			sp, ok := specs[it.Placement.SandboxID]
			if !isClaim(sp, ok) {
				continue
			}
			if c := claimFrom(it, ns, &sp); lq.keepClaim(c) {
				out = append(out, c)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i]["metadata"].(map[string]any)["name"].(string) < out[j]["metadata"].(map[string]any)["name"].(string)
	})
	return out, pos, nil
}

// serveClaims answers a verb on claims.
func (s *Server) serveClaims(w http.ResponseWriter, r *http.Request, verb, ns, name string) error {
	ctx := r.Context()
	if ns == "" && verb != "list" && verb != "watch" {
		return errNoNamespace
	}
	owners, err := s.owned(ns)
	if err != nil {
		return err
	}
	switch verb {
	case "list":
		lq, err := parseListQuery(r.URL.Query())
		if err != nil {
			return err
		}
		items := []any{}
		var pos uint64
		var names []string
		for o := range owners {
			names = append(names, o)
		}
		sort.Strings(names)
		for _, o := range names {
			cs, p, err := s.claims(ctx, o, owners[o], lq)
			if err != nil {
				return err
			}
			pos = max(pos, p)
			for _, c := range cs {
				items = append(items, c)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"apiVersion": ExtensionsAPIVersion(), "kind": "SandboxClaimList",
			"metadata": map[string]any{"resourceVersion": strconv.FormatUint(pos, 10)}, "items": items})
		return nil
	case "get", "delete", "patch":
		owner := firstKey(owners)
		claimNotFound := &StatusError{Code: http.StatusNotFound, Reason: "NotFound", Message: fmt.Sprintf("sandboxclaims.%s %q not found", ExtensionsGroup, name)}
		it, err := s.find(owner, name)
		var se *StatusError
		if errors.As(err, &se) && se.Code == http.StatusNotFound {
			return claimNotFound
		} else if err != nil {
			return err
		}
		sp, ok := s.Backend.Specs(ctx, specRefs(it))[it.Placement.SandboxID]
		if !isClaim(sp, ok) {
			return claimNotFound
		}
		if verb == "patch" {
			return s.patchClaim(w, r, it, ns, sp)
		}
		if verb == "delete" {
			if err := s.Backend.Delete(ctx, owner, it.Placement.SandboxID); err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, Status{TypeMeta: TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Success", Code: http.StatusOK,
				Message: fmt.Sprintf("sandboxclaims.%s %q deleted", ExtensionsGroup, name)})
			return nil
		}
		writeJSON(w, http.StatusOK, claimFrom(it, ns, &sp))
		return nil
	case "create":
		owner := firstKey(owners)
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			return &StatusError{Code: http.StatusBadRequest, Reason: "BadRequest", Message: err.Error()}
		}
		req, _, err := s.claimRequest(ctx, ns, body)
		if err != nil {
			return err
		}
		if _, err := s.find(owner, req.Name); err == nil {
			return &StatusError{Code: http.StatusConflict, Reason: "AlreadyExists", Message: fmt.Sprintf("sandboxclaims.%s %q already exists", ExtensionsGroup, req.Name)}
		}
		id, err := s.Backend.Create(ctx, owner, req, "kubeapi-claim/"+ns+"/"+req.Name)
		if err != nil {
			return err
		}
		it, seen := s.waitFor(ctx, owner, id)
		if !seen {
			pos, _ := s.Hub.Position()
			it = kubeview.Item{RV: pos}
			it.Placement.SandboxID, it.Placement.Name, it.Placement.OwnerRef = id, req.Name, owner
			it.Placement.CreatedUnix = s.now().Unix()
		}
		sp := SpecSummary{Image: req.Image, Runtime: req.Runtime, Tags: req.Tags}
		writeJSON(w, http.StatusCreated, claimFrom(it, ns, &sp))
		return nil
	case "watch":
		return s.watchClaims(w, r, ns, owners)
	}
	return &StatusError{Code: http.StatusMethodNotAllowed, Reason: "MethodNotAllowed", Message: verb + " is not supported on sandboxclaims"}
}

func firstKey(m map[string]string) string {
	for k := range m {
		return k
	}
	return ""
}

// watchClaims streams claim events: the sandbox watch, kept to claim-made
// sandboxes and rendered as claims.
func (s *Server) watchClaims(w http.ResponseWriter, r *http.Request, ns string, owners map[string]string) error {
	owner := kubeview.AllOwners
	if ns != "" {
		owner = firstKey(owners)
	}
	q := r.URL.Query()
	lq, err := parseListQuery(q)
	if err != nil {
		return err
	}
	return s.streamWatch(w, r, owner, q, func(ctx context.Context, ev kubeview.Event) any {
		n := ns
		if n == "" {
			n, _ = s.Owners.Namespace(ev.Item.Placement.OwnerRef)
		}
		if n == "" {
			return nil
		}
		if ev.Item.Placement.KubeClaim == cluster.KubeClaimNo {
			return nil
		}
		sp, ok := s.Backend.Specs(ctx, specRefs(ev.Item))[ev.Item.Placement.SandboxID]
		if !isClaim(sp, ok) {
			return nil
		}
		if c := claimFrom(ev.Item, n, &sp); lq.keepClaim(c) {
			return c
		}
		return nil
	}, func(rv uint64, end bool) any {
		md := map[string]any{"resourceVersion": strconv.FormatUint(rv, 10)}
		if end {
			md["annotations"] = map[string]string{initialEventsEnd: "true"}
		}
		return map[string]any{"apiVersion": ExtensionsAPIVersion(), "kind": SandboxClaimKind, "metadata": md}
	})
}
