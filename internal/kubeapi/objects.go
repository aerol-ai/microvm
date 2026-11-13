package kubeapi

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// SandboxTemplates and SandboxWarmPools live in etcd as AerolVM's own
// internal CRDs (group k8s.aerolvm.io, decision C17): they change rarely,
// AerolVM gets no Kubernetes-only table, and the gateways are the only
// writer, limited to those two kinds. The API answers for them under the
// upstream group and passes each call through, translating the group both
// ways; claims and sandboxes stay out of etcd.

// InternalGroup is where the internal CRDs live.
const (
	InternalGroup   = "k8s.aerolvm.io"
	InternalVersion = "v1alpha1"
)

// ObjectStore keeps the stored kinds. KubeClient implements it over the
// kube-apiserver; tests use a fake.
type ObjectStore interface {
	Get(ctx context.Context, resource, ns, name string) (map[string]any, error)
	List(ctx context.Context, resource, ns string, q url.Values) (map[string]any, error)
	Create(ctx context.Context, resource, ns string, obj map[string]any) (map[string]any, error)
	Update(ctx context.Context, resource, ns, name string, obj map[string]any) (map[string]any, error)
	Patch(ctx context.Context, resource, ns, name, contentType string, body []byte) (map[string]any, error)
	Delete(ctx context.Context, resource, ns, name string) (map[string]any, error)
	// Watch streams WatchEvents, one JSON object per line.
	Watch(ctx context.Context, resource, ns string, q url.Values) (io.ReadCloser, error)
}

func internalAPIVersion() string { return InternalGroup + "/" + InternalVersion }

// ExtensionsAPIVersion is apiVersion for the extensions kinds.
func ExtensionsAPIVersion() string { return ExtensionsGroup + "/" + Version }

// toUpstream rewrites a stored object (or list) so it reads as the
// upstream kind.
func toUpstream(obj map[string]any) map[string]any {
	if obj == nil {
		return nil
	}
	if v, _ := obj["apiVersion"].(string); v == internalAPIVersion() {
		obj["apiVersion"] = ExtensionsAPIVersion()
	}
	if items, ok := obj["items"].([]any); ok {
		for _, it := range items {
			if m, ok := it.(map[string]any); ok {
				toUpstream(m)
			}
		}
	}
	return obj
}

// toInternal rewrites a client's object for storage.
func toInternal(obj map[string]any) map[string]any {
	if v, _ := obj["apiVersion"].(string); v == "" || v == ExtensionsAPIVersion() {
		obj["apiVersion"] = internalAPIVersion()
	}
	return obj
}

func objectPath(resource, ns, name string) string {
	p := "/apis/" + InternalGroup + "/" + InternalVersion
	if ns != "" {
		p += "/namespaces/" + url.PathEscape(ns)
	}
	p += "/" + resource
	if name != "" {
		p += "/" + url.PathEscape(name)
	}
	return p
}

// raw sends one call and returns the open response; a non-2xx answer is a
// StatusError carrying the kube-apiserver's own code, reason and message.
func (k *KubeClient) raw(ctx context.Context, method, path, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, k.Host+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if k.Token != nil {
		tok, err := k.Token()
		if err != nil {
			return nil, fmt.Errorf("kubeapi: service account token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := k.Client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var st Status
		if json.Unmarshal(raw, &st) == nil && st.Code != 0 {
			return nil, &StatusError{Code: st.Code, Reason: st.Reason, Message: st.Message}
		}
		return nil, &StatusError{Code: resp.StatusCode, Reason: "InternalError", Message: strings.TrimSpace(string(raw))}
	}
	return resp, nil
}

func (k *KubeClient) object(ctx context.Context, method, path, contentType string, body []byte) (map[string]any, error) {
	var rd io.Reader
	if body != nil {
		rd = strings.NewReader(string(body))
	}
	resp, err := k.raw(ctx, method, path, contentType, rd)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return toUpstream(out), nil
}

func (k *KubeClient) Get(ctx context.Context, resource, ns, name string) (map[string]any, error) {
	return k.object(ctx, http.MethodGet, objectPath(resource, ns, name), "", nil)
}

func (k *KubeClient) List(ctx context.Context, resource, ns string, q url.Values) (map[string]any, error) {
	path := objectPath(resource, ns, "")
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	return k.object(ctx, http.MethodGet, path, "", nil)
}

func (k *KubeClient) Create(ctx context.Context, resource, ns string, obj map[string]any) (map[string]any, error) {
	raw, err := json.Marshal(toInternal(obj))
	if err != nil {
		return nil, err
	}
	return k.object(ctx, http.MethodPost, objectPath(resource, ns, ""), "application/json", raw)
}

func (k *KubeClient) Update(ctx context.Context, resource, ns, name string, obj map[string]any) (map[string]any, error) {
	raw, err := json.Marshal(toInternal(obj))
	if err != nil {
		return nil, err
	}
	return k.object(ctx, http.MethodPut, objectPath(resource, ns, name), "application/json", raw)
}

func (k *KubeClient) Patch(ctx context.Context, resource, ns, name, contentType string, body []byte) (map[string]any, error) {
	return k.object(ctx, http.MethodPatch, objectPath(resource, ns, name), contentType, body)
}

func (k *KubeClient) Delete(ctx context.Context, resource, ns, name string) (map[string]any, error) {
	return k.object(ctx, http.MethodDelete, objectPath(resource, ns, name), "", nil)
}

// Watch streams the stored kind's events, each rewritten to the upstream
// group as it passes.
func (k *KubeClient) Watch(ctx context.Context, resource, ns string, q url.Values) (io.ReadCloser, error) {
	q = cloneValues(q)
	q.Set("watch", "true")
	resp, err := k.raw(ctx, http.MethodGet, objectPath(resource, ns, "")+"?"+q.Encode(), "", nil)
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	go func() {
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 64<<10), 16<<20)
		for sc.Scan() {
			var ev map[string]any
			if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
				continue
			}
			if obj, ok := ev["object"].(map[string]any); ok {
				toUpstream(obj)
			}
			line, _ := json.Marshal(ev)
			if _, err := pw.Write(append(line, '\n')); err != nil {
				return
			}
		}
		pw.CloseWithError(sc.Err())
	}()
	return pr, nil
}

func cloneValues(q url.Values) url.Values {
	out := url.Values{}
	for k, v := range q {
		out[k] = append([]string(nil), v...)
	}
	return out
}
